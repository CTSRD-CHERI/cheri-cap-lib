#! /usr/bin/env python3

import re
import sys
import subprocess

# Parsing TCL structures
# ======================

# Parse nested TCL structure into nested python list (helper function)
def parseTCLHelper(s):
  result = []
  s = s.lstrip()
  while s:
    if s[0] == '{':
      (subtree, s) = parseTCLHelper(s[1:])
      result.append(subtree)
    elif s[0] == '}':
      return (result, s[1:])
    else:
      word = ""
      while s and s[0] not in [' ', '{', '}']:
        word = word + s[0]
        s = s[1:]
      result.append(word)
    s = s.lstrip()

  return (result, s)

# Parse nested TCL structure into nested python list
def parseTCL(s):
  return parseTCLHelper(s)[0]

# Helper functions
# ================

# Strip qualifiers from qualified name
def stripQualifiers(s):
  return s.split("::")[-1]

# Is the given type a Module type constructor?
def isModuleTypeCons(s):
  return s[0:8] == "Module#(" and s[-1] == ")"

# Unwrap Module#(t) to t
def stripModuleTypeCons(s):
  if isModuleTypeCons(s):
    return s[8:-1]
  else:
    return s

# Flatten list of strings to a string
def flatString(x):
  if type(x) == list:
    if x:
      return flatString(x[0]) + flatString(x[1:])
    else:
      return ""
  else:
    return x

# Flatten input to a list of strings
def listOfString(x):
  if type(x) == list:
    if x:
      return [flatString(x[0])] + listOfString(x[1:])
    else:
      return []
  else:
    return [x]

# Split args at outermost nesting level
def splitArgs(s):
  nestCount = 0
  args = []
  arg = ""
  for c in s:
    if c == '(':
      nestCount = nestCount + 1
    elif c == ')':
      nestCount = nestCount - 1
    if c == ',' and nestCount == 0:
      args.append(arg)
      arg = ""
    else:
      arg = arg + c
  if arg: args.append(arg)
  return args

# Bluetcl interaction
# ===================

# Interactive interface to bluetcl
class Bluetcl:
  # Constructor: open bluetcl as a subprocess
  def __init__(self):
    try:
      self.p = subprocess.Popen(['bluetcl'],
                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE, text=True)
      self.p.stdin.write("namespace import ::Bluetcl::*\n")
      self.p.stdin.flush();
    except subprocess.CalledProcessError:
      print("Couldn't open bluetcl")
      sys.exit()

  # Destructor: terminate bluetcl process
  def __del__(self):
    self.p.terminate()

  # Load package
  def loadPackage(self, pkg):
    self.p.stdin.write("bpackage load " + pkg + "\n")
    self.p.stdin.flush();

  # Get bit-level representation of given type
  def bitify(self, typeName):
    self.p.stdin.write("puts [type bitify " + typeName + "]\n")
    self.p.stdin.flush()
    return parseTCL(self.p.stdout.readline())

  # Determine bit width of given type
  def bitWidth(self, typeName):
    tree = self.bitify(typeName)
    return tree[2]

  # Get all functions in given package
  def getFuncs(self, pkg):
    self.p.stdin.write("puts [defs func " + pkg + "]\n")
    self.p.stdin.flush()
    return parseTCL(self.p.stdout.readline())

  # Get info for given type
  def getTypeInfo(self, typeName):
    self.p.stdin.write("puts [type full " + typeName + "]\n")
    self.p.stdin.flush()
    return parseTCL(self.p.stdout.readline())

# Main
# ====

# Check args
if len(sys.argv) != 1:
  print("Usage: CHERICapWrapBlarney2.py")
  sys.exit()

# Load CHERICapWrap module into bluetcl
bluetcl = Bluetcl()
bluetcl.loadPackage("CHERICapWrap")

# Translate Bluespec type to Blarney type
def translateType(t):
  if t == "Bool":
    return "Bit 1"
  elif t[0:5] == "Tuple" and t[6:8] == "#(" and t[-1] == ")":
    args = splitArgs(t[8:-1])
    return '(' + ", ".join([translateType(arg) for arg in args]) + ')'
  else:
    w = bluetcl.bitWidth(t)
    return "Bit " + w

# Get type sigs for each function
def getFuncSigs():
  sigs = []
  funcs = bluetcl.getFuncs("CHERICapWrap")
  for func in funcs:
    if func[0] == "function":
      funcName = stripQualifiers(func[1])
      resultType = func[2][1]
      if isModuleTypeCons(resultType):
        ifcName = stripModuleTypeCons(resultType)
        ifc = bluetcl.getTypeInfo(ifcName)
        if ifc[0] == "Interface":
          method = ifc[2][1][0][1:][0]
          methodRet = flatString(method[0])
          methodName = method[1]
          methodArgs = listOfString(method[2])
          ports = listOfString(method[3])[0][9:-3]
          inputNames = ports.replace('"', '').split(",")
          sigs.append(
            { 'funcName': methodName
            , 'argNames' : inputNames if ports else []
            , 'argTypes' : [translateType(arg) for arg in methodArgs]
            , 'argWidths' : [bluetcl.bitWidth(arg) for arg in methodArgs]
            , 'returnType' : translateType(methodRet)
            , 'returnWidth' : bluetcl.bitWidth(methodRet)
            })
  return sigs

# Generate function wrappers in Blarney
def genBlarneyWrappers():
  sigs = getFuncSigs()
  for sig in sigs:
    modName = "module_" + sig['funcName']
    funcName = sig['funcName'][7:]
    # Blarney type signature
    print(funcName + " :: " +
            " -> ".join(sig['argTypes'] + [sig['returnType']]))
    # Blarney function LHS
    print(funcName + " " + " ".join(sig['argNames']) + " = ")
    # Blarney function RHS
    print('  unpack $ FromBV $ makePrim1 (Custom')
    print('   ', '"' + modName + '"')
    print('   ', '[' + ", ".join(
      [ '("' + sig['funcName'] + '_' + arg + '", ' + w + ')'
        for (arg, w) in zip(sig['argNames'], sig['argWidths'])]) + ']')
    print('   ', '[("' + sig['funcName'] + '", ' + sig['returnWidth'] + ')]')
    print('   ', '[]', 'False', 'Nothing) $ ')
    print('     ', '[' + ", ".join(
      ['toBV $ pack ' + arg for arg in sig['argNames']]) + ']')
    print()

print("module CHERIBlarneyWrappers where")
print()
print("import Blarney")
print("import Blarney.Core.BV")
print()
genBlarneyWrappers()
