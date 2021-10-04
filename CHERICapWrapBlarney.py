#! /usr/bin/env python3

import re
import sys
import glob
import select
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

# Split string at outermost nesting level (w.r.t. parentheses)
def splitOuter(s, sep = ','):
  nestCount = 0
  args = []
  arg = ""
  strLen = len(s)
  sepLen = len(sep)
  i = 0
  while i < strLen:
    if s[i] == '(':
      nestCount = nestCount + 1
    elif s[i] == ')':
      nestCount = nestCount - 1
    if nestCount == 0 and i+sepLen <= strLen and s[i:i+sepLen] == sep:
      args.append(arg)
      arg = ""
      i = i + sepLen
    else:
      arg = arg + s[i]
      i = i + 1
  args.append(arg)
  return args

# Strip qualifiers from qualified name
def stripQualifiers(s):
  return splitOuter(s, "::")[-1]

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

  # Wait for response on bluetcl's stdout or stderr
  # Abort if stderr is non-empty
  def awaitResponse(self):
    ready = select.select([self.p.stderr, self.p.stdout], [], [], 1.0)
    if self.p.stderr in ready[0]:
      print("Bluetcl error: ", self.p.stderr.readline())
      sys.exit()

  # Load package
  def loadPackage(self, pkg):
    self.p.stdin.write("bpackage load " + pkg + "\n")
    self.p.stdin.flush();

  # Get bit-level representation of given type
  def bitify(self, typeName):
    self.p.stdin.write("puts [type bitify " + typeName + "]\n")
    self.p.stdin.flush()
    self.awaitResponse()
    return parseTCL(self.p.stdout.readline())

  # Determine bit width of given type
  def bitWidth(self, typeName):
    tree = self.bitify(typeName)
    return tree[2]

  # Get all functions in given package
  def getFuncs(self, pkg):
    self.p.stdin.write("puts [defs func " + pkg + "]\n")
    self.p.stdin.flush()
    self.awaitResponse()
    return parseTCL(self.p.stdout.readline())

  # Get info for given type
  def getTypeInfo(self, typeName):
    self.p.stdin.write("puts [type full " + typeName + "]\n")
    self.p.stdin.flush()
    self.awaitResponse()
    return parseTCL(self.p.stdout.readline())

# Verilog extraction
# ==================

# Generate Haskell definition of the null / almighty capability
def genCapDefn(capValName):
  files = glob.glob("*" + capValName + ".v")
  if not files:
    print("Can't find *" + capValName + ".v")
    sys.exit()
  with open(files[0]) as f:
    for line in f:
      m = re.match(".*" + capValName + " = [0-9]+'h([0-9a-fA-F]+).*", line)
      if m:
        print(capValName + "Integer :: Integer = 0x" + m.groups()[0])
        return

# Main
# ====

# Check args
if len(sys.argv) != 2:
  print("Usage: CHERICapWrapBlarney.py <MODULE_NAME>")
  sys.exit()

# Name of generated Haskell module
moduleName = sys.argv[1]

# Load CHERICapWrap module into bluetcl
bluetcl = Bluetcl()
bluetcl.loadPackage("CHERICapWrap")

# Translate Bluespec type to Blarney type
def translateType(t):
  if t == "Bool":
    return "Bit 1"
  elif t[0:5] == "Tuple" and t[6:8] == "#(" and t[-1] == ")":
    args = splitOuter(t[8:-1])
    return '(' + ", ".join([translateType(arg) for arg in args]) + ')'
  elif stripQualifiers(t) == "HardPerms":
    return "HardPerms"
  elif stripQualifiers(t)[0:10] == "BoundsInfo":
    return "BoundsInfo"
  elif stripQualifiers(t)[0:7] == "Exact#(" and t[-1] == ")":
    tbase = stripQualifiers(t)
    arg = translateType(tbase[7:-1])
    if " " in arg:
      arg = '(' + arg + ')'
    return "Exact " + arg
  elif t and t[0].islower():
    return t
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
    print('  unpack $ FromBV $ head $ makePrim (Custom')
    print('   ', '"' + modName + '"')
    print('   ', '[' + ", ".join(
      [ '("' + sig['funcName'] + '_' + arg + '", ' + w + ')'
        for (arg, w) in zip(sig['argNames'], sig['argWidths'])]) + ']')
    print('   ', '[("' + sig['funcName'] + '", ' + sig['returnWidth'] + ')]')
    print('   ', '[]', 'False', 'False', 'Nothing) ')
    print('     ', '[' + ", ".join(
      ['toBV $ pack ' + arg for arg in sig['argNames']]) + ']')
    print('     ', '[Just "' + sig['funcName'] + '"]')
    print()

# Generate Blarney type for given Bluespec struct
def genBlarneyStruct(t):
  info = bluetcl.getTypeInfo(t)
  ctrName = t.split("#")[0]
  tnew = translateType(t)
  if info[0] != "Struct":
    print("Type", t, "is not a struct")
    sys.exit()
  print("data", tnew, "=")
  print(" ", ctrName, "{")
  infoIndex = 3 if info[2] == "polymorphic" else 2
  ctrs = info[infoIndex][1]
  first = True
  for ctr in ctrs:
    print(" ", " " if first else ",", ctr[1], "::", translateType(ctr[0]))
    first = False
  print(" ", "} deriving (Generic, Interface, Bits)")
  print()

# Helpful type synonyms
def genBlarneyTypeSyns():
  icapWidth = bluetcl.bitWidth("CapPipe")
  addrWidth = bluetcl.getTypeInfo("CapAddrW")[2]
  capWidth = bluetcl.getTypeInfo("CapW")[2]
  print("type CapPipeWidth =", icapWidth)
  print("type CapPipe = Bit CapPipeWidth")
  print()
  print("type CapPipeMetaWidth =", int(icapWidth) - int(addrWidth))
  print("type CapPipeMeta = Bit CapPipeMetaWidth")
  print()
  print("type CapMemWidth =", int(capWidth) + 1)
  print("type CapMem = Bit CapMemWidth")
  print()
  print("type CapMemMetaWidth =", int(capWidth) - int(addrWidth) + 1)
  print("type CapMemMeta = Bit CapMemMetaWidth")
  print()
  print("type CapAddrWidth =", int(addrWidth))
  print("type CapAddr = Bit CapAddrWidth")
  print()

addrWidth = bluetcl.getTypeInfo("CapAddrW")[2]
print("module " + moduleName + " where")
print()
print("import Blarney")
print("import Blarney.Core.BV")
print()
genBlarneyTypeSyns()
genBlarneyStruct("Exact#(t)")
genBlarneyStruct("HardPerms")
genBlarneyStruct("BoundsInfo#(" + str(addrWidth) + ")")
genBlarneyWrappers()
genCapDefn("nullCapMem")
genCapDefn("almightyCapMem")
genCapDefn("nullCapPipe")
genCapDefn("almightyCapPipe")
