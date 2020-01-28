#! /usr/bin/env python3

import argparse
import re

parser = argparse.ArgumentParser(description=
  '''Generates a Blarney wrapper for the given Bluespec generated verilog file
     containing a module definition of a purely combinational CHERI function.
  ''')
parser.add_argument('verilog_files', metavar='VERILOG_FILE', type=str, nargs='+',
                    help='The file(s) to process')
parser.add_argument('--output', '-o', metavar='OUTPUT_FILE', type=str, nargs='?',
                    default="CHERIBlarneyWrappers",
                    help='The output Blarney Haskell module to generate')
args = parser.parse_args()

class BlarneyWrapper:
  def __init__(self, size, name, ins, out):
    self.size = size
    self.name = name
    self.ins = ins
    self.out = out
  def verilogModuleName(self):
    return "module_wrap{:d}_{:s}".format(self.size, self.name)
  def verilodInputNames(self):
    return ["wrap{:d}_{:s}_{:s}".format(self.size, self.name, nm)
                for nm in [x[0] for x in self.ins]]
  def verilogOutputName(self):
    return "wrap{:d}_{:s}".format(self.size, self.name)
  def emitBlarney(self):
    ins_names = [x[0] for x in self.ins]
    ins_wdths = [x[1] for x in self.ins]
    str_type = "{:s} :: {:s}{:s}{:s}".format(
      self.name,
      " -> ".join(["Bit {:d}".format(n) for n in ins_wdths]),
      " -> " if self.ins else "",
      "Bit {:d}".format(self.out[1]))
    str_decl = "{:s} {:s} = FromBV $\n  makePrim1 (Custom \"{:s}\" [{:s}] [{:s}] [] False) [{:s}] {:d}".format(
        self.name, " ".join(ins_names),
        self.verilogModuleName(),
        ", ".join(["\"{:s}\"".format(n) for n in self.verilodInputNames()]),
        "(\"{:s}\", {:d})".format(self.verilogOutputName(), self.out[1]),
        ", ".join(["toBV {:s}".format(nm) for nm in ins_names]),
        self.out[1])
    return "{:s}\n{:s}".format(str_type, str_decl)

def main():
  # define module regexp
  modDecl = re.compile("^module\s+module_wrap(\d+)_(\w+)\(")
  # TODO handle size 1
  #
  wrappers = []
  for fname in args.verilog_files:
    size = 0
    name = None
    ins = []
    out = ("",0)
    with open(fname, "r") as f:
      for ln in f:
        modM = modDecl.match(ln)
        if modM:
          size = int(modM.group(1))
          name = modM.group(2)
          break
      if not name:
        print("Couldn't find a valid Verilog module definition")
        exit(-1)
      # define input/output regexp
      inDecl  = re.compile("^\s*input(\s+\[(\d+)\s+:\s+0\])?\s+wrap(\d+)_"+name+"_(\w+);")
      outDecl = re.compile("^\s*output(\s+\[(\d+)\s+:\s+0\])?\s+wrap(\d+)_"+name+";")

      for ln in f:
        inM  = inDecl.match(ln)
        outM = outDecl.match(ln)
        if inM:
          ins.append((inM.group(4), (int(inM.group(2)) + 1) if inM.group(1) else 1))
        elif outM:
          out = (name, (int(outM.group(2)) + 1) if outM.group(1) else 1)
        #else:
        #  print("===>> no match for line: {:s}".format(ln))
    wrappers.append(BlarneyWrapper(size, name, ins, out))

  with open(args.output+".hs", "w") as f:
    #print("module CHERI{:d} where\n".format(size))
    f.write("module "+args.output+" where\n\n")
    f.write("import Blarney\n")
    f.write("import Blarney.BV\n")
    for w in wrappers:
      f.write("\n{:s}\n".format(w.emitBlarney()))

if __name__ == "__main__":
  main()
