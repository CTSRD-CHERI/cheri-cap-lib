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
                    default="",
                    help='The output Blarney Haskell module to generate')
parser.add_argument('--generator', metavar='GENERATOR', type=str, nargs='?',
                    default='Blarney',
                    help='The generator to be used')
args = parser.parse_args()

# Generic wrapper for a Verilog module
class Wrapper:
  def __init__(self, size, name, ins, out):
    self.size = size
    self.name = name
    self.ins = ins
    self.out = out
  def verilogModuleName(self):
    return "module_wrap{:d}_{:s}".format(self.size, self.name)
  def verilogInputNames(self):
    return ["wrap{:d}_{:s}_{:s}".format(self.size, self.name, nm)
                for nm in [x[0] for x in self.ins]]
  def verilogOutputName(self):
    return "wrap{:d}_{:s}".format(self.size, self.name)
  def emit(self):
    raise NotImplementedError("Please Implement this method")


# Generic generator class
# Describes the minimum functionality that a generator needs to implement.
# A generator takes some list of Verilog modules (which includes information
# about the module name, inputs, outputs, etc) and generates a list of file
# contents that should be written.
class Generator:
  # namehint is a hint for naming, and each specific generator subclass will
  # interpret it in its own way. In many cases it may be the single generated
  # filename
  def __init__(self, namehint, mods = None):
    self.namehint = namehint
    if mods is not None:
      self.modules = mods
    else:
      self.modules = list()

  def addVerilogModule(self, mod):
    self.modules.append(mod)

  # Generates a list of tuples containing output file names and output file
  # contents to be written to disk
  def emit(self):
    raise NotImplementedError("Method not implemented in subclass")

# Generates Blarney files
# When the namehint is not empty, it is used as the filename and .hs is appended
# otherwise the old default filename of CHERIBlarneyWrappers.hs is used
class BlarneyGenerator(Generator):
  def emit(self):
    modname = "CHERIBlarneyWrappers"
    filename = modname + ".hs"
    if self.namehint is not None and self.namehint != "":
      modname = self.namehint
      filename = self.namehint + ".hs"

    contents = "module " + modname + " where\n\n"
    contents += "import Blarney\n"
    contents += "import Blarney.Core.BV\n"
    for mod in self.modules:
      print(mod.name)
      contents += "\n"
      ins_names = [x[0] for x in mod.ins]
      ins_wdths = [x[1] for x in mod.ins]
      str_type = "{:s} :: {:s}{:s}{:s}".format(
        mod.name,
        " -> ".join(["Bit {:d}".format(n) for n in ins_wdths]),
        " -> " if mod.ins else "",
        "Bit {:d}".format(mod.out[1]))
      str_decl = "{:s} {:s} = FromBV $\n  makePrim1 (Custom \"{:s}\" [{:s}] [{:s}] [] False Nothing) [{:s}]".format(
          mod.name, " ".join(ins_names),
          mod.verilogModuleName(),
          ", ".join(["(\"{:s}\", {:d})".format(n, w)
                       for (n, w) in zip(mod.verilogInputNames(),
                                         ins_wdths)]),
          "(\"{:s}\", {:d})".format(mod.verilogOutputName(), mod.out[1]),
          ", ".join(["toBV {:s}".format(nm) for nm in ins_names]))
      contents += "{:s}\n{:s}".format(str_type, str_decl)
      contents += "\n".format(str_decl)


    return [(filename, contents)]

# generates SystemVerilog files
# when the namehint is non-empty it is used as a prefix for the file name
# generates a _pkg.sv file containing:
#   a typedef of cheri_cap_t which is an "opaque" capability
#   a typedef of cheri_cap_dec_t which is a decompressed capability
# generates a _mod.sv file containing a module which combinationally takes an "opaque"
# capability as the input and gives a decompressed capability as the output
class SystemVerilogGenerator(Generator):
  def emit(self):
    cap_type_name = "cheri_cap_t"           # the name of the opaque cap type
    cap_dec_type_name = "cheri_cap_dec_t"   # the name of the expanded cap type
    cap_dec_mod_name = "cheri_cap_expander" # the name of the expanding module
    cap_in_signal_name = "cap_i"            # the name of the input signal to the expanding module
    cap_out_signal_name = "cap_o"           # the name of the output signal to the expanding module
    cap_search_string = "cap"               # the string required for inferring capability width

    pkg_file_name = "cheri_pkg.sv"
    module_file_name = "{:s}.sv".format(cap_dec_mod_name)

    # prepend namehint if non-empty
    if self.namehint is not None and self.namehint != "":
      pkg_file_name = self.namehint + "_" + pkg_file_name
      module_file_name = self.namehint + "_" + module_file_name

    pkg_name = pkg_file_name[:-3]
    dec_mod_name = module_file_name[:-3]

    # find the size of a capability by assuming that any no-input modules
    # with "cap" in the name have a capability output
    cap_size = None
    for mod in self.modules:
      if len(mod.ins) != 0 or cap_search_string not in mod.name.lower():
        continue
      cap_size = mod.out[1]
      break

    if cap_size == None:
      # the above method failed to find a capability size
      # to fix, can either implement a better method or just hard-code the capability size
      raise NotImplementedError("Unable to determine capability size from input files")


    cap_type_def_text = "  typedef logic [{:d}:0] {:s};\n".format(cap_size-1, cap_type_name)

    # assume all modules with one capability-sized input are "getters"
    # these will be the fields of the decompressed capability struct
    struct_elems = list()
    for mod in self.modules:
      if len(mod.ins) == 1 and mod.ins[0][1] == cap_size:
        struct_elems.append(mod)

    # structure definition
    struct_def_text = "  typedef struct packed {\n"
    for mod in struct_elems:
      struct_def_text += "    logic [{:d}:{:d}] {:s};\n".format(mod.out[1]-1, 0, mod.name)
    struct_def_text += "  }} {:s};\n".format(cap_dec_type_name)

    # package definition
    pkg_def_text = "package {:s};\n".format(pkg_name)
    pkg_def_text += cap_type_def_text
    pkg_def_text += struct_def_text
    pkg_def_text += "endpackage\n"

    # module definition
    module_def_text = "module {:s} (\n".format(cap_dec_mod_name)
    module_def_text += "  input  {:s}::{:s} {:s},\n".format(pkg_name, cap_type_name, cap_in_signal_name)
    module_def_text += "  output {:s}::{:s} {:s}\n".format(pkg_name, cap_dec_type_name, cap_out_signal_name)
    module_def_text += ");\n"
    module_def_text += "  import {:s}::*;\n".format(pkg_name)

    # module instantiations
    for mod in struct_elems:
      module_def_text += "  {:s} {:s}_mod (\n".format(mod.verilogModuleName(), mod.name)
      module_def_text += "    .{:s}({:s}),\n".format(mod.verilogInputNames()[0], cap_in_signal_name)
      module_def_text += "    .{:s}({:s}.{:s})\n".format(mod.verilogOutputName(), cap_out_signal_name, mod.name)
      module_def_text += "  );\n"

    module_def_text += "endmodule\n"

    return [(pkg_file_name, pkg_def_text),
            (module_file_name, module_def_text)]

def main():
  # define module regexp
  modDecl = re.compile("^module\s+module_wrap(\d+)_(\w+)\(")
  # TODO handle size 1
  #
  # gather the list of modules
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
    wrappers.append(Wrapper(size, name, ins, out))

  # choose the right generator based on the input argument
  gen = None
  if args.generator.lower() in ["systemverilog", "sv"]:
    gen = SystemVerilogGenerator(args.output, wrappers)
  elif args.generator.lower() in ["blarney"]:
    gen = BlarneyGenerator(args.output, wrappers)
  else:
    print("Invalid generator selected; exiting")
    return

  for out in gen.emit():
    with open(out[0], "w") as f:
      f.write(out[1])


if __name__ == "__main__":
  main()
