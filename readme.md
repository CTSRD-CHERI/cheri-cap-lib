# CHERI CAP LIB

The [cheri-cap-lib](https://github.com/CTSRD-CHERI/cheri-cap-lib.git) repository is meant to gather several specific implementations of CHERI capabilities and provide a common interface.

The `CHERICap` Bluespec typeclass in [CHERICap.bsv](CHERICap.bsv) captures the intended API to CHERI capabilities.
```bsv
function Bool isValidCap (t cap);
function t setValidCap (t cap, Bool valid);
function Bit#(flg) getFlags (t cap);
function t setFlags (t cap, Bit#(flg) flags);
function HardPerms getHardPerms (t cap);
function t setHardPerms (t cap, HardPerms hardperms);
function SoftPerms getSoftPerms (t cap);
function t setSoftPerms (t cap, SoftPerms softperms);
function Bit#(31) getPerms (t cap);
function t setPerms (t cap, Bit#(31) perms);
function Kind getKind (t cap);
function Bool isSentry (t cap);
function Bool isSealedWithType (t cap);
function Bool isSealed (t cap);
function Bit#(ot) getType (t cap);
function Exact#(t) setType (t cap, Bit#(ot) otype);
function Bit#(n) getAddr (t cap);
function Exact#(t) setAddr (t cap, Bit#(n) addr);
function t maskAddr (t cap, Bit#(maskable_bits) mask);
function Bit#(n) getOffset (t cap);
function Exact#(t) modifyOffset (t cap, Bit#(n) offset, Bool doInc);
function Exact#(t) setOffset (t cap, Bit#(n) offset);
function Exact#(t) incOffset (t cap, Bit#(n) inc);
function Bit#(n) getBase (t cap);
function Bit#(TAdd#(n, 1)) getTop (t cap);
function Bit#(TAdd#(n, 1)) getLength (t cap);
function Bool isInBounds (t cap, Bool isTopIncluded);
function Exact#(t) setBounds (t cap, Bit#(n) length);
function t nullWithAddr (Bit#(n) addr);
function t almightyCap;
function t nullCap;
function Bool validAsType (t dummy, Bit#(n) checkType);
function t fromMem (Tuple2#(Bool, Bit#(mem_sz)) mem_cap);
function Tuple2#(Bool, Bit#(mem_sz)) toMem (t cap);
```

The main currently used CHERI capability implementation using the "CHERI concentrate" format can be found in [CHERICC_Fat.bsv](CHERICC_Fat.bsv).

It is possible to export verilog wrappers for the [CHERICC_Fat.bsv](CHERICC_Fat.bsv) implementation of the `CHERICap` typeclass methods by runing `make verilog-wrappers`. It is also possible to export [blarney](https://github.com/mn416/blarney.git) wrappers by running `make blarney-wrappers`.

# TODO
- pull in the various known BSV implementations
- pull in the existing testing infrastructure
