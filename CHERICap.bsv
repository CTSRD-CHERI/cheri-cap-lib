/*-
 * Copyright (c) 2018-2021 Alexandre Joannou
 * Copyright (c) 2019 Peter Rugg
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * @BERI_LICENSE_HEADER_START@
 *
 * Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  BERI licenses this
 * file to you under the BERI Hardware-Software License, Version 1.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *   http://www.beri-open-systems.org/legal/license-1-0.txt
 *
 * Unless required by applicable law or agreed to in writing, Work distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @BERI_LICENSE_HEADER_END@
 */

package CHERICap;

export SoftPerms;
export HardPerms;
export Kind;
export BoundsInfo;
export Exact;
export SetBoundsReturn;
export showCHERICap;
export CHERICap :: *;
export Cast;

// CHERI capability types
////////////////////////////////////////////////////////////////////////////////

// Permission bits

typedef Bit #(16) SoftPerms;

typedef struct {
  Bool permitSetCID;
  Bool accessSysRegs;
  Bool permitUnseal;
  Bool permitCCall;
  Bool permitSeal;
  Bool permitStoreLocalCap;
  Bool permitStoreCap;
  Bool permitLoadCap;
  Bool permitStore;
  Bool permitLoad;
  Bool permitExecute;
  Bool global;
} HardPerms deriving(Bits, Eq, FShow);

instance Bitwise #(HardPerms);
  function \& (x1, x2) = unpack(pack(x1) & pack(x2));
  function \| (x1, x2) = unpack(pack(x1) | pack(x2));
  function \^ (x1, x2) = unpack(pack(x1) ^ pack(x2));
  function \~^ (x1, x2) = unpack(pack(x1) ~^ pack(x2));
  function \^~ (x1, x2) = unpack(pack(x1) ^~ pack(x2));
  function invert (x) = unpack(invert (pack(x))); //XXX Bluespec ref guide uses x1 here but simply x for other single arg methods...
  function \<< (x1, x2) = unpack(pack(x1) << x2);
  function \>> (x1, x2) = unpack(pack(x1) >> x2);
  function msb (x) = msb(pack(x));
  function lsb (x) = lsb(pack(x));
endinstance

// Kind of a capability, that is whether it is "sealed with a given otype", or
// if it is a "sentry" or simply "unsealed".

typedef union tagged {
  void UNSEALED;
  void SENTRY;
  void RES0;
  void RES1;
  Bit #(ot) SEALED_WITH_TYPE;
} Kind #(numeric type ot) deriving (Bits, Eq, FShow);

// helper type for gathering bounds information on a capability

typedef struct {
  Bit#(n) base;
  Bit#(TAdd#(n, 1)) top;
  Bit#(TAdd#(n, 1)) length;
  Bit#(n) repBase;
  Bit#(TAdd#(n, 1)) repTop;
  Bit#(TAdd#(n, 1)) repLength;
} BoundsInfo #(numeric type n) deriving (Bits, Eq, FShow);

// helper types and functions
////////////////////////////////////////////////////////////////////////////////

// Helper type to return the result of an operation along with whether the
// operation was exact. In cases where no sensible inexact representation
// exists, the only guarantee is that the tag bit is not set.

typedef struct {
  Bool exact;
  t    value;
} Exact #(type t) deriving (Bits);

// Helper type for the return value of the 'setBoundsCombined' method

typedef struct {
  t cap;
  Bool exact;
  Bit #(n) length;
  Bit #(n) mask;
} SetBoundsReturn #(type t, numeric type n) deriving (Bits, Eq, FShow);

// helper function to test belonging to a range
function Bool belongsToRange ( Bit #(n) x, Bit #(n) low, Bit #(n) high
                             , Bool highIncluded);
  Bool notTooHigh = highIncluded ? x <= high : x < high;
  Bool notTooLow = x >= low;
  return notTooLow && notTooHigh;
endfunction

// XXX TODO augment with all architectural bounds/ repbounds ?
function Fmt showCHERICap (t cap)
  provisos (CHERICap #(t , ot, flg, n, mem_sz, maskable_bits));
  return $format( "Valid: 0x%0x", isValidCap(cap)) +
         $format(" Perms: 0x%0x", getPerms(cap)) +
         $format(" Kind: ", fshow(getKind(cap))) +
         $format(" Addr: 0x%0x", getAddr(cap)) +
         $format(" Base: 0x%0x", getBase(cap)) +
         $format(" Length: 0x%0x", getLength(cap));
endfunction

// Cast typeclass to convert from one type to another. Helpful for converting
// a capability format to another.

typeclass Cast#(type src, type dest);
  function dest cast (src x);
endtypeclass

instance Cast#(t, t);
  function cast = id;
endinstance

// CHERI capability typeclass
////////////////////////////////////////////////////////////////////////////////

typeclass CHERICap #( type t
                    , numeric type ot
                    , numeric type flg
                    , numeric type n
                    , numeric type mem_sz
                    , numeric type maskable_bits )
  dependencies (t determines (ot, flg, n, mem_sz, maskable_bits));

  // capability validity
  //////////////////////////////////////////////////////////////////////////////

  // Return whether the Capability is valid
  function Bool isValidCap (t cap);
  // Set the capability as valid. All fields left unchanged
  function t setValidCap (t cap, Bool valid);

  // capability flags
  //////////////////////////////////////////////////////////////////////////////

  // Get the flags field
  function Bit#(flg) getFlags (t cap);
  // Set the flags field
  function t setFlags (t cap, Bit#(flg) flags);

  // capability permissions
  //////////////////////////////////////////////////////////////////////////////

  // Get the hardware permissions
  function HardPerms getHardPerms (t cap);
  // Set the hardware permissions
  function t setHardPerms (t cap, HardPerms hardperms);
  // Get the software permissions
  function SoftPerms getSoftPerms (t cap);
  // Set the software permissions
  function t setSoftPerms (t cap, SoftPerms softperms);
  // Get the architectural permissions
  function Bit#(31) getPerms (t cap) =
    zeroExtend({pack(getSoftPerms(cap)), 3'h0, pack(getHardPerms(cap))});
  // Set the architectural permissions
  function t setPerms (t cap, Bit#(31) perms) =
    setSoftPerms ( setHardPerms(cap, unpack(perms[11:0]))
                 , unpack(truncate(perms[30:15])) );

  // capability kind
  //////////////////////////////////////////////////////////////////////////////
  // Manipulate the kind of the capability, i.e. whether it is sealed, sentry,
  // unsealed, ...

  // get the kind of a capability
  function Kind#(ot) getKind (t cap);
  // set the kind of a capability
  function t setKind (t cap, Kind#(ot) kind);
  // XXX TODO Check if a type is valid
  function Bool validAsType (t dummy, Bit#(n) checkType);

  // capability in-memory architectural representation
  //////////////////////////////////////////////////////////////////////////////
  // Note that the following rule is expected to hold:
  // fromMem (tuple2 (isValidCap (cap), {getMeta (cap), getAddr (cap)})) == cap

  // Get the in-memory architectural representation of the capability metadata
  function Bit #(TSub #(mem_sz, n)) getMeta (t cap);
  // Get the in-memory architectural representation of the capability address
  function Bit #(n) getAddr (t cap);
  // Convert from in-memory architectural bit representation to capability type
  function t fromMem (Tuple2#(Bool, Bit#(mem_sz)) mem_cap);
  // Convert from capability type to in-memory architectural bit representation
  function Tuple2#(Bool, Bit#(mem_sz)) toMem (t cap);

  // capability address/offset manipulation
  //////////////////////////////////////////////////////////////////////////////

  // Set the address of the capability. Result invalid if unrepresentable
  function Exact#(t) setAddr (t cap, Bit#(n) addr);
  // Set the address of the capability. Result assumed to be representable
  function t setAddrUnsafe (t cap, Bit#(n) addr);
  // Add to the address of the capability. Result assumed to be representable
  function t addAddrUnsafe (t cap, Bit#(maskable_bits) inc);
  // Mask the least significant bits of capability address with a mask
  // maskable_width should be small enough to make this
  // safe with respect to representability
  function t maskAddr (t cap, Bit#(maskable_bits) mask);
  // Get the offset of the capability
  function Bit#(n) getOffset (t cap) = getAddr(cap) - getBase(cap);
  // Modify the offset of the capability. Result invalid if unrepresentable
  function Exact#(t) modifyOffset (t cap, Bit#(n) offset, Bool doInc);
  // Set the offset of the capability. Result invalid if unrepresentable
  function Exact#(t) setOffset (t cap, Bit#(n) offset) =
    modifyOffset(cap, offset, False);
  // Set the offset of the capability. Result invalid if unrepresentable
  function Exact#(t) incOffset (t cap, Bit#(n) inc) =
    modifyOffset(cap, inc, True);

  // capability architectural bounds queries
  //////////////////////////////////////////////////////////////////////////////
  // Note that the following rules are expected to hold:
  // getBase (cap) + getLength (cap) == getLength (cap)
  // getRepBase (cap) + getRepLength (cap) == getRepLength (cap)
  // isInRepBounds (cap) ==> isInRepBounds (cap)

  // Get all architectural bound information for a capability
  function BoundsInfo#(n) getBoundsInfo (t cap);
  // Get the base
  function Bit#(n) getBase (t cap) = getBoundsInfo(cap).base;
  // Get the top
  function Bit#(TAdd#(n, 1)) getTop (t cap) = getBoundsInfo(cap).top;
  // Get the length
  function Bit#(TAdd#(n, 1)) getLength (t cap) = getBoundsInfo(cap).length;
  // Assertion that the capability's address is between its base and top
  function Bool isInBounds (t cap, Bool isTopIncluded) =
    belongsToRange ( zeroExtend (getAddr (cap))
                   , zeroExtend (getBase (cap))
                   , getTop (cap)
                   , isTopIncluded );
  // Get the representable base
  function Bit#(n) getRepBase (t cap) = getBoundsInfo(cap).repBase;
  // Get the representable top
  function Bit#(TAdd#(n, 1)) getRepTop (t cap) = getBoundsInfo(cap).repTop;
  // Get the representable length
  function Bit#(TAdd#(n, 1)) getRepLength (t cap) =
    getBoundsInfo(cap).repLength;
  // Assertion that the capability's address is between its representable
  // base and top
  function Bool isInRepBounds (t cap, Bool isRepTopIncluded) =
    belongsToRange ( zeroExtend (getAddr (cap))
                   , zeroExtend (getRepBase (cap))
                   , getRepTop (cap)
                   , isRepTopIncluded );

  // XXX TODO Check the alignment of the base, giving least significant 2 bits.
  // This relies on the fact that internal exponents take up 2 bits of the
  // base.
  function Bit#(2) getBaseAlignment (t cap);

  // XXX TODO Get representable alignment mask
  function Bit#(n) getRepresentableAlignmentMask ( t dummy
                                                 , Bit#(n) length_request) =
    setBoundsCombined(nullCapFromDummy(dummy), length_request).mask;

  // XXX TODO Get representable length
  function Bit#(n) getRepresentableLength (t dummy, Bit#(n) length_request) =
    setBoundsCombined(nullCapFromDummy(dummy), length_request).length;

  // capability derivation (bounds set)
  //////////////////////////////////////////////////////////////////////////////

  // Set the length of the capability. Inexact: result length may be different
  // to requested
  function Exact#(t) setBounds (t cap, Bit#(n) length);
    let combinedResult = setBoundsCombined(cap, length);
    return Exact {exact: combinedResult.exact, value: combinedResult.cap};
  endfunction
  // XXX TODO
  function SetBoundsReturn#(t, n) setBoundsCombined (t cap, Bit#(n) length);

  // common capabilities
  //////////////////////////////////////////////////////////////////////////////

  // the null capability
  function t nullCap = nullCapFromDummy(?);
  // a null capability with a given address set
  function t nullWithAddr (Bit#(n) addr);
  // maximally permissive capability (initial register state)
  function t almightyCap;
  // XXX TODO Workaround to allow null cap to be derived in default
  // implementations
  function t nullCapFromDummy(t dummy);

  // Assert that the encoding is valid
  //////////////////////////////////////////////////////////////////////////////
  function Bool isDerivable (t cap);

endtypeclass

endpackage
