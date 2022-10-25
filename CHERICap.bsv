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
  Bit #(otypeW) SEALED_WITH_TYPE;
} Kind #(numeric type otypeW) deriving (Bits, Eq, FShow);

// helper type for gathering bounds information on a capability

typedef struct {
  Bit #(addrW) base;
  Bit #(TAdd #(addrW, 1)) top;
  Bit #(TAdd #(addrW, 1)) length;
  Bit #(addrW) repBase;
  Bit #(TAdd #(addrW, 1)) repTop;
  Bit #(TAdd #(addrW, 1)) repLength;
  Bool repSplit;
} BoundsInfo #(numeric type addrW) deriving (Bits, Eq, FShow);

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
  capT cap;
  Bool exact;
  Bit #(addrW) length;
  Bit #(addrW) mask;
} SetBoundsReturn #(type capT, numeric type addrW) deriving (Bits, Eq, FShow);

// helper function to test belonging to a range
function Bool belongsToRange ( Bit #(n) x, Bit #(n) low, Bit #(n) high
                             , Bool highIncluded);
  Bool notTooHigh = highIncluded ? x <= high : x < high;
  Bool notTooLow = x >= low;
  return notTooLow && notTooHigh;
endfunction

// XXX TODO augment with all architectural bounds/ repbounds ?
function Fmt showCHERICap (capT cap)
  provisos (CHERICap #(capT , otypeW, flgW, addrW, inMemW, maskableW));
  return $format( "Valid: 0x%0x", isValidCap(cap)) +
         $format(" Perms: 0x%0x", getPerms(cap)) +
         $format(" Kind: ", fshow(getKind(cap))) +
         $format(" Addr: 0x%0x", getAddr(cap)) +
         $format(" Base: 0x%0x", getBase(cap)) +
         $format(" Length: 0x%0x", getLength(cap));
endfunction

// Cast typeclass to convert from one type to another. Helpful for converting
// a capability format to another.

typeclass Cast #(type src, type dest);
  function dest cast (src x);
endtypeclass

instance Cast #(capT, capT);
  function cast = id;
endinstance

// CHERI capability typeclass
////////////////////////////////////////////////////////////////////////////////
// Note: Some class methods receive a "dummy" capability as a type proxy
//       argument. This is useful for methods to know which capability format is
//       being operated on without requiring a specific capability value.
//       (A more elegant way to achieve this would be to use something along the
//       lines of haskell's "@type" type application mechanism)

typeclass CHERICap #( type capT              // type of the CHERICap capability
                    , numeric type otypeW    // width of the object type
                    , numeric type flgW      // width of the flags field
                    , numeric type addrW     // width of the address
                    , numeric type inMemW    // width of the capability in mem
                    , numeric type maskableW // width of maskable bits
                    )
  dependencies (capT determines (otypeW, flgW, addrW, inMemW, maskableW));

  // capability validity
  //////////////////////////////////////////////////////////////////////////////

  // Return whether the Capability is valid
  function Bool isValidCap (capT cap);
  // Set the capability as valid. All fields left unchanged
  function capT setValidCap (capT cap, Bool valid);

  // capability flags
  //////////////////////////////////////////////////////////////////////////////

  // Get the flags field
  function Bit #(flgW) getFlags (capT cap);
  // Set the flags field
  function capT setFlags (capT cap, Bit #(flgW) flags);

  // capability permissions
  //////////////////////////////////////////////////////////////////////////////

  // Get the hardware permissions
  function HardPerms getHardPerms (capT cap);
  // Set the hardware permissions
  function capT setHardPerms (capT cap, HardPerms hardperms);
  // Get the software permissions
  function SoftPerms getSoftPerms (capT cap);
  // Set the software permissions
  function capT setSoftPerms (capT cap, SoftPerms softperms);
  // Get the architectural permissions
  function Bit #(31) getPerms (capT cap) =
    zeroExtend ({pack (getSoftPerms (cap)), 3'h0, pack (getHardPerms (cap))});
  // Set the architectural permissions
  function capT setPerms (capT cap, Bit #(31) perms) =
    setSoftPerms ( setHardPerms (cap, unpack (perms[11:0]))
                 , unpack (truncate (perms[30:15])) );

  // capability kind
  //////////////////////////////////////////////////////////////////////////////
  // Manipulate the kind of the capability, i.e. whether it is sealed, sentry,
  // unsealed, ...

  // get the kind of a capability
  function Kind #(otypeW) getKind (capT cap);
  // set the kind of a capability
  function capT setKind (capT cap, Kind #(otypeW) kind);
  // Check if a type is valid (requires a dummy proxy)
  function Bool validAsType (capT dummy, Bit #(addrW) checkType);

  // capability in-memory architectural representation
  //////////////////////////////////////////////////////////////////////////////
  // Note that the following rule is expected to hold:
  // fromMem (toMem (cap)) == cap
  // fromMem (tuple2 (isValidCap (cap), {getMeta (cap), getAddr (cap)})) == cap

  // Get the in-memory architectural representation of the capability metadata
  function Bit #(TSub #(inMemW, addrW)) getMeta (capT cap);
  // Get the in-memory architectural representation of the capability address
  function Bit #(addrW) getAddr (capT cap);
  // Convert from in-memory architectural bit representation to capability type
  function capT fromMem (Tuple2 #(Bool, Bit #(inMemW)) mem_cap);
  // Convert from capability type to in-memory architectural bit representation
  function Tuple2 #(Bool, Bit #(inMemW)) toMem (capT cap);

  // capability address/offset manipulation
  //////////////////////////////////////////////////////////////////////////////

  // Set the address of the capability. Result invalid if unrepresentable
  function Exact #(capT) setAddr (capT cap, Bit #(addrW) addr);
  // Set the address of the capability. Result assumed to be representable
  function capT setAddrUnsafe (capT cap, Bit #(addrW) addr);
  // Add to the address of the capability. Result assumed to be representable
  function capT addAddrUnsafe (capT cap, Bit #(maskableW) inc);
  // Mask the least significant bits of capability address with a mask
  // maskable_width should be small enough to make this
  // safe with respect to representability
  function capT maskAddr (capT cap, Bit #(maskableW) mask);
  // Get the offset of the capability
  function Bit #(addrW) getOffset (capT cap) = getAddr(cap) - getBase(cap);
  // Modify the offset of the capability. Result invalid if unrepresentable
  function Exact #(capT) modifyOffset ( capT cap
                                      , Bit #(addrW) offset
                                      , Bool doInc);
  // Set the offset of the capability. Result invalid if unrepresentable
  function Exact #(capT) setOffset (capT cap, Bit #(addrW) offset) =
    modifyOffset(cap, offset, False);
  // Set the offset of the capability. Result invalid if unrepresentable
  function Exact #(capT) incOffset (capT cap, Bit #(addrW) inc) =
    modifyOffset(cap, inc, True);

  // capability architectural bounds queries
  //////////////////////////////////////////////////////////////////////////////
  // Note that the following rules are expected to hold:
  // getBase (cap) + getLength (cap) == getTop (cap)
  // getRepBase (cap) + getRepLength (cap) == getRepTop (cap)
  // isInBounds (cap) ==> isInRepBounds (cap)

  // Get all architectural bound information for a capability
  function BoundsInfo #(addrW) getBoundsInfo (capT cap);
  // Get the base
  function Bit #(addrW) getBase (capT cap) = getBoundsInfo(cap).base;
  // Get the top
  function Bit #(TAdd #(addrW, 1)) getTop (capT cap) = getBoundsInfo(cap).top;
  // Get the length
  function Bit #(TAdd #(addrW, 1)) getLength (capT cap) =
    getBoundsInfo(cap).length;
  // Assertion that the capability's address is between its base and top
  function Bool isInBounds (capT cap, Bool isTopIncluded) =
    belongsToRange ( zeroExtend (getAddr (cap))
                   , zeroExtend (getBase (cap))
                   , getTop (cap)
                   , isTopIncluded );
  // Get the representable base
  function Bit #(addrW) getRepBase (capT cap) = getBoundsInfo(cap).repBase;
  // Get the representable top
  function Bit #(TAdd #(addrW, 1)) getRepTop (capT cap) =
    getBoundsInfo(cap).repTop;
  // Get the representable length
  function Bit #(TAdd #(addrW, 1)) getRepLength (capT cap) =
    getBoundsInfo(cap).repLength;
  // Check if the capapbility's representable region is split (i.e. wrapping the
  // address space)
  function Bool isRepSplit (capT cap) = getBoundsInfo(cap).repSplit;
  // Assertion that the capability's address is between its representable
  // base and top
  function Bool isInRepBounds (capT cap);
    let addr = getAddr (cap);
    let bInfo = getBoundsInfo (cap);
    let okLo = addr >= bInfo.repBase;
    let okHi = zeroExtend (addr) < bInfo.repTop;
    return (okLo && okHi) || (bInfo.repSplit && (okLo != okHi));
  endfunction
  // Check the alignment of the base, giving least significant 2 bits.
  function Bit #(2) getBaseAlignment (capT cap) = getBoundsInfo (cap).base[1:0];

  // capability derivation (bounds set)
  //////////////////////////////////////////////////////////////////////////////

  // Set the length of the capability
  function SetBoundsReturn #(capT, addrW)
    setBoundsCombined (capT cap, Bit #(addrW) length);
  // Set the length of the capability. Inexact: result length may be different
  // to requested
  function Exact #(capT) setBounds (capT cap, Bit #(addrW) length);
    let combinedResult = setBoundsCombined (cap, length);
    return Exact {exact: combinedResult.exact, value: combinedResult.cap};
  endfunction
  // Round a requested length (requires a dummy proxy)
  function Bit #(addrW) roundLength (capT dummy, Bit #(addrW) reqLength) =
    setBoundsCombined (nullCapFromDummy (dummy), reqLength).length;
  // Get alignment mask for a requested length (requires a dummy proxy)
  function Bit #(addrW) alignmentMask (capT dummy, Bit #(addrW) reqLength) =
    setBoundsCombined (nullCapFromDummy (dummy), reqLength).mask;

  // common capabilities
  //////////////////////////////////////////////////////////////////////////////

  // the null capability
  function capT nullCap = nullCapFromDummy (?);
  // a null capability with a given address set
  function capT nullWithAddr (Bit #(addrW) addr);
  // maximally permissive capability (initial register state)
  function capT almightyCap;
  // the null capability (requires a dummy proxy)
  function capT nullCapFromDummy (capT dummy);

  // Assert that the encoding is valid
  //////////////////////////////////////////////////////////////////////////////

  function Bool isDerivable (capT cap);

endtypeclass

endpackage
