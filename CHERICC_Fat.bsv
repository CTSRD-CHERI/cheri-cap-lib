/*
 * Copyright (c) 2015-2019 Jonathan Woodruff
 * Copyright (c) 2017-2025 Alexandre Joannou
 * Copyright (c) 2019 Peter Rugg
 * Copyright (c) 2021 Dapeng Gao
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

package CHERICC_Fat;

import DefaultValue :: *;
import CHERICap     :: *;

export CapMem;
export CapReg;
export CapPipe;

export CapFat;
export MW;
export Perms;
export ResW;
export Format;
export TempFields;
export Bounds;
export UPermW;
export CapW;
export ExpW;
export CapAddrW;
export CBoundsW;
export CBounds;
export VA_Width;
export HPerms;
export PermsW;
export Exp;
export MetaInfo;
export SetBoundsReturn;
export CapTrim;
export trimCap;
export untrimCap;
export CapAddr;
export CapAddrPlus1;

// ===============================================================================

typedef struct {
  Bool v;
  t d;
} VnD#(type t) deriving (Bits);

// ===============================================================================

`ifdef CAP64
typedef 2  UPermW;
typedef 10  MW;
typedef TMul#(MW,2) CBoundsW;
typedef 5  ExpW;
typedef 3 HalfExpW;
typedef 0 ResHiW;
typedef 3 ResLoW;
typedef 32 CapAddrW;
typedef 64 CapW;
`else // CAP128 is default
typedef 4   UPermW;
typedef 14  MW;
typedef TSub#(TMul#(MW,2),1) CBoundsW;
typedef 6   ExpW;
typedef 2 HalfExpW;
typedef 7 ResHiW;
typedef 15 ResLoW;
typedef 64  CapAddrW;
typedef 128 CapW;
`endif

// The Address type is used to represent the full sized address returned to the
// consuming pipeline. In cases where fewer than CapAddrW bits are stored to
// represent a memory address (and remaining bits are usable for storing extra
// metadata), returning a value of type Address is currently expected to sign
// extend the address.
// SizeOf#(Address) should be greater or equal to CapAddrW
typedef CapAddrW AddressW;
typedef Bit#(AddressW)     Address;

// The compressed bounds field type
typedef Bit#(CBoundsW) CBounds;
// The CapAddr types
typedef Bit#(CapAddrW)          CapAddr;
typedef Bit#(TAdd#(CapAddrW,1)) CapAddrPlus1;
typedef Bit#(TAdd#(CapAddrW,2)) CapAddrPlus2;
// The Hardware permissions type
typedef struct {
  Bool permission_store_level;
  Bool permit_load_ephemeral;
  Bool permit_load_mutable;
  Bool access_sys_regs;
  Bool permit_execute;
  Bool permit_load;
  Bool permit_store;
  Bool permit_cap;
  Bool capability_level;
} HPerms deriving(Bits, Eq, FShow); // 9 bits

typedef struct {
  Bit#(5) code;
  Bool capability_level;
} CompressedHPerms deriving(Bits, Eq, FShow); // 6 bits

function HPerms compressedHPermsToHPerms(CompressedHPerms cPerms);
  let p = HPerms {
    permission_store_level: False,
    permit_load_ephemeral: False,
    permit_load_mutable: False,
    access_sys_regs: False,
    permit_execute: False,
    permit_load: False,
    permit_store: False,
    permit_cap: False,
    capability_level: cPerms.capability_level};
  case (cPerms.code)
    {2'd0,3'd1}, {2'd0,3'd5},
    {2'd1,3'd0}, {2'd1,3'd1}, {2'd1,3'd2}, {2'd1,3'd3}, {2'd1,3'd4}, {2'd1,3'd5}, {2'd1,3'd6}, {2'd1,3'd7},
    {2'd2,3'd3},
    {2'd3,3'd3}, {2'd3,3'd7}
    : p.permit_load = True;
  endcase
  case (cPerms.code)
    {2'd0,3'd4}, {2'd0,3'd5},
    {2'd1,3'd0}, {2'd1,3'd1}, {2'd1,3'd4}, {2'd1,3'd5}, {2'd1,3'd6}, {2'd1,3'd7},

    {2'd3,3'd7}
    : p.permit_store = True;
  endcase
  case (cPerms.code)

    {2'd1,3'd0}, {2'd1,3'd1}, {2'd1,3'd2}, {2'd1,3'd3}, {2'd1,3'd4}, {2'd1,3'd5},
    {2'd2,3'd3},
    {2'd3,3'd3}, {2'd3,3'd7}
    : p.permit_cap = True;
  endcase
  case (cPerms.code)

    {2'd1,3'd0}, {2'd1,3'd1}, {2'd1,3'd2}, {2'd1,3'd3}, {2'd1,3'd4}, {2'd1,3'd5},

    {2'd3,3'd3}, {2'd3,3'd7}
    : p.permit_load_mutable = True;
  endcase
  case (cPerms.code)

    {2'd1,3'd0}, {2'd1,3'd1}, {2'd1,3'd2}, {2'd1,3'd3}, {2'd1,3'd4}, {2'd1,3'd5}, {2'd1,3'd6}, {2'd1,3'd7}


    : p.permit_execute = True;
  endcase
  case (cPerms.code)

    {2'd1,3'd0}, {2'd1,3'd1}


    : p.access_sys_regs = True;
  endcase
  return p;
endfunction

function Bool compressedHPermsToIntMode(CompressedHPerms cPerms);
  return (case (cPerms.code)

      {2'd1,3'd0}, {2'd1,3'd2}, {2'd1,3'd4}, {2'd1,3'd6}


      : return False;
      default: return True;
    endcase);
endfunction

// The permissions field, including both "soft" and "hard" permission bits.
typedef struct {
  Bit#(UPermW) soft;
  Bool         intMode;
  HPerms       hard;
} Perms deriving(Bits, Eq, FShow);

typedef struct {
  Bit#(UPermW) soft;
  CompressedHPerms chperms;
} CPerms deriving(Bits, Eq, FShow);

function Perms getPermsField(CapabilityInMemory memcap);
`ifdef CAP64
  return Perms{
    soft: memcap.perms.soft,
    intMode: compressedHPermsToIntMode(memcap.perms.chperms),
    hard: compressedHPermsToHPerms(capmmemcapem.perms.chperms)
  };
`else
  return memcap.perms;
`endif
endfunction

// The full capability structure, including the "tag" bit.
`ifdef CAP64
typedef struct {
  Bool         isCapability;
  Bit#(ResHiW) reserved_hi; // 0-bits in this case
  CPerms       perms;
  Bit#(ResLoW) reserved_lo;
  Bool         sealed;
  CBounds      bounds;
  CapAddr      address;
} CapabilityInMemory deriving (Bits, Eq, FShow); // CapW + 1 (tag bit)
`else
typedef struct {
  Bool         isCapability; // 1
  Bit#(ResHiW) reserved_hi;  // 7
  Perms        perms;        // 4 + 1 + 9
  Bit#(ResLoW) reserved_lo;  // 15
  Bool         sealed;       // 1
  CBounds      bounds;       // 27
  CapAddr      address;      // 64
} CapabilityInMemory deriving (Bits, Eq, FShow); // CapW + 1 (tag bit)
`endif

// The full capability structure as Bits, including the "tag" bit.
typedef Bit#(TAdd#(CapW,1)) Capability;
// not including the tag bit
typedef Bit#(CapW) CapBits;
/* TODO
staticAssert(valueOf(SizeOf#(CapabilityInMemory))==valueOf(SizeOf#(Capability)),
    "The CapabilityInMemory type has incorrect size of " + integerToString(valueOf(SizeOf#(CapabilityInMemory))) + " (CapW = " + integerToString(valueOf(CapW)) + ")"
);
*/
// Bit type of the debug capability
typedef Bit#(CapW) DebugCap;
// Format of the cheri concentrate capability
typedef enum {Exp0, EmbeddedExp} Format deriving (Bits, Eq, FShow);
// Exponent type
typedef UInt#(ExpW) Exp;

// unpacked capability format
typedef struct {
  Bool           isCapability;
  Bit#(CapAddrW) address;
  Bit#(MW)       addrBits;
  Perms          perms;
  Bit#(ResHiW)   reserved_hi;
  Bit#(ResLoW)   reserved_lo;
  Bool           sealed;
  Format         format;
  Bounds         bounds;
} CapFat deriving (Bits);

// "Architectural FShow"
function Fmt showArchitectural(CapFat cap) =
  $format("valid:%b", cap.isCapability)
  + $format(" perms:0x%x", getPerms(cap))
  + $format(" kind:", fshow(getKind(cap)))
  + $format(" offset:0x%x", getOffsetFat(cap, getTempFields(cap)))
  + $format(" base:0x%x", getBotFat(cap, getTempFields(cap)))
  + $format(" length:0x%x", getLengthFat(cap, getTempFields(cap)));

// "Microarchitectural FShow"
instance FShow#(CapFat);
  function Fmt fshow(CapFat cap) =
    $format("valid:%b", cap.isCapability)
    + $format(" perms:0x%x", getPerms(cap))
    + $format(" reserved hi:0x%x", cap.reserved_hi)
    + $format(" reserved hi:0x%x", cap.reserved_lo)
    + $format(" format:", fshow(cap.format))
    + $format(" bounds:", fshow(cap.bounds))
    + $format(" address:0x%x", cap.address)
    + $format(" addrBits:0x%x", cap.addrBits)
    + $format(" {bot:0x%x top:0x%x len:0x%x offset:0x%x}",
                getBotFat(cap, getTempFields(cap)),
                getTopFat(cap, getTempFields(cap)),
                getLengthFat(cap, getTempFields(cap)),
                getOffsetFat(cap, getTempFields(cap)))
    + $format(" (TempFields: {") + fshow(getTempFields(cap)) + $format("})");
endinstance

// default value for CatFat
CapFat defaultCapFat = defaultValue;

// unpack a memory representation of the capability
function CapFat unpackCap(Capability thin);
  CapabilityInMemory memCap = unpack(thin);
  // extract the fields from the memory capability
  CapFat fat = defaultValue;
  fat.isCapability = memCap.isCapability;
  fat.perms        = getPermsField(memCap);
  fat.reserved_hi  = memCap.reserved_hi;
  fat.reserved_lo  = memCap.reserved_lo;
  fat.sealed       = memCap.sealed;
  match {.f, .b}   = decBounds(memCap.bounds);
  fat.format       = f;
  fat.bounds       = b;
  fat.address      = memCap.address;
  // The next few lines are to optimise the critical path of generating addrBits.
  // The value of Exp can now be 0 or come from token, so assume they come from the token,
  // then select the lower bits at the end if they didn't after all.
  BoundsEmbeddedExp tmp = unpack(memCap.bounds);
  Exp potentialExp = unpack({tmp.expTopHalf,tmp.expBotHalf});
  Bit#(MW) potentialAddrBits = truncate(memCap.address >> potentialExp);
  fat.addrBits = tmp.embeddedExp ? potentialAddrBits
                                 : truncate(memCap.address);
  return fat;
endfunction

// pack the fat capability into the memory representation
function Capability packCap(CapFat fat);
  CapabilityInMemory thin = CapabilityInMemory{
      isCapability: fat.isCapability
    , perms:        fat.perms
    , reserved_hi:  fat.reserved_hi
    , reserved_lo:  fat.reserved_lo
    , sealed:       fat.sealed
    , bounds:       encBounds(fat.format,fat.bounds)
    , address:      fat.address };
  return pack(thin);
endfunction

// The temporary fields
typedef MetaInfo TempFields;

// Interface functions
//------------------------------------------------------------------------------
function BoundsInfo#(CapAddrW) getBoundsInfoFat (CapFat cap, TempFields tf)
  provisos ( NumAlias #(fullW, TAdd #(CapAddrW, 1))
           , NumAlias #(upperW, TSub #(fullW, MW))
           , NumAlias #(lowerW, MW) );

  // shared useful bindings and precomputed values
  //////////////////////////////////////////////////////////////////////////////

  // bind the Bounds field of the CapFat to shorter handy names
  Exp exp = cap.bounds.exp;
  Bit #(MW) baseBits = cap.bounds.baseBits;
  Bit #(MW) topBits = cap.bounds.topBits;
  // prepare representable bound bits
  Bit #(MW) repBoundBits = tf.repBoundBits;

  // prepare typed "lower" MW zeroes for simpler concatenation
  Bit #(lowerW) lowerZeroes = 0;

  // prepare "full" version for baseBits, topBits and repBoundBits
  Bit #(fullW) baseBitsFull = zeroExtend (baseBits) << exp;
  Bit #(fullW) topBitsFull = zeroExtend (topBits) << exp;
  Bit #(fullW) repBoundBitsFull = zeroExtend (repBoundBits) << exp;

  // other helper values
  CapAddr capAddr0 = 0;
  CapAddrPlus1 addrSpaceTop = {1'b1, capAddr0};
  Bool alwaysRep = exp >= resetExp - 2;

  // shared +1 and -1/~0 shifted by exponent
  Bit #(upperW) allOnesExpShifted = ~0 << exp;
  let mask = allOnesExpShifted;
  let minusOne = allOnesExpShifted;
  Bit #(upperW) oneExpShifted = 1 << exp;
  let plusOne = oneExpShifted;

  // Prepare "upper" address and its "hi" and "lo" region versions
  Bit #(upperW) addrUpperBits = truncateLSB ({1'b0, cap.address}) & mask;
  Bit #(upperW) addrUpperHi = addrUpperBits + (tf.addrHi ? 0 : plusOne);
  Bit #(upperW) addrUpperLo = addrUpperBits + (tf.addrHi ? minusOne : 0);
  function addrUpper (isHi) = isHi ? addrUpperHi : addrUpperLo;

  // compute base
  //////////////////////////////////////////////////////////////////////////////

  // Use the appropriate upper bits of the address based on whether the base is
  // in the "hi" or the "lo" region, append implied zeroes in the lower bits,
  // and or in the base bits
  CapAddr base =
    truncate ({addrUpper (tf.baseHi), lowerZeroes} | baseBitsFull);

  // compute top
  //////////////////////////////////////////////////////////////////////////////

  // Use the appropriate upper bits of the address based on whether the top is
  // in the "hi" or the "lo" region, append implied zeroes in the lower bits,
  // and or in the top bits
  CapAddrPlus1 top = {addrUpper (tf.topHi), lowerZeroes} | topBitsFull;
  // If the base and top are more than an address space away from eachother,
  // invert the 64th/32nd bit of Top. This corrects for errors that happen when
  // the representable space wraps the address space.
  Bit #(2) topTip = truncateLSB (top);
  Bit #(2) baseTip = {1'b0, msb (base)};
  // If the bit we're interested in are actually coming from baseBits, select
  // the correct one from there.
  // exp == (resetExp - 1) doesn't matter since we will not flip unless
  // exp < resetExp - 1.
  if (exp == (resetExp - 2)) baseTip = {1'b0, baseBits[valueOf(MW) - 1]};
  // Do the final check.
  // If exp >= resetExp - 1, the bits we're looking at are coming directly from
  // topBits and baseBits, are not being inferred, and therefore do not need
  // correction. If we are below this range, check that the difference between
  // the resulting top and bottom is less than one address space.  If not, flip
  // the msb of the top.
  if (exp < (resetExp - 1) && (topTip - baseTip) > 1)
    top[valueOf(CapAddrW)] = ~top[valueOf(CapAddrW)];

  // compute length
  //////////////////////////////////////////////////////////////////////////////

  // Get the top and base bits with the 2 correction bits prepended
  Bit #(TAdd #(MW, 2)) correctBase = {pack (tf.baseCorrection), baseBits};
  Bit #(TAdd #(MW, 2)) correctTop  = {pack (tf.topCorrection), topBits};
  // Get the length by subtracting base from top and shifting appropriately, and
  // saturate in case of big exponent
  CapAddr length =
    (exp >= resetExp) ? ~0 : zeroExtend (correctTop - correctBase) << exp;

  // compute repBase
  //////////////////////////////////////////////////////////////////////////////

  // Use the "lo" region upper bits of the address, append implied zeroes in the
  // lower bits, and or in the representable bound bit.
  // Saturate to zero when in the "always representable" case,
  // i.e. exp >= resetExp - 2.
  CapAddr repBase =
    alwaysRep ? capAddr0
              : truncate ({addrUpperLo, lowerZeroes} | repBoundBitsFull);

  // compute repTop
  //////////////////////////////////////////////////////////////////////////////

  // Use the "hi" region upper bits of the address, append implied zeroes in the
  // lower bits, and or in the representable bound bits
  // Saturate to 1 and all zeroes when in the "always representable" case,
  // i.e. exp >= resetExp - 2.
  CapAddrPlus1 repTop =
    alwaysRep ? addrSpaceTop
              : {addrUpperHi, lowerZeroes} | repBoundBitsFull;

  // compute repLength
  //////////////////////////////////////////////////////////////////////////////

  CapAddrPlus1 repLength = {oneExpShifted, lowerZeroes};

  // compute split of representable space
  //////////////////////////////////////////////////////////////////////////////

  Bool repSplit = alwaysRep ? False : ! unpack (reduceOr (addrUpperHi));

  // return populated BoundsInfo structure
  //////////////////////////////////////////////////////////////////////////////

  return BoundsInfo { base: base
                    , top: top
                    , length: length
                    , repBase: repBase
                    , repTop: repTop
                    , repLength: repLength
                    , repSplit: repSplit };
endfunction

function CapAddr getBotFat(CapFat cap, TempFields tf);
  // First, construct a full length value with the base bits and the
  // correction bits above, and shift that value to the appropriate spot.
  CapAddr addBase = signExtend({pack(tf.baseCorrection), cap.bounds.baseBits}) << cap.bounds.exp;
  // Build a mask on the high bits of a full length value to extract the high
  // bits of the address.
  Bit#(TSub#(CapAddrW,MW)) mask = ~0 << cap.bounds.exp;
  // Extract the high bits of the address (and append the implied zeros at the
  // bottom), and add with the previously prepared value.
  return {truncateLSB(cap.address)&mask,0} + addBase;
endfunction
function CapAddrPlus1 getTopFat(CapFat cap, TempFields tf);
  // First, construct a full length value with the top bits and the
  // correction bits above, and shift that value to the appropriate spot.
  CapAddrPlus1 addTop = signExtend({pack(tf.topCorrection), cap.bounds.topBits}) << cap.bounds.exp;
  // Build a mask on the high bits of a full length value to extract the high
  // bits of the address.
  Bit#(TSub#(TAdd#(CapAddrW,1),MW)) mask = ~0 << cap.bounds.exp;
  // Extract the high bits of the address (and append the implied zeros at the
  // bottom), and add with the previously prepared value.
  CapAddrPlus1 ret = {truncateLSB({1'b0,cap.address})&mask,0} + addTop;
  // If the bottom and top are more than an address space away from eachother,
  // invert the 64th/32nd bit of Top.  This corrects for errors that happen
  // when the representable space wraps the address space.
  Bit#(2) topTip = truncateLSB(ret);
  // Calculate the msb of the base.
  // First assume that only the address and correction are involved...
  Bit#(TSub#(CapAddrW,MW)) bot = truncateLSB(cap.address) + (signExtend(pack(tf.baseCorrection)) << cap.bounds.exp);
  Bit#(2) botTip = {1'b0, msb(bot)};
  // If the bit we're interested in are actually coming from baseBits, select
  // the correct one from there.
  // exp == (resetExp - 1) doesn't matter since we will not flip unless
  // exp < resetExp-1.
  if (cap.bounds.exp == (resetExp - 2)) botTip = {1'b0, cap.bounds.baseBits[valueOf(MW)-1]};
  // Do the final check.
  // If exp >= resetExp - 1, the bits we're looking at are coming directly from
  // topBits and baseBits, are not being inferred, and therefore do not need
  // correction. If we are below this range, check that the difference between
  // the resulting top and bottom is less than one address space.  If not, flip
  // the msb of the top.
  if (cap.bounds.exp<(resetExp-1) && (topTip - botTip) > 1)
    ret[valueOf(CapAddrW)] = ~ret[valueOf(CapAddrW)];
  return ret;
endfunction
function CapAddr getLengthFat(CapFat cap, TempFields tf);
  // Get the top and base bits with the 2 correction bits prepended
  Bit#(TAdd#(MW,2)) top  = {pack(tf.topCorrection),cap.bounds.topBits};
  Bit#(TAdd#(MW,2)) base = {pack(tf.baseCorrection),cap.bounds.baseBits};
  // Get the length by substracting base from top and shifting appropriately
  CapAddr length = zeroExtend(top - base) << cap.bounds.exp;
  // Return a saturated length in case of big exponent
  // TODO: The saturation behaviour here is short of being correct
  return (cap.bounds.exp >= resetExp) ? ~0 : length;
endfunction
function Address getOffsetFat(CapFat cap, TempFields tf);
  // Get the exponent
  Exp e = cap.bounds.exp;
  // Get the base bits with the 2 correction bits prepended
  Bit#(TAdd#(MW,2)) base = {pack(tf.baseCorrection),cap.bounds.baseBits};
  // Get the offset bits by substracting the previous value from the addrBits
  Bit#(TAdd#(MW,2)) offset = {2'b0, cap.addrBits} - base;
  // Grab the bottom bits of the address and sign extend them to the size of Address
  Address addrLSB = signExtend(cap.address & ~(~0 << e));
  // Return the computed offset bits (sign extended) shifted appropriatly,
  // with the low address bits appended
  return (signExtend(offset) << e) | addrLSB;
endfunction
function Bit#(31) getPerms(CapFat cap);
  Bit#(SizeOf#(HPerms)) hardPerms = zeroExtend(pack(cap.perms.hard));
  Bit#(UPermW) softPerms = zeroExtend(pack(cap.perms.soft));
  return zeroExtend({softPerms,hardPerms});
endfunction
function TempFields getTempFields(CapFat cap) = getMetaInfo(cap);
function Bool capInBounds(CapFat cap, TempFields tf, Bool inclusive);
  // Check that the pointer of a capability is currently within the bounds
  // of the capability
  Bool ptrVStop = inclusive ? cap.addrBits <= cap.bounds.topBits
                            : cap.addrBits <  cap.bounds.topBits;
  // Top is ok if the pointer and top are in the same alignment region
  // and the pointer is less than the top.  If they are not in the same
  // alignment region, it's ok if the top is in Hi and the bottom in Low.
  Bool topOk  = (tf.topHi  == tf.addrHi) ? ptrVStop : tf.topHi;
  Bool baseOk = (tf.baseHi == tf.addrHi) ? cap.addrBits >= cap.bounds.baseBits
                                         : tf.addrHi;
  return topOk && baseOk;
endfunction
function CapFat setCapPointer(CapFat cap, CapAddr pointer);
  // Function to "cheat" and just set the pointer when we know that
  // it will be in representable bounds by some other means.
  CapFat ret   = cap;
  ret.address  = pointer;
  ret.addrBits = truncate(ret.address >> ret.bounds.exp);
  return ret;
endfunction
// Only currently used for algorithm comparison.

function Bit#(n) smearMSBRight(Bit#(n) x);
  Bit#(n) res = x;
  for (Integer i = 0; i < valueOf(TLog#(n))-1; i = i + 1)
    res = res | (res >> 2**i);
  return res;
endfunction

function SetBoundsReturn#(CapFat, CapAddrW) setBoundsFat(CapFat cap, Address lengthFull, TempFields tf);
  CapFat ret = cap;
  // Find new exponent by finding the index of the most significant bit of the
  // length, or counting leading zeros in the high bits of the length, and
  // substracting them to the CapAddr width (taking away the bottom MW-1 bits:
  // trim (MW-1) bits from the bottom of length since any length with a
  // significance that small will yield an exponent of zero).
  CapAddr length = truncate(lengthFull);
  Bit#(TSub#(CapAddrW,TSub#(MW,1))) lengthMSBs = truncateLSB(length);
  Exp zeros = zeroExtend(countZerosMSB(lengthMSBs));
  // Adjust resetExp by one since it's scale reaches 1-bit greater than a
  // 64-bit length can express.
  Bool maxZero = (zeros==(resetExp-1));
  Bool intExp = !(maxZero && length[fromInteger(valueOf(TSub#(MW,2)))]==1'b0);
  // Do this without subtraction
  //fromInteger(valueof(TSub#(SizeOf#(Address),TSub#(MW,1)))) - zeros;
  Exp e = (resetExp-1) - zeros;
  // Derive new base bits by extracting MW bits from the capability address
  // starting at the new exponent's position.
  CapAddrPlus2 base = {2'b0, cap.address};
  Bit#(TAdd#(MW,1)) newBaseBits = truncate(base>>e);

  // Derive new top bits by extracting MW bits from the capability address +
  // requested length, starting at the new exponent's position, and rounding up
  // if significant bits are lost in the process.
  CapAddrPlus2 len = {2'b0, length};
  CapAddrPlus2 top = base + len;

  // Create a mask with all bits set below the MSB of length and then masking
  // all bits below the mantissa bits.
  CapAddrPlus2 lmask = smearMSBRight(len);
  // The shift amount required to put the most significant set bit of the len
  // just above the bottom HalfExpW bits that are taken by the exp.
  Integer shiftAmount = valueOf(TSub#(TSub#(MW,2),HalfExpW));

  // Calculate all values associated with E=e (e not rounding up)
  // Round up considering the stolen HalfExpW exponent bits if required
  Bit#(TAdd#(MW,1)) newTopBits = truncate(top>>e);
  // Check if non-zero bits were lost in the low bits of top, either in the 'e'
  // shifted out bits or in the HalfExpW bits stolen for the exponent
  // Shift by MW-1 to move MSB of mask just below the mantissa, then up
  // HalfExpW more to take in the bits that will be lost for the exponent when
  // it is non-zero.
  CapAddrPlus2 lmaskLor = lmask>>fromInteger(shiftAmount+1);
  CapAddrPlus2 lmaskLo  = lmask>>fromInteger(shiftAmount);
  // For the len, we're not actually losing significance since we're not
  // storing it, we just want to know if any low bits are non-zero so that we
  // will know if it will cause the total length to round up.
  Bool lostSignificantLen  = (len&lmaskLor)!=0 && intExp;
  Bool lostSignificantTop  = (top&lmaskLor)!=0 && intExp;
  // Check if non-zero bits were lost in the low bits of base, either in the
  // 'e' shifted out bits or in the HalfExpW bits stolen for the exponent
  Bool lostSignificantBase = (base&lmaskLor)!=0 && intExp;

  // Calculate all values associated with E=e+1 (e rounding up due to msb of L
  // increasing by 1) This value is just to avoid adding later.
  Bit#(MW) newTopBitsHigher = truncateLSB(newTopBits);
  // Check if non-zero bits were lost in the low bits of top, either in the 'e'
  // shifted out bits or in the HalfExpW bits stolen for the exponent Shift by
  // MW-1 to move MSB of mask just below the mantissa, then up HalfExpW more to
  // take in the bits that will be lost for the exponent when it is non-zero.
  Bool lostSignificantTopHigher  = (top&lmaskLo)!=0 && intExp;
  // Check if non-zero bits were lost in the low bits of base, either in the
  // 'e' shifted out bits or in the HalfExpW bits stolen for the exponent
  Bool lostSignificantBaseHigher = (base&lmaskLo)!=0 && intExp;
  // If either base or top lost significant bits and we wanted an exact
  // setBounds, void the return capability

  // We need to round up Exp if the msb of length will increase.
  // We can check how much the length will increase without looking at the
  // result of adding the length to the base.  We do this by adding the lower
  // bits of the length to the base and then comparing both halves (above and
  // below the mask) to zero.  Either side that is non-zero indicates an extra
  // "1" that will be added to the "mantissa" bits of the length, potentially
  // causing overflow.  Finally check how close the requested length is to
  // overflow, and test in relation to how much the length will increase.
  CapAddrPlus2 topLo = (lmaskLor & len) + (lmaskLor & base);
  CapAddrPlus2 mwLsbMask = lmaskLor ^ lmaskLo;
  // If the first bit of the mantissa of the top is not the sum of the
  // corrosponding bits of base and length, there was a carry in.
  Bool lengthCarryIn = (mwLsbMask & top) != ((mwLsbMask & base)^(mwLsbMask & len));
  Bool lengthRoundUp = lostSignificantTop;
  Bool lengthIsMax        = (len & (~lmaskLor)) == (lmask ^ lmaskLor);
  Bool lengthIsMaxLessOne = (len & (~lmaskLor)) == (lmask ^ lmaskLo);

  Bool lengthOverflow = False;
  if (lengthIsMax && (lengthCarryIn || lengthRoundUp)) lengthOverflow = True;
  if (lengthIsMaxLessOne && lengthCarryIn && lengthRoundUp) lengthOverflow = True;

  if(lengthOverflow && intExp) begin
    e = e+1;
    ret.bounds.topBits = lostSignificantTopHigher ? newTopBitsHigher + 'b1000
                                                  : newTopBitsHigher;
    ret.bounds.baseBits = truncateLSB(newBaseBits);
  end else begin
    ret.bounds.topBits = lostSignificantTop ? truncate(newTopBits + 'b1000)
                                            : truncate(newTopBits);
    ret.bounds.baseBits = truncate(newBaseBits);
  end
  Bool exact = !(lostSignificantBase || lostSignificantTop);

  ret.bounds.exp = e;
  // Update the addrBits fields
  ret.addrBits = ret.bounds.baseBits;
  // Derive new format from newly computed exponent value, and round top up if
  // necessary
  if (!intExp) begin // If we have an Exp of 0 and no implied MSB of L.
    ret.format = Exp0;
  end else begin
    ret.format = EmbeddedExp;
    Bit#(HalfExpW) botZeroes = 0;
    ret.bounds.baseBits = {truncateLSB(ret.bounds.baseBits), botZeroes};
    ret.bounds.topBits  = {truncateLSB(ret.bounds.topBits),  botZeroes};
  end

  // Begin calculate newLength in case this is a request just for a
  // representable length:
  CapAddrPlus2 newLength = {2'b0, length};
  CapAddrPlus2 baseMask = -1; // Override the result from the previous line if
                              // we represent everything.
  if (intExp) begin
    CapAddrPlus2 oneInLsb = (lmask ^ (lmask>>1)) >> shiftAmount;
    CapAddrPlus2 newLengthRounded = newLength + oneInLsb;
    newLength        = (newLength        & (~lmaskLor));
    newLengthRounded = (newLengthRounded & (~lmaskLor));
    if (lostSignificantLen) newLength = newLengthRounded;
    baseMask = (lengthIsMax && lostSignificantTop) ? ~lmaskLo : ~lmaskLor;
  end

  // In parallel, work out if the result is going to be in bounds

  // Base computation simple since tf and addrBits already extracted
  // Logic same as capInBounds
  Bool newBaseInBounds = (tf.baseHi == tf.addrHi) ? cap.addrBits >= cap.bounds.baseBits
                                                  : tf.addrHi;

  // Interpret the requested length relative to the authorising cap
  CapAddr lengthShifted = length >> cap.bounds.exp;

  // Split the length into the mantissa, and the bits that overflowed
  Bit#(TSub#(CapAddrW, MW)) lengthExcess = truncateLSB(lengthShifted);
  Bit#(MW) lengthBits = truncate(lengthShifted);

  // If length didn't fit into the mantissa, it's definitely too big
  Bool lengthDisqualified = lengthExcess != 0;

  // Compute the new top bits, assuming the same exponent
  Bit#(TAdd#(MW, 1)) reqTopBits = {1'b0,cap.addrBits} + {1'b0,lengthBits};

  // Find the difference between the current and new top bits
  Int#(TAdd#(MW, 2)) topDiff = unpack({pack(tf.topCorrection), cap.bounds.topBits} - {1'b0,reqTopBits});

  // Compute on bits below the mantissa for edge cases
  CapAddrPlus2 lowMask = ~((~0) << cap.bounds.exp);
  CapAddrPlus2 carryMask = ~lowMask & (lowMask << 1);

  // Recover carry inputs to each bit of top calculation
  CapAddrPlus2 carries = len ^ base ^ top;

  Bool lowCarry = (carries & carryMask) != 0;
  Bool lowRemainder = (top & lowMask) != 0;

  // Address the cases for the top: difference in the mantissa bits dictates slack in the lower bits
  Bool newTopInBounds = !lengthDisqualified && (
                             topDiff > 1
                          || (topDiff == 1 && !(lowCarry && lowRemainder))
                          || (topDiff == 0 && !(lowCarry || lowRemainder))
                        );

  // Address the last case: address is zero being interpreted as the top of the address space.
  Bool addressWrap = len == 0 && cap.address == 0 && cap.bounds.baseBits != 0;

  Bool resultInBounds = newBaseInBounds && newTopInBounds && !addressWrap;

  // Nullify the capability if the result is not in bounds
  if (!resultInBounds) ret.isCapability = False;

  // Return derived capability
  return SetBoundsReturn { cap:    ret
                         , exact:  exact
                         , length: truncate(newLength)
                         , mask:   truncate(baseMask)
                         , inBounds: resultInBounds };
endfunction
function CapFat seal(CapFat cap, TempFields tf);
  CapFat ret = cap;
  ret.sealed = True;
  return ret;
endfunction
function CapFat unseal(CapFat cap, x _);
  CapFat ret = cap;
  ret.sealed = False;
  return ret;
endfunction
function VnD#(CapFat) incOffsetFat( CapFat cap
                                  , CapAddr pointer
                                  , CapAddr offset // this is the increment in inc offset, and the offset in set offset
                                  , TempFields tf
                                  , Bool setOffset);
// NOTE:
// The 'offset' argument is the "increment" value when setOffset is false, and
// the actual "offset" value when setOffset is true.
//
// For this function to work correctly, we must have
// 'offset' = 'pointer'-'cap.address'.
// In the most critical case we have both available and picking one or the
// other is less efficient than passing both.  If the 'setOffset' flag is set,
// this function will ignore the 'pointer' argument and use 'offset' to set the
// offset of 'cap' by adding it to the capability base. If the 'setOffset' flag
// is not set, this function will increment the offset of 'cap' by replacing
// the 'cap.address' field with the 'pointer' argument (with the assumption
// that the 'pointer' argument is indeed equal to 'cap.address'+'offset'.  The
// 'cap.addrBits' field is also updated accordingly.
  CapFat ret = cap;
  Exp e = cap.bounds.exp;
  // Updating the address of a capability requires checking that the new
  // address is still within representable bounds. For capabilities with big
  // representable regions (with exponents >= resetExp-2), there is no
  // representability issue.
  // For the other capabilities, the check consists of two steps:
  // - A "inRange" test
  // - A "inLimits" test

  // The inRange test
  // ----------------
  // Conceptually, the inRange test checks the magnitude of 'offset' is less
  // then the representable region's size S. This ensures that the inLimits
  // test result is meaningful. The test succeeds if the absolute value of
  // 'offset' is less than S, that is -S < 'offset' < S. This test reduces to a
  // check that there are no significant bits in the high bits of 'offset',
  // that is they are all ones or all zeros.
  CapAddr offsetAddr = offset;
  Bit#(TSub#(CapAddrW,MW)) signBits       = signExtend(offset[valueOf(TSub#(CapAddrW,1))]);
  Bit#(TSub#(CapAddrW,MW)) highOffsetBits = truncateLSB(offsetAddr);
  Bit#(TSub#(CapAddrW,MW)) highBitsfilter = -1 << e;
  highOffsetBits = (highOffsetBits ^ signBits) & highBitsfilter;
  Bool inRange = (highOffsetBits == 0);

  // The inLimits test
  // -----------------
  // Conceptually, the inLimits test ensures that neither the of the edges of
  // the representable region have been crossed with the new address. In
  // essence, it compares the distance 'offsetBits' added (on MW bits) with the
  // distance 'toBounds' to the edge of the representable space (on MW bits).
  // - For a positive or null increment
  //   inLimits = offsetBits < toBounds - 1
  // - For a negative increment:
  //   inLimits = (offsetBits >= toBounds) and ('we were not already on the
  //   bottom edge') (when already on the bottom edge of the representable
  //   space, the relevant bits of the address and those of the representable
  //   edge are the same, leading to a false positive on the i >= toBounds
  //   comparison)

  // The sign of the increment
  Bool posInc = msb(offsetAddr) == 1'b0;

  // The offsetBits value corresponds to the appropriate slice of the
  // 'offsetAddr' argument
  Bit#(MW) offsetBits  = truncate(offsetAddr >> e);

  // The toBounds value is given by substracting the address of the capability
  // from the address of the edge of the representable region (on MW bits) when
  // the 'setOffset' flag is not set. When it is set, it is given by
  // substracting the base address of the capability from the edge of the
  // representable region (on MW bits).  This value is both the distance to the
  // representable top and the distance to the representable bottom (when
  // appended to a one for negative sign), a convenience of the two's
  // complement representation.

  // NOTE: When the setOffset flag is set, toBounds should be the distance from
  // the base to the representable edge. This can be computed efficiently, and
  // without relying on the temporary fields, as follows: equivalent to
  // (repBoundBits - cap.bounds.baseBits):
  Bit#(MW) toBounds_A   = {3'b110,0};
  // equivalent to (repBoundBits - cap.bounds.baseBits - 1):
  Bit#(MW) toBoundsM1_A = toBounds_A - 1;
  /*
  XXX not sure if we still care about that
  if (toBoundsM1_A != (toBounds_A-1)) $display("error %x", toBounds_A[15:13]);
  */
  // When the setOffset flag is not set, we need to use the temporary fields
  // with the upper bits of the representable bounds
  Bit#(MW) repBoundBits = tf.repBoundBits;
  Bit#(MW) toBounds_B   = repBoundBits - cap.addrBits;
  Bit#(MW) toBoundsM1_B = repBoundBits + ~cap.addrBits;
  // Select the appropriate toBounds value
  Bit#(MW) toBounds   = setOffset ? toBounds_A   : toBounds_B;
  Bit#(MW) toBoundsM1 = setOffset ? toBoundsM1_A : toBoundsM1_B;
  Bool addrAtRepBound = !setOffset && (repBoundBits == cap.addrBits);

  // Implement the inLimit test
  Bool inLimits = False;
  if (posInc) begin
    // For a positive or null increment
    // SetOffset is offsetting against base, which has 0 in the lower bits, so
    // we don't need to be conservative.
    inLimits = setOffset ? offsetBits <= toBoundsM1
                         : offsetBits <  toBoundsM1;
  end else begin
    // For a negative increment
    inLimits = (offsetBits >= toBounds) && !addrAtRepBound;
  end

  // Complete representable bounds check
  // -----------------------------------
  Bool inBounds = (inRange && inLimits) || (e >= (resetExp - 2));

  // Updating the return capability
  // ------------------------------
  if (setOffset) begin
    // Get the base and add the offsetAddr. This could be slow, but seems to
    // pass timing.
    ret.address = getBotFat(cap,tf) + offsetAddr;
    // Work out the slice of the address we are interested in using MW-bit
    // arithmetics.
    Bit#(MW) newAddrBits = cap.bounds.baseBits + offsetBits;
    // Ensure the bits of the address slice past the top of the address space
    // are zero
    Bit#(2) mask = (e == resetExp) ? 2'b00 : (e == resetExp-1) ? 2'b01 : 2'b11;
    ret.addrBits = {mask, ~0} & newAddrBits;
  end else begin
    // In the incOffset case, the 'pointer' argument already contains the new
    // address
    ret.address  = pointer;
    ret.addrBits = truncate(ret.address >> e);
  end
  // Nullify the capability if the representable bounds check has failed
  if (!inBounds) ret.isCapability = False;

  // return updated / invalid capability
  return VnD {v: inBounds, d: ret};
endfunction
function VnD#(CapFat) setAddress(CapFat cap, CapAddr address, TempFields tf);
  CapFat ret = setCapPointer(cap, address);
  Exp e = cap.bounds.exp;
  // Calculate what the difference in the upper bits of the new and original addresses must be if
  // the new address is within representable bounds.
  Bool newAddrHi  = ret.addrBits < tf.repBoundBits;
  Bit#(TSub#(CapAddrW,MW)) deltaAddrHi = signExtend({1'b0,pack(newAddrHi)} - {1'b0,pack(tf.addrHi)}) << e;
  // Calculate the actual difference between the upper bits of the new address and the original address.
  Bit#(TSub#(CapAddrW,MW)) mask = -1 << e;
  Bit#(TSub#(CapAddrW,MW)) deltaAddrUpper = (truncateLSB(address)&mask) - (truncateLSB(cap.address)&mask);
  Bool inRepBounds = deltaAddrHi == deltaAddrUpper;
  if (!inRepBounds) ret.isCapability = False;
  return VnD {v: inRepBounds, d: ret};
endfunction

///////////////////////////////
// Internal types and values //
////////////////////////////////////////////////////////////////////////////////

// Exponent that pushes the implied +1 of the top 1 bit outside the address space
Exp resetExp = fromInteger(valueOf(TSub#(TAdd#(CapAddrW,2),MW)));

Bit#(MW) resetTop = {2'b01,0};
typedef struct {
  Exp exp;
  Bit#(MW) topBits;
  Bit#(MW) baseBits;
} Bounds deriving (Bits, Eq, FShow);
instance DefaultValue #(Bounds);
  defaultValue = Bounds {
      exp     : resetExp
    , topBits : resetTop
    , baseBits: 0 };
endinstance
instance DefaultValue #(CapFat);
  defaultValue = CapFat {
      isCapability: True
    , perms       : unpack(~0)
    , reserved_hi : 0
    , reserved_lo : 0
    , sealed      : False
    , format      : EmbeddedExp
    , bounds      : defaultValue
    , address     : 0
    , addrBits    : 0 };
endinstance

CapFat null_cap = CapFat {
    isCapability: False
  , perms       : unpack(0)
  , reserved_hi : 0
  , reserved_lo : 0
  , sealed      : False
  , format      : EmbeddedExp
  , bounds      : defaultValue
  , address     : 0
  , addrBits    : 0 };

///////////////////////////////////////////////
// CHERI CONCENTRATE, example 128-bit format //
///////////////////////////////////////////////
// In memory representation //
////////////////////////////////////////////////////////////////////////////////
/*
XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
XXX Note that the Flags field does not currently appear in the drawing below
XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX

                    Embedded Exp
127___124_123_112_111_109_108__91__90_89_________________________78_77__________________________64
|        |       |       |       |   |                             |                             |
| uperms | perms |  res  | otype | 0 |                    top<11:0>|                   base<13:0>| Exp0
| uperms | perms |  res  |       | 1 |             top<11:3>|e<5:3>|            base<13:3>|e<2:0>| EmbeddedExp
|________|_______|_______|_______|___|_____________________________|_____________________________|
63_______________________________________________________________________________________________0
|                                                                                                |
|                                      address                                                   |
|________________________________________________________________________________________________|

reconstructing most significant top bits:
top<20:19> = base<20:19> + carry_out + len_correction
     where
             carry_out      = 1 if top<18:0> < base <18:0>
                              0 otherwise
             len_correction = 0 if Exp0
                              1 otherwise
*/

// These three bounds formats help with the decBounds function.
typedef struct {
  Bool              embeddedExp;
  Bit#(TSub#(MW,2)) top;
  Bit#(MW)          base;
} BoundsExp0 deriving(Bits, Eq, FShow);

typedef struct {
  Bool                              embeddedExp;
  Bit#(TSub#(MW,TAdd#(HalfExpW,2))) topUpperBits;
  Bit#(HalfExpW)                    expTopHalf;
  Bit#(TSub#(MW,HalfExpW))          baseUpperBits;
  Bit#(HalfExpW)                    expBotHalf;
} BoundsEmbeddedExp deriving(Bits, Eq, FShow);

function Tuple2#(Format, Bounds) decBounds (CBounds raw);
  Bool embeddedExp = (truncateLSB(raw)==1'b1);
  Format format    = (embeddedExp) ? EmbeddedExp : Exp0;
  Bounds bounds    = defaultValue;
  //bounds.exp      = 0;
  //bounds.topBits  = 0;
  //bounds.baseBits = 0;
  Bit#(HalfExpW) halfExp0 = 0;

  case (format)
    EmbeddedExp: begin
      BoundsEmbeddedExp b = unpack(raw);
      bounds.exp          = unpack({b.expTopHalf,b.expBotHalf});
      bounds.topBits      = {?,b.topUpperBits,halfExp0}; // will supply the top
                                                         // two bits later.
      bounds.baseBits     = {b.baseUpperBits,halfExp0};
    end
    default: begin // and Exp0
      bounds.exp      = 0;
      BoundsExp0 b    = unpack(raw);
      bounds.topBits  = {?,b.top}; // will supply the top two bits later.
      bounds.baseBits = b.base;
    end
  endcase
  // topBits = baseBits + lengthBits.
  // lengthBits is not present here, but the MSB of lengthBits can be implied
  // to be 1.
  // To calculate the upper bits of of top, we need the oritinal carry out from
  // the lower bits of base + length, which we find like so:
  Bit#(TSub#(MW,2)) topBits  = truncate(bounds.topBits);
  Bit#(TSub#(MW,2)) baseBits = truncate(bounds.baseBits);
  Bit#(2) carry_out = (topBits < baseBits) ? 2'b01 : 2'b00;
  Bit#(2) len_correction = case (format)
                             Exp0: 2'b00;
                             default: 2'b01;
                           endcase;
  Bit#(2) impliedTopBits = truncateLSB(bounds.baseBits) + carry_out + len_correction;
  bounds.topBits = {impliedTopBits,truncate(bounds.topBits)};
  return tuple2(format,bounds);
endfunction

function CBounds encBounds (Format format, Bounds bounds);
  Bit#(HalfExpW) hiExpBits = truncateLSB(pack(bounds.exp));
  Bit#(HalfExpW) loExpBits = truncate(pack(bounds.exp));

  Bit#(TSub#(MW,TAdd#(HalfExpW,2))) eExpTop = truncate(bounds.topBits >> valueOf(HalfExpW));
  Bit#(TSub#(MW,HalfExpW))         eExpBase = truncateLSB(bounds.baseBits);

  return case (format)
           Exp0: {1'b0, truncate(bounds.topBits), bounds.baseBits};
           EmbeddedExp: {1'b1, eExpTop, hiExpBits, eExpBase, loExpBits};
         endcase;
endfunction

typedef struct {
  Bit#(MW) repBoundBits;
  Bool    topHi;
  Bool    baseHi;
  Bool    addrHi;
  Int#(2) topCorrection;
  Int#(2) baseCorrection;
} MetaInfo deriving(Bits, Eq, FShow);

function MetaInfo getMetaInfo (CapFat cap);
  Bit#(MW) repBound = cap.bounds.baseBits - {3'b010, 0};
  Bool topHi  = cap.bounds.topBits < repBound;
  Bool baseHi = cap.bounds.baseBits < repBound;
  Bool addrHi = cap.addrBits < repBound;
  Int#(2) topCorrection  = (topHi  ==  addrHi) ? 0 :
                           (topHi  && !addrHi) ? 1 :
                                                -1;
  Int#(2) baseCorrection = (baseHi ==  addrHi) ? 0 :
                           (baseHi && !addrHi) ? 1 :
                                                -1;
  return MetaInfo {
      repBoundBits: repBound
    , topHi          : topHi
    , baseHi         : baseHi
    , addrHi         : addrHi
    , topCorrection  : topCorrection
    , baseCorrection : baseCorrection };
endfunction

// XXX TODO
// to avoid an orphan instance here, we should make CapMem a "newtype",
// basically:
// typedef struct {
//   Bit #(TAdd #(1, CapW)) cap;
// } CapMem;
typedef Bit #(TAdd #(1, CapW)) CapMem;

typedef CapFat CapReg;

typedef struct {
  CapFat capFat;
  TempFields tempFields;
} CapPipe deriving (Bits);

// CapMem CHERICap instance
////////////////////////////////////////////////////////////////////////////////
// Note: commented out methods have a provided default implementation in the
//       CHERICap typeclass definition

instance CHERICap #(CapMem, CapAddrW, CapW, 0);

  // capability validity
  //////////////////////////////////////////////////////////////////////////////
  function isValidCap (capMem);
    CapabilityInMemory cap = unpack (capMem);
    return cap.isCapability;
  endfunction
  function setValidCap (capMem, v);
    CapabilityInMemory cap = unpack (capMem);
    cap.isCapability = v;
    return pack (cap);
  endfunction

  // capability flags
  //////////////////////////////////////////////////////////////////////////////
  function getIntMode (capMem);
    CapabilityInMemory cap = unpack (capMem);
    return getPerms(cap).intMode;
  endfunction
  function setIntMode (capMem, im);
    CapabilityInMemory cap = unpack (capMem);
    cap.perms.intMode = im; // XXX Only works for CAP128 currently...
    return pack (cap);
  endfunction

  // capability permissions
  //////////////////////////////////////////////////////////////////////////////
  function getHardPerms (capMem);
    CapabilityInMemory cap = unpack (capMem);
`ifdef CAP64
    HPerms hperms = compressedHPermsToHPerms(cap.perms);
`else
    HPerms hperms = cap.perms.hard;
`endif
    return HardPerms {
        accessSysRegs:        hperms.access_sys_regs
      , permitLoadMutable:    hperms.permit_load_mutable
      , permitLoadEphemeral:  hperms.permit_load_ephemeral
      , permitCap:            hperms.permit_cap
      , permitStore:          hperms.permit_store
      , permitLoad:           hperms.permit_load
      , permitExecute:        hperms.permit_execute
      , permissionStoreLevel: hperms.permission_store_level
    };
  endfunction
  function setHardPerms = error ("setHardPerms not implemented for CapMem");
  function getSoftPerms = error ("getSoftPerms not implemented for CapMem");
  function setSoftPerms = error ("setSoftPerms not implemented for CapMem");
  //function getPerms = error ("getPerms not implemented for CapMem");
  //function setPerms = error ("setPerms not implemented for CapMem");

  // capability kind
  //////////////////////////////////////////////////////////////////////////////
  function getKind = error ("getKind not implemented for CapMem");
  function setKind = error ("setKind not implemented for CapMem");
  function validAsType (dummy, checkType) = True; // No otypes, so dummy function.

  // capability in-memory architectural representation
  //////////////////////////////////////////////////////////////////////////////
  function getMeta (capMem);
    CapabilityInMemory cap = unpack (capMem);
    return { pack (cap.perms)
           , pack (cap.reserved)
           , pack (cap.flags)
           , pack (cap.otype)
           , pack (cap.bounds) };
  endfunction
  function getAddr (capMem);
    CapabilityInMemory cap = unpack (capMem);
    return pack (cap.address);
  endfunction
  function fromMem(x) = unpack(pack(x));
  function toMem(x) = unpack(pack(x));

  // capability address/offset manipulation
  //////////////////////////////////////////////////////////////////////////////
  function setAddr = error ("setAddr not implemented for CapMem");
  function setAddrUnsafe (capMem, address);
    CapabilityInMemory cap = unpack (capMem);
    cap.address = address;
    return pack (cap);
  endfunction
  function addAddrUnsafe (capMem, inc) =
    setAddrUnsafe (capMem, getAddr (capMem) + signExtend (inc));
  function maskAddr = error ("maskAddr not implemented for CapMem");
  //function getOffset = error ("getOffset not implemented for CapMem");
  function modifyOffset = error ("modifyOffset not implemented for CapMem");
  //function setOffset = error ("setOffset not implemented for CapMem");
  //function incOffset = error ("incOffset not implemented for CapMem");

  // capability architectural bounds queries
  //////////////////////////////////////////////////////////////////////////////
  function getBoundsInfo = error ("getBoundsInfo not implemented for CapMem");
  //function getBase = error ("getBase not implemented for CapMem");
  //function getTop = error ("getTop not implemented for CapMem");
  //function getLength = error ("getLength not implemented for CapMem");
  //function isInBounds = error ("isInBounds not implemented for CapMem");
  //function getRepBase = error ("getRepBase not implemented for CapMem");
  //function getRepTop = error ("getRepTop not implemented for CapMem");
  //function getRepLength = error ("getRepLength not implemented for CapMem");
  //function isInRepBounds = error ("isInRepBounds not implemented for CapMem");
  function getBaseAlignment =
    error ("getBaseAlignment not implemented for CapMem");

  // capability derivation (bounds set)
  //////////////////////////////////////////////////////////////////////////////
  function setBoundsCombined =
    error ("setBoundsCombined not implemented for CapMem");
  //function setBounds = error ("setBounds not implemented for CapMem");
  //function roundLength = error ("roundLength not implemented for CapMem");
  //function alignmentMask = error ("alignmentMask not implemented for CapMem");

  // common capabilities
  //////////////////////////////////////////////////////////////////////////////
  //function nullCap = error ("nullCap not implemented for CapMem");
  function nullWithAddr = setAddrUnsafe (packCap (null_cap));
  function almightyCap;
    CapReg res = almightyCap;
    return cast (res);
  endfunction
  function nullCapFromDummy (dummy) = packCap (null_cap);

  // Assert that the encoding is valid
  //////////////////////////////////////////////////////////////////////////////
  function isDerivable = error ("isDerivable not implemented for CapMem");

endinstance

instance FShow #(CapPipe);
  function fshow(cap) = $format(
                        "v: ", fshow(isValidCap(cap)),
                        " a: ", fshow(getAddr(cap)),
                        " o: ", fshow(getOffset(cap)),
                        " b: ", fshow(getBase(cap)),
                        " t: ", fshow(getTop(cap)),
                        " sp: ", fshow(pack(getSoftPerms(cap))),
                        " hp: ", fshow(pack(getHardPerms(cap))),
                        " s: ", fshow(cap.capFat.sealed),
                        " m: ", fshow(getIntMode(cap)));
endinstance

instance Eq #(CapPipe);
  function Bool \== (CapPipe x, CapPipe y) = toMem(x) == toMem(y);
//  function Bool \/= (CapPipe x, CapPipe y);
endinstance
instance Eq #(CapReg);
  function Bool \== (CapReg x, CapReg y) = toMem(x) == toMem(y);
//  function Bool \/= (CapPipe x, CapPipe y);
endinstance

// CapReg CHERICap instance
////////////////////////////////////////////////////////////////////////////////
// Note: commented out methods have a provided default implementation in the
//       CHERICap typeclass definition

instance CHERICap #(CapReg, CapAddrW, CapW, 0);

  // capability validity
  //////////////////////////////////////////////////////////////////////////////
  function isValidCap (x) = x.isCapability;
  function setValidCap (cap, tag);
    cap.isCapability = tag;
    return cap;
  endfunction

  // capability flags
  //////////////////////////////////////////////////////////////////////////////
  function getIntMode (cap) =
`ifdef CAP64
    compressedHPermsToIntMode(cap.perms);
`else
    cap.perms.intMode;
`endif

  function setIntMode (cap, im);
`ifdef CAP64
    error("cap64 not complete yet"); // XXX not implemented yet.  Needs legalisation.
`else
    cap.perms.intMode = im;
`endif
    return cap;
  endfunction

  // capability permissions
  //////////////////////////////////////////////////////////////////////////////
  function getHardPerms (cap) = HardPerms {
      accessSysRegs:        cap.perms.hard.access_sys_regs
    , permitLoadMutable:    cap.perms.hard.permit_load_mutable
    , permitLoadEphemeral:  cap.perms.hard.permit_load_ephemeral
    , permitCap:            cap.perms.hard.permit_cap
    , permitStore:          cap.perms.hard.permit_store
    , permitLoad:           cap.perms.hard.permit_load
    , permitExecute:        cap.perms.hard.permit_execute
    , permissionStoreLevel: cap.perms.hard.permission_store_level
  };
  function setHardPerms (cap, perms);
    cap.perms.hard = HPerms {
        access_sys_regs:            perms.accessSysRegs
      , permit_load_mutable:        perms.permitLoadMutable
      , permit_load_ephemeral:      perms.permitLoadEphemeral
      , permit_cap:                 perms.permitCap
      , permit_store:               perms.permitStore
      , permit_load:                perms.permitLoad
      , permit_execute:             perms.permitExecute
      , permission_store_level:     perms.permissionStoreLevel
    };
    return cap;
  endfunction
  function getSoftPerms (cap) = zeroExtend (cap.perms.soft);
  function setSoftPerms (cap, perms);
    cap.perms.soft = truncate (perms);
    return cap;
  endfunction
  //function getPerms = error ("getPerms not implemented for CapReg");
  //function setPerms = error ("setPerms not implemented for CapReg");

  // capability kind
  //////////////////////////////////////////////////////////////////////////////
  function getKind (cap) = (cap.sealed) ? SENTRY:UNSEALED;

  function setKind (cap, kind) = case (kind)
    UNSEALED: unseal (cap);
    SENTRY:   seal (cap);
  endcase;
  function validAsType (dummy, checkType);
    CapMem nullC = nullCap;
    return validAsType (nullC, checkType);
  endfunction

  // capability in-memory architectural representation
  //////////////////////////////////////////////////////////////////////////////
  function getMeta (capReg);
    CapMem cap = unpack (pack (toMem (capReg)));
    return getMeta (cap);
  endfunction
  function getAddr (capReg);
    CapMem cap = unpack (pack (toMem (capReg)));
    return getAddr (cap);
  endfunction
  function fromMem (x) = cast (pack (x));
  function toMem (x) = unpack (cast (x));

  // capability address/offset manipulation
  //////////////////////////////////////////////////////////////////////////////
  function setAddr = error ("setAddr not implemented for CapReg");
  function setAddrUnsafe (cap, address) = setCapPointer (cap, address);
  function addAddrUnsafe (cap, inc) =
    setAddrUnsafe (cap, getAddr (cap) + signExtend (inc));
  function maskAddr (cap, mask) = setCapPointer (cap, cap.address & {~0, mask});
  function getOffset = error ("getOffset not implemented for CapReg");
  function modifyOffset = error ("modifyOffset not implemented for CapReg");
  //function setOffset = error ("setOffset not implemented for CapReg");
  //function incOffset = error ("incOffset not implemented for CapReg");

  // capability architectural bounds queries
  //////////////////////////////////////////////////////////////////////////////
  function getBoundsInfo = error ("getBoundsInfo not implemented for CapReg");
  //function getBase = error ("getBase not implemented for CapReg");
  //function getTop = error ("getTop not implemented for CapReg");
  //function getLength = error ("getLength not implemented for CapReg");
  //function isInBounds = error ("isInBounds not implemented for CapReg");
  //function getRepBase = error ("getRepBase not implemented for CapReg");
  //function getRepTop = error ("getRepTop not implemented for CapReg");
  //function getRepLength = error ("getRepLength not implemented for CapReg");
  //function isInRepBounds = error ("isInRepBounds not implemented for CapReg");
  function getBaseAlignment (cap) =
    // If cap exp is non-zero, we have internal exponent, so the least
    // significant two bits of the base are implicitly zero.  Otherwise, we
    // have a zero exponent, so the least significant two bits of the base are
    // the least significant bits of the encoded base
    (cap.bounds.exp == 0) ? cap.bounds.baseBits[1:0] : 2'b0;

  // capability derivation (bounds set)
  //////////////////////////////////////////////////////////////////////////////
  function setBoundsCombined (cap, length) = error ("setBoundsCombined not implemented for CapReg");
  //function setBounds = error ("setBounds not implemented for CapReg");
  //function roundLength = error ("roundLength not implemented for CapReg");
  //function alignmentMask = error ("alignmentMask not implemented for CapReg");

  // common capabilities
  //////////////////////////////////////////////////////////////////////////////
  //function nullCap = error ("nullCap not implemented for CapReg");
  function nullWithAddr (addr) = setAddrUnsafe (null_cap, addr);
  function almightyCap = defaultCapFat;
  function nullCapFromDummy (x) = null_cap;

  // Assert that the encoding is valid
  //////////////////////////////////////////////////////////////////////////////
  function isDerivable (cap) =
        (cap.bounds.exp <= resetExp)
    && !(   (cap.bounds.exp == resetExp)
         && (   (truncateLSB (cap.bounds.topBits)  != 1'b0)
             || (truncateLSB (cap.bounds.baseBits) != 2'b0) ))
    && !(   (cap.bounds.exp == resetExp-1)
         && (truncateLSB (cap.bounds.baseBits) != 1'b0))
    &&  (cap.reserved == 0);

endinstance

instance CHERICap #(CapPipe, CapAddrW, CapW, 0);

  //Functions supported by CapReg are just passed through

  function isValidCap (x) = isValidCap(x.capFat);
  function setValidCap (cap, tag) =
    CapPipe { capFat: setValidCap(cap.capFat, tag)
            , tempFields: cap.tempFields };
  function getIntMode (cap) = getIntMode(cap.capFat);
  function setIntMode (cap, flags) =
    CapPipe { capFat: setIntMode(cap.capFat, flags)
            , tempFields: cap.tempFields };
  function getHardPerms (cap) = getHardPerms(cap.capFat);
  function setHardPerms (cap, perms) =
    CapPipe { capFat: setHardPerms(cap.capFat, perms)
            , tempFields: cap.tempFields };
  function getSoftPerms (cap) = getSoftPerms(cap.capFat);
  function setSoftPerms (cap, perms) =
    CapPipe { capFat: setSoftPerms(cap.capFat, perms)
            , tempFields: cap.tempFields };
  function getKind (cap) = getKind(cap.capFat);
  function setKind (cap, kind) =
    CapPipe { capFat:setKind(cap.capFat,kind)
            , tempFields: cap.tempFields };

  function getMeta (cap) = getMeta (cap.capFat);
  function getAddr (cap) = getAddr (cap.capFat);
  function maskAddr (cap, mask) =
    CapPipe { capFat: maskAddr(cap.capFat, mask)
            , tempFields: cap.tempFields };
  function validAsType (dummy, checkType) =
    validAsType(dummy.capFat, checkType);
  function toMem (cap) = toMem(cap.capFat);
  function getBaseAlignment (cap) = getBaseAlignment(cap.capFat);

  //Functions supported by CapReg but which require TempFields to be changed

  function setBoundsCombined (cap, length);
    let result = setBoundsFat(cap.capFat, length, cap.tempFields);
    return SetBoundsReturn {
        cap: CapPipe { capFat: result.cap
                     , tempFields: getTempFields(result.cap) }
      , exact: result.exact
      , inBounds: result.inBounds
      , length: result.length
      , mask: result.mask };
  endfunction

  function nullWithAddr (addr);
    CapReg res = nullWithAddr(addr);
    return CapPipe { capFat: res, tempFields: getTempFields(res) };
  endfunction

  function fromMem (capBits);
    CapReg res = fromMem(capBits);
    return CapPipe { capFat: res, tempFields: getTempFields(res) };
  endfunction

  function almightyCap;
    CapReg res = almightyCap;
    return CapPipe { capFat: res, tempFields: getTempFields(res) };
  endfunction

  function nullCapFromDummy (x);
    CapReg res = nullCap;
    return CapPipe { capFat: res, tempFields: getTempFields(res) };
  endfunction

  //Functions that require TempFields

  function setAddr (cap, address);
    let result = setAddress(cap.capFat, address, cap.tempFields);
    cap.capFat = result.d;
    cap.tempFields = getTempFields(cap.capFat);
    return Exact { exact: result.v, value: cap };
  endfunction

  function setAddrUnsafe (cap, address);
    cap.capFat = setAddrUnsafe(cap.capFat, address);
    cap.tempFields = getTempFields(cap.capFat);
    return cap;
  endfunction

  function addAddrUnsafe (cap, inc) =
    setAddrUnsafe(cap, getAddr(cap) + signExtend(inc));

  function getOffset (x) = getOffsetFat(x.capFat, x.tempFields);

  function modifyOffset (cap, offset, doInc);
    let result = incOffsetFat( cap.capFat
                             , cap.capFat.address + offset
                             , offset
                             , cap.tempFields
                             , !doInc);
    cap.capFat = result.d;
    cap.tempFields = getTempFields(cap.capFat);
    return Exact { exact: result.v, value: cap };
  endfunction

  function getBoundsInfo (cap) = getBoundsInfoFat (cap.capFat, cap.tempFields);

  function getBase (cap) = getBotFat(cap.capFat, cap.tempFields);

  function getTop (cap) = getTopFat(cap.capFat, cap.tempFields);

  function getLength (cap) = getLengthFat(cap.capFat, cap.tempFields);

  function isInBounds (cap, inclusive) =
    capInBounds(cap.capFat, cap.tempFields, inclusive);

  function isDerivable (cap) = isDerivable(cap.capFat);

endinstance

instance Cast#(CapMem, CapReg);
  function CapReg cast (CapMem thin) = unpackCap(thin ^ packCap(null_cap));
endinstance

instance Cast#(CapReg, CapMem);
  function CapMem cast (CapReg fat) = packCap(fat) ^ packCap(null_cap);
endinstance

instance Cast#(CapReg, CapPipe);
  function CapPipe cast (CapReg thin) =
    CapPipe { capFat: thin
            , tempFields: getTempFields(thin) };
endinstance

instance Cast#(CapPipe, CapReg);
  function CapReg cast (CapPipe fat) = fat.capFat;
endinstance

instance Cast#(CapMem, CapPipe);
  function CapPipe cast (CapMem thin);
    CapReg cr = cast(thin);
    return cast(cr);
  endfunction
endinstance

instance Cast#(CapPipe, CapMem);
  function CapMem cast (CapPipe fat);
    CapReg cr = cast(fat);
    return cast(cr);
  endfunction
endinstance

instance Cast#(function CapReg f0(t x), function CapPipe f1(t y));
  function cast(f0);
    function CapPipe f1(t arg) = cast(f0(arg));
    return f1;
  endfunction
endinstance

instance Cast#(function CapPipe f0(t y), function Bit#(CapAddrW) f1(t x));
  function cast(f0);
    function Bit#(CapAddrW) f1(t arg) = getAddr(f0(arg));
    return f1;
  endfunction
endinstance

`ifdef CAP64
// XXX TODO
// This is probably the wrong fix but allows the code to compile, and the
// code for CAP64 is not used anywhere.
// Need to consider what the right size is.
typedef 31 VA_Width;
`else
typedef 48 VA_Width;
`endif
// Type and function to trim unnecessary fields of a capability that is known to
// be unsealed with the tag set (e.g. PCC)
typedef struct {
  Perms        perms;
  CBounds      bounds;
  Bit#(VA_Width)     address;
  Bool         validAddress;
} CapTrim deriving(Bits, Eq, FShow);
function CapTrim  trimCap(CapMem cm);
  CapabilityInMemory cap = unpack(cm);
  Bit#(TSub#(CapAddrW,VA_Width)) addr_upper = truncateLSB(cap.address);
  return CapTrim{perms: cap.perms,
                 flags: cap.flags,
                 bounds: cap.bounds,
                 address: truncate(cap.address),
                 validAddress: (addr_upper==signExtend(cap.address[valueOf(VA_Width)-1]))
  };
endfunction
function CapMem untrimCap(CapTrim ct);
  // Encode an invalid address as the bit above the last valid bit being different.
  Bit#(1) addressMsb = ct.address[valueOf(VA_Width)-1];
  if (!ct.validAddress) addressMsb = ^addressMsb;
  return pack(CapabilityInMemory{
                isCapability: True,
                perms: ct.perms,
                reserved: 0,
                flags: ct.flags,
                otype: otype_unsealed,
                bounds: ct.bounds,
                address: signExtend({addressMsb,ct.address})
  });
endfunction

endpackage
