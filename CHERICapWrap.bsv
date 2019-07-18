/*
 * Copyright (c) 2019 Alexandre Joannou
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

package CHERICapWrap;

import CHERICap :: *;
import CHERICC_Fat :: *;

`define CAPTYPE CapPipe
`define W(name)\
`ifndef CAP64\
wrap128_``name\
`else\
wrap64_``name\
`endif

(* noinline *)
function Bool `W(isValidCap) (`CAPTYPE cap) = isValidCap(cap);
(* noinline *)
function `CAPTYPE `W(setValidCap) (`CAPTYPE cap, Bool valid) = setValidCap(cap, valid);
(* noinline *)
function Bit#(FlagsW) `W(getFlags) (`CAPTYPE cap) = getFlags(cap);
(* noinline *)
function `CAPTYPE `W(setFlags) (`CAPTYPE cap, Bit#(FlagsW) flags) = setFlags(cap,flags);
(* noinline *)
function HardPerms `W(getHardPerms) (`CAPTYPE cap) = getHardPerms(cap);
(* noinline *)
function `CAPTYPE `W(setHardPerms) (`CAPTYPE cap, HardPerms hardperms) = setHardPerms(cap, hardperms);
(* noinline *)
function SoftPerms `W(getSoftPerms) (`CAPTYPE cap) = getSoftPerms(cap);
(* noinline *)
function `CAPTYPE `W(setSoftPerms) (`CAPTYPE cap, SoftPerms softperms) = setSoftPerms(cap, softperms);
(* noinline *)
function Bit#(31) `W(getPerms) (`CAPTYPE cap) = getPerms(cap);
(* noinline *)
function `CAPTYPE `W(setPerms) (`CAPTYPE cap, Bit#(31) perms) = setPerms(cap, perms);
(* noinline *)
function Kind `W(getKind) (`CAPTYPE cap) = getKind(cap);
(* noinline *)
function Bool `W(isSentry) (`CAPTYPE cap) = isSentry(cap);
(* noinline *)
function Bool `W(isSealedWithType) (`CAPTYPE cap) = isSealedWithType(cap);
(* noinline *)
function Bool `W(isSealed) (`CAPTYPE cap) = isSealed(cap);
(* noinline *)
function Bit#(OTypeW) `W(getType) (`CAPTYPE cap) = getType(cap);
(* noinline *)
function Exact#(`CAPTYPE) `W(setType) (`CAPTYPE cap, Bit#(OTypeW) otype) = setType(cap, otype);
(* noinline *)
function Bit#(CapAddressW) `W(getAddr) (`CAPTYPE cap) = getAddr(cap);
(* noinline *)
function Exact#(`CAPTYPE) `W(setAddr) (`CAPTYPE cap, Bit#(CapAddressW) addr) = setAddr(cap, addr);
(* noinline *)
function Bit#(CapAddressW) `W(getOffset) (`CAPTYPE cap) = getOffset(cap);
(* noinline *)
function Exact#(`CAPTYPE) `W(setOffset) (`CAPTYPE cap, Bit#(CapAddressW) offset) = setOffset (cap, offset);
(* noinline *)
function Bit#(CapAddressW) `W(getBase) (`CAPTYPE cap) = getBase(cap);
(* noinline *)
function Bit#(TAdd#(CapAddressW, 1)) `W(getTop) (`CAPTYPE cap) = getTop(cap);
(* noinline *)
function Bit#(TAdd#(CapAddressW, 1)) `W(getLength) (`CAPTYPE cap) = getLength(cap);
(* noinline *)
function Bool `W(isInBounds) (`CAPTYPE cap, Bool isTopIncluded) = isInBounds(cap, isTopIncluded);
(* noinline *)
function Exact#(`CAPTYPE) `W(setBounds) (`CAPTYPE cap, Bit#(CapAddressW) length) = setBounds(cap, length);
(* noinline *)
function `CAPTYPE `W(nullWithAddr) (Bit#(CapAddressW) addr) = nullWithAddr(addr);
(* noinline *)
function `CAPTYPE `W(almightyCap) = almightyCap;
(* noinline *)
function `CAPTYPE `W(nullCap) = nullCap;
(* noinline *)
function Bool `W(validAsType) (`CAPTYPE dummy, Bit#(CapAddressW) checkType) = validAsType(dummy, checkType);
(* noinline *)
function `CAPTYPE `W(fromMem) (Tuple2#(Bool, Bit#(CapW)) mem_cap) = fromMem(mem_cap);
(* noinline *)
function Tuple2#(Bool, Bit#(CapW)) `W(toMem) (`CAPTYPE cap) = toMem(cap);

endpackage
