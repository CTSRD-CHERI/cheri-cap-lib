/*
 * Copyright (c) 2019-2025 Alexandre Joannou
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

`ifndef CAPTYPE
`define CAPTYPE CapPipe
`endif

function CapPipe capArg(`CAPTYPE cap) = cast(cap);
function `CAPTYPE capRet(CapPipe cap) = cast(cap);
function Exact#(`CAPTYPE) capExactRet(Exact#(CapPipe) e_cap) =
  Exact { exact: e_cap.exact, value: cast(e_cap.value) };

`ifndef CAP64
`define W(name) wrap128_``name
`else
`define W(name) wrap64_``name
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
function `CAPTYPE `W(setHardPerms) (`CAPTYPE cap, HardPerms hardperms) = capRet(setHardPerms(capArg(cap), hardperms));
(* noinline *)
function SoftPerms `W(getSoftPerms) (`CAPTYPE cap) = getSoftPerms(capArg(cap));
(* noinline *)
function `CAPTYPE `W(setSoftPerms) (`CAPTYPE cap, SoftPerms softperms) = capRet(setSoftPerms(capArg(cap), softperms));
(* noinline *)
function Bit#(31) `W(getPerms) (`CAPTYPE cap) = getPerms(capArg(cap));
(* noinline *)
function `CAPTYPE `W(setPerms) (`CAPTYPE cap, Bit#(31) perms) = capRet(setPerms(capArg(cap), perms));
(* noinline *)
function Kind#(OTypeW) `W(getKind) (`CAPTYPE cap) = getKind(capArg(cap));
(* noinline *)
function `CAPTYPE `W(setKind) (`CAPTYPE cap, Kind#(OTypeW) kind) = capRet(setKind(capArg(cap), kind));
(* noinline *)
function Bit#(CapAddrW) `W(getAddr) (`CAPTYPE cap) = getAddr(cap);
(* noinline *)
function `CAPTYPE `W(setAddrUnsafe) (`CAPTYPE cap, Bit#(CapAddrW) addr) = capRet(setAddrUnsafe(capArg(cap), addr));
(* noinline *)
function Exact#(`CAPTYPE) `W(setAddr) (`CAPTYPE cap, Bit#(CapAddrW) addr) = capExactRet(setAddr(capArg(cap), addr));
(* noinline *)
function Bit#(CapAddrW) `W(getOffset) (`CAPTYPE cap) = getOffset(capArg(cap));
(* noinline *)
function Exact#(`CAPTYPE) `W(modifyOffset) (`CAPTYPE cap, Bit#(CapAddrW) offset, Bool doInc) = capExactRet(modifyOffset (capArg(cap), offset, doInc));
(* noinline *)
function Exact#(`CAPTYPE) `W(setOffset) (`CAPTYPE cap, Bit#(CapAddrW) offset) = capExactRet(setOffset (capArg(cap), offset));
(* noinline *)
function Exact#(`CAPTYPE) `W(incOffset) (`CAPTYPE cap, Bit#(CapAddrW) inc) = capExactRet(incOffset (capArg(cap), inc));
(* noinline *)
function Bit#(CapAddrW) `W(getBase) (`CAPTYPE cap) = getBase(capArg(cap));
(* noinline *)
function Bit#(TAdd#(CapAddrW, 1)) `W(getTop) (`CAPTYPE cap) = getTop(capArg(cap));
(* noinline *)
function Bit#(CapAddrW) `W(getLength) (`CAPTYPE cap) = getLength(capArg(cap));
(* noinline *)
function Bool `W(isInBounds) (`CAPTYPE cap, Bool isTopIncluded) = isInBounds(capArg(cap), isTopIncluded);
(* noinline *)
function Exact#(`CAPTYPE) `W(setBounds) (`CAPTYPE cap, Bit#(CapAddrW) length) = capExactRet(setBounds(capArg(cap), length));
(* noinline *)
function `CAPTYPE `W(nullWithAddr) (Bit#(CapAddrW) addr) = nullWithAddr(addr);
(* noinline *)
function `CAPTYPE `W(almightyCap) = almightyCap;
(* noinline *)
function `CAPTYPE `W(nullCap) = nullCap;
(* noinline *)
function Bool `W(validAsType) (`CAPTYPE dummy, Bit#(CapAddrW) checkType) = validAsType(dummy, checkType);
(* noinline *)
function `CAPTYPE `W(fromMem) (Tuple2#(Bool, Bit#(CapW)) mem_cap) = fromMem(mem_cap);
(* noinline *)
function Tuple2#(Bool, Bit#(CapW)) `W(toMem) (`CAPTYPE cap) = toMem(cap);
(* noinline *)
function Bit#(CapAddrW) `W(getRepresentableAlignmentMask) (`CAPTYPE dummy, Bit#(CapAddrW) length) = alignmentMask (capArg(dummy), length);
(* noinline *)
function Bit#(CapAddrW) `W(getRepresentableLength) (`CAPTYPE dummy, Bit#(CapAddrW) length) = roundLength (capArg(dummy), length);
(* noinline *)
function Bit#(2) `W(getBaseAlignment) (`CAPTYPE cap) = getBaseAlignment(capArg(cap));
(* noinline *)
function Bool `W(isDerivable) (`CAPTYPE cap) = isDerivable(capArg(cap));



endpackage
