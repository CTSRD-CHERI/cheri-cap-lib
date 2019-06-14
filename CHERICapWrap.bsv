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

///////////////////
// Helper Macros //
////////////////////////////////////////////////////////////////////////////////

`define newCapPipe (x)\
CapPipe newCap = cast(x);

`define retExactCap (x)\
return Exact {\
  exact: tmp.exact,\
  value: cast(tmp.value)\
};

// defWrap...<N>_<M> :
// N number of type parameters
// M number of arguments

`define defWrapIfc_1_1 (name, param_t, ret_t, arg_t)\
interface Wrap_``name#(type param_t);\
  (* always_ready *) method ret_t name (arg_t arg1);\
endinterface
`define defWrapIfc_1_2 (name, param_t, ret_t, arg1_t, arg2_t)\
interface Wrap_``name#(type param_t);\
  (* always_ready *) method ret_t name (arg1_t arg1, arg2_t arg2);\
endinterface
`define defWrapIfc_2_1 (name, param1_t, param2_t, ret_t, arg_t)\
interface Wrap_``name#(type param1_t, type param2_t);\
  (* always_ready *) method ret_t name (arg_t arg);\
endinterface
`define defWrapIfc_2_2 (name, param1_t, param2_t, ret_t, arg1_t, arg2_t)\
interface Wrap_``name#(type param1_t, type param2_t);\
  (* always_ready *) method ret_t name (arg1_t arg1, arg2_t arg2);\
endinterface
`define defPipeWrap_1_1 (name, param_t)\
(* synthesize *)\
module wrap_``name (Wrap_``name#(param_t));\
  method name(cap);\
    `newCapPipe(cap)\
    return name(newCap);\
  endmethod\
endmodule
`define defPipeWrap_1_2 (name, param_t)\
(* synthesize *)\
module wrap_``name (Wrap_``name#(param_t));\
  method name(cap, val);\
    `newCapPipe(cap)\
    return cast(name(newCap, val));\
  endmethod\
endmodule
`define defPipeWrap_2_1 (name, param1_t, param2_t)\
(* synthesize *)\
module wrap_``name (Wrap_``name#(param1_t, param2_t));\
  method name(cap);\
    `newCapPipe(cap)\
    return cast(name(newCap));\
  endmethod\
endmodule
`define defPipeWrap_2_2 (name, param1_t, param2_t)\
(* synthesize *)\
module wrap_``name (Wrap_``name#(param1_t, param2_t));\
  method name(cap, val);\
    `newCapPipe(cap)\
    return cast(name(newCap, val));\
  endmethod\
endmodule
`define defExactPipeWrap_2_2 (name, param1_t, param2_t)\
(* synthesize *)\
module wrap_``name (Wrap_``name#(param1_t, param2_t));\
  method name(cap, val);\
    `newCapPipe(cap)\
    let tmp = name(newCap, val);\
    `retExactCap(tmp)\
  endmethod\
endmodule

//////////////////////////////////////////
// definitions for individual functions //
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_2(setBounds, cap_t, n, Exact#(cap_t), cap_t, Bit#(n))
`defExactPipeWrap_2_2(setBounds, CapMem, CapAddressW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_1(isValidCap, cap_t, Bool, cap_t)
`defPipeWrap_1_1(isValidCap, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_2(setValidCap, cap_t, cap_t, cap_t, Bool)
`defPipeWrap_1_2(setValidCap, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_1(getFlags, cap_t, flg, Bit#(flg), cap_t)
`defPipeWrap_2_1(getFlags, CapMem, FlagsW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_2(setFlags, cap_t, flg, cap_t, cap_t, Bit#(flg))
`defPipeWrap_2_2(setFlags, CapMem, FlagsW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_1(getHardPerms, cap_t, HardPerms, cap_t)
`defPipeWrap_1_1(getHardPerms, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_2(setHardPerms, cap_t, cap_t, cap_t, HardPerms)
`defPipeWrap_1_2(setHardPerms, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_1(getSoftPerms, cap_t, SoftPerms, cap_t)
`defPipeWrap_1_1(getSoftPerms, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_2(setSoftPerms, cap_t, cap_t, cap_t, SoftPerms)
`defPipeWrap_1_2(setSoftPerms, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_1(getPerms, cap_t, Bit#(31), cap_t)
`defPipeWrap_1_1(getPerms, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_2(setPerms, cap_t, cap_t, cap_t, Bit#(31))
`defPipeWrap_1_2(setPerms, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_1(getKind, cap_t, Kind, cap_t)
`defPipeWrap_1_1(getKind, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_1(getType, cap_t, ot, Bit#(ot), cap_t)
`defPipeWrap_2_1(getType, CapMem, OTypeW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_2(setType, cap_t, ot, Exact#(cap_t), cap_t, Bit#(ot))
`defExactPipeWrap_2_2(setType, CapMem, OTypeW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_1(getAddr, cap_t, n, Bit#(n), cap_t)
`defPipeWrap_2_1(getAddr, CapMem, CapAddressW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_2(setAddr, cap_t, n, Exact#(cap_t), cap_t, Bit#(n))
`defExactPipeWrap_2_2(setAddr, CapMem, CapAddressW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_1(getOffset, cap_t, n, Bit#(n), cap_t)
`defPipeWrap_2_1(getOffset, CapMem, CapAddressW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_2(setOffset, cap_t, n, Exact#(cap_t), cap_t, Bit#(n))
`defExactPipeWrap_2_2(setOffset, CapMem, CapAddressW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_1(getBase, cap_t, n, Bit#(n), cap_t)
`defPipeWrap_2_1(getBase, CapMem, CapAddressW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_1(getTop, cap_t, n, Bit#(TAdd#(n, 1)), cap_t)
`defPipeWrap_2_1(getTop, CapMem, CapAddressW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_2_1(getLength, cap_t, n, Bit#(TAdd#(n, 1)), cap_t)
`defPipeWrap_2_1(getLength, CapMem, CapAddressW)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_2(isInBounds, cap_t, Bool, cap_t, Bool)
`defPipeWrap_1_2(isInBounds, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_1(isSentry, cap_t, Bool, cap_t)
`defPipeWrap_1_1(isSentry, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_1(isSealedWithType, cap_t, Bool, cap_t)
`defPipeWrap_1_1(isSealedWithType, CapMem)
////////////////////////////////////////////////////////////////////////////////
`defWrapIfc_1_1(isSealed, cap_t, Bool, cap_t)
`defPipeWrap_1_1(isSealed, CapMem)
////////////////////////////////////////////////////////////////////////////////

endpackage
