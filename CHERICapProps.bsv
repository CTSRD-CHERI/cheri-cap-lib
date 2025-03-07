/*
 * Copyright (c) 2024 Matthew Naylor
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

package CHERICapProps;

import CHERICap :: *;
import CHERICC_Fat :: *;

// Helpers
// =======

// Bluespec does not seem to provide a boolean implication operator
// (and Bool is not in Ord).

function Bool implies(Bool x, Bool y) = !x || y;

// Enumerating valid capabilities
// ==============================

// We assume that valid capabilities of all possible bounds are reachable
// by calling setBounds on the almighty capability with arbitrary base and
// length, ignoring those calls that return capabilities with inexact
// bounds. (One possible exception is the almighty capability itself.) This
// assumption is justified later.

function Bool forallBaseAndLen(CapAddr base, CapAddr len,
                                 function Bool prop(CapPipe cap));
  Bool ret = ?;
  if (base == 0 && ~len == 0) begin
    ret = prop(almightyCap);
  end else begin
    Exact#(CapPipe) baseCap = setAddr(almightyCap, base);
    Exact#(CapPipe) boundedCap = setBounds(baseCap.value, len);
    ret = baseCap.exact && implies
      ( boundedCap.exact
      , prop(boundedCap.value)
      );
  end
  return ret;
endfunction

// Furthermore, every valid capability can be reached by calling setAddr on
// the result with an arbitrary address. (Only caring about bounds and
// addresses of capabilities here.)

function Bool forallCap(CapAddr base, CapAddr len, CapAddr addr,
                              function Bool prop(CapPipe cap));
  function forall(cap);
    Exact#(CapPipe) arbitraryCap = setAddr(cap, addr);
    return implies(arbitraryCap.exact, prop(arbitraryCap.value));
  endfunction
  return forallBaseAndLen(base, len, forall);
endfunction

// The following two properties help justify the above assumption.

// First, if we call setBounds twice in succession (starting from
// almighty), then we end up with a capability that could have been
// determined with a single setBounds call (also starting from almighty).
// In other words, we can repeatedly shorten chain of setBounds calls to a
// single call starting from almighty.

(* noinline *)
function Bool prop_unique(CapAddr base, CapAddr len,
                          CapAddr newBase, CapAddr newLen);
  Exact#(CapPipe) baseCap = setAddr(almightyCap, base);
  Exact#(CapPipe) boundedCap = setBounds(baseCap.value, len);
  Exact#(CapPipe) newBaseCap = setAddr(boundedCap.value, newBase);
  Exact#(CapPipe) finalCap = setBounds(newBaseCap.value, newLen);
  Exact#(CapPipe) expectedBaseCap = setAddr(almightyCap, newBase);
  Exact#(CapPipe) expectedCap =
    setBounds(expectedBaseCap.value, newLen);
  return baseCap.exact && expectedBaseCap.exact && implies
    ( boundedCap.exact && newBaseCap.exact &&
      finalCap.exact && expectedCap.exact &&
      isValidCap(finalCap.value) &&
      newBase >= base && {1'b0, newBase} + {1'b0, newLen} <=
                         {1'b0, base}    + {1'b0, len}
    , toMem(expectedCap.value) == toMem(finalCap.value)
    );
endfunction

// Second, if setBounds returns a capability with inexact bounds, then
// there exists a different call to setBounds that returns the same
// capability with exact bounds.

(* noinline *)
function Bool prop_exact(CapAddr base, CapAddr len);
  Exact#(CapPipe) baseCap = setAddr(almightyCap, base);
  Exact#(CapPipe) boundedCap = setBounds(baseCap.value, len);
  Exact#(CapPipe) baseCap2 = setAddr(almightyCap, getBase(boundedCap.value));
  CapAddr length = getLength(boundedCap.value);
  Exact#(CapPipe) boundedCap2 = setBounds(baseCap2.value, length);
  return baseCap.exact && baseCap2.exact && implies
           ( ~length != 0
           , boundedCap2.exact
           );
endfunction

// There are certain conditions under which setBounds must return a
// capability with exact bounds.

(* noinline *)
function Bool prop_exactConditions(CapAddr base, CapAddr len);
  SetBoundsReturn#(CapPipe, CapAddrW) sb = setBoundsCombined(nullCap, len);
  Exact#(CapPipe) baseCap = setAddr(almightyCap, base & sb.mask);
  Exact#(CapPipe) boundedCap = setBounds(baseCap.value, sb.length);
  return baseCap.exact && boundedCap.exact;
endfunction

// Properties
// ==========

(* noinline *)
function Bool prop_getBase(CapAddr base, CapAddr len, CapAddr addr);
  function prop(cap) = getBase(cap) == base;
  return forallCap(base, len, addr, prop);
endfunction

(* noinline *)
function Bool prop_getTop(CapAddr base, CapAddr len, CapAddr addr);
  Bool reqAlmighty = ~len == 0;
  function prop(cap) = getTop(cap) == zeroExtend(base) + (reqAlmighty ? {1'b1, 0} : zeroExtend(len));
  return forallCap(base, len, addr, prop);
endfunction

(* noinline *)
function Bool prop_getLength(CapAddr base, CapAddr len, CapAddr addr);
  function prop(cap) = getLength(cap) == zeroExtend(len);
  return forallCap(base, len, addr, prop);
endfunction

(* noinline *)
function Bool prop_setAddr(CapAddr base, CapAddr len, CapAddr addr);
  Integer tolerance = 32; /* How far out-of-bounds can we go in general? */
  function prop(cap);
    Exact#(CapPipe) tmp = setAddr(cap, addr);
    Int#(TAdd#(CapAddrW,2)) addrInt = unpack(zeroExtend(addr));
    Int#(TAdd#(CapAddrW,2)) baseInt = unpack(zeroExtend(base));
    Int#(TAdd#(CapAddrW,2)) lenInt = unpack(zeroExtend(len));
    let low = baseInt - fromInteger(tolerance);
    let high = baseInt + lenInt + fromInteger(tolerance);
    return implies( addrInt >= low && addrInt <= high
                  , tmp.exact && getAddr(tmp.value) == addr );
  endfunction
  return forallBaseAndLen(base, len, prop);
endfunction

(* noinline *)
function Bool prop_isInBounds(CapAddr base, CapAddr len, CapAddr addr);
  function prop(cap);
    // TODO: the nowrap condition is required (but probably should not be)
    Bool nowrap = truncateLSB({1'b0, base} + {1'b0, len}) == 1'b0;
    return implies
             ( nowrap
             , isInBounds(cap, False) ==
                 (getAddr(cap) >= getBase(cap) &&
                    zeroExtend(getAddr(cap)) < getTop(cap))
             );
  endfunction
  return forallCap(base, len, addr, prop);
endfunction

(* noinline *)
function Bool prop_fromToMem(CapMem in);
  CapPipe cp = fromMem(unpack(in));
  CapMem cm = pack(toMem(cp));
  return (cm == in);
endfunction

(* noinline *)
function Bool prop_setBounds(CapAddr base, CapAddr len, CapAddr addr, CapAddr new_len);
  function prop(cap);
    let new_cap = setBounds(cap,new_len).value;
    return implies( isValidCap(new_cap),
                    getBase(cap) <= getBase(new_cap)
                    && getTop(cap) >= getTop(new_cap)
                  );
  endfunction
  return forallCap(base, len, addr, prop);
endfunction

endpackage
