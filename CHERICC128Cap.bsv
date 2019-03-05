/*
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

package CHERICC128Cap;

import DefaultValue::*;
import Capability128ccLibs::*;
import CHERICap::*;

export CapMem;
export CapReg;
export CapPipe;
export CHERICap::*;


// ===============================================================================
// Typeclass instance for interface

typedef Bit#(129) CapMem;

typedef CapFat CapReg;

typedef Tuple2#(CapFat, TempFields) CapPipe;

instance CHERICap #(CapMem, 18, 64);
  function isValidCap (x) = error("feature not implemented for this cap type");
  function setValidCap (x) = error("feature not implemented for this cap type");
  function getHardPerms (x) = error("feature not implemented for this cap type");
  function setHardPerms (x) = error("feature not implemented for this cap type");
  function getSoftPerms (x) = error("feature not implemented for this cap type");
  function setSoftPerms (x) = error("feature not implemented for this cap type");
  function getKind (x) = error("feature not implemented for this cap type");
  function getType (x) = error("feature not implemented for this cap type");
  function setType (x) = error("feature not implemented for this cap type");
  function getAddr (x) = error("feature not implemented for this cap type");
  function setAddr (x) = error("feature not implemented for this cap type");
  function getOffset (x) = error("feature not implemented for this cap type");
  function setOffset (x) = error("feature not implemented for this cap type");
  function getBase (x) = error("feature not implemented for this cap type");
  function getTop (x) = error("feature not implemented for this cap type");
  function getLength (x) = error("feature not implemented for this cap type");
  function setBounds (x) = error("feature not implemented for this cap type");
  function nullWithAddr (x) = error("feature not implemented for this cap type");
  function almightyCap = error("feature not implemented for this cap type");
  function nullCap = error("feature not implemented for this cap type");
endinstance

instance CHERICap #(CapReg, 18, 64);
  function isValidCap (x) = error("feature not implemented for this cap type");
  function setValidCap (x) = error("feature not implemented for this cap type");
  function getHardPerms (x) = error("feature not implemented for this cap type");
  function setHardPerms (x) = error("feature not implemented for this cap type");
  function getSoftPerms (x) = error("feature not implemented for this cap type");
  function setSoftPerms (x) = error("feature not implemented for this cap type");
  function getKind (x) = error("feature not implemented for this cap type");
  function getType (x) = error("feature not implemented for this cap type");
  function setType (x) = error("feature not implemented for this cap type");
  function getAddr (x) = error("feature not implemented for this cap type");
  function setAddr (x) = error("feature not implemented for this cap type");
  function getOffset (x) = error("feature not implemented for this cap type");
  function setOffset (x) = error("feature not implemented for this cap type");
  function getBase (x) = error("feature not implemented for this cap type");
  function getTop (x) = error("feature not implemented for this cap type");
  function getLength (x) = error("feature not implemented for this cap type");
  function setBounds (x) = error("feature not implemented for this cap type");
  function nullWithAddr (x) = error("feature not implemented for this cap type");
  function almightyCap = defaultCapFat;
  function nullCap = Capability128ccLibs::nullCap;
endinstance

instance CHERICap #(CapPipe, 18, 64);

  function isValidCap (x) = tpl_1(x).isCapability;

  function CapPipe setValidCap (CapPipe cap, Bool tag);
    let capReg = tpl_1(cap);
    let tempFields = tpl_2(cap);
    capReg.isCapability = tag;
    return tuple2(capReg, tempFields);
  endfunction

  function HardPerms getHardPerms (CapPipe cap);
    let capReg = tpl_1(cap);
    return HardPerms {
      accessSysRegs: capReg.perms.hard.acces_sys_regs,
      permitUnseal: capReg.perms.hard.permit_unseal,
      permitCCall: capReg.perms.hard.permit_ccall,
      permitSeal: capReg.perms.hard.permit_seal,
      permitStoreLocalCap: capReg.perms.hard.permit_store_ephemeral_cap,
      permitStoreCap: capReg.perms.hard.permit_store_cap,
      permitLoadCap: capReg.perms.hard.permit_load_cap,
      permitStore: capReg.perms.hard.permit_store,
      permitLoad: capReg.perms.hard.permit_load,
      permitExecute: capReg.perms.hard.permit_execute,
      global: capReg.perms.hard.non_ephemeral
    };
  endfunction

  function CapPipe setHardPerms (CapPipe cap, HardPerms perms);
    let capReg = tpl_1(cap);
    let tempFields = tpl_2(cap);
    capReg.perms.hard = HPerms {
      reserved: ?,
      acces_sys_regs: perms.accessSysRegs,
      permit_unseal: perms.accessSysRegs,
      permit_ccall: perms.accessSysRegs,
      permit_seal: perms.accessSysRegs,
      permit_store_ephemeral_cap: perms.accessSysRegs,
      permit_store_cap: perms.accessSysRegs,
      permit_load_cap: perms.accessSysRegs,
      permit_store: perms.accessSysRegs,
      permit_load: perms.accessSysRegs,
      permit_execute: perms.accessSysRegs,
      non_ephemeral: perms.accessSysRegs
    };
    return tuple2(capReg, tempFields);
  endfunction

  function SoftPerms getSoftPerms (CapPipe cap);
    let capReg = tpl_1(cap);
    return zeroExtend(capReg.perms.soft);
  endfunction

  function CapPipe setSoftPerms (CapPipe cap, SoftPerms perms);
    let capReg = tpl_1(cap);
    let tempFields = tpl_2(cap);
    capReg.perms.soft = truncate(perms);
    return tuple2(capReg, tempFields);
  endfunction

  function Kind getKind (CapPipe cap);
    let capReg = tpl_1(cap);
    case (capReg.otype)
      otype_unsealed: return UNSEALED;
      otype_sentry: return SENTRY;
      default: return (capReg.otype <= otype_max) ? SEALED_WITH_TYPE : RES0;
    endcase
  endfunction

  function getType (x) = getType(tpl_1(x)).d;

  function Exact#(CapPipe) setType (CapPipe cap, Bit #(18) otype);
    let capReg = tpl_1(cap);
    let tempFields = tpl_2(cap);
    if (otype == -1) begin
      capReg = unseal(capReg, ?);
    end else begin
      capReg = seal(capReg, ?, VnD {v: True, d:otype});
    end
    return Exact {
      exact: True,
      value: tuple2(capReg, tempFields)
    };
  endfunction

  function getAddr (x) = truncate(getAddress(tpl_1(x)));

  function Exact#(CapPipe) setAddr (CapPipe cap, Bit#(64) address);
    let capReg = tpl_1(cap);
    let tempFields = tpl_2(cap);
    capReg = setAddress(capReg, zeroExtend(address), tempFields);
    return Exact {exact: capReg.isCapability, value: tuple2(capReg, getTempFields(capReg))};
  endfunction

  function getOffset (x) = getOffset(tpl_1(x));

  function Exact#(CapPipe) setOffset (CapPipe cap, Bit#(64) offset);
    let capReg = tpl_1(cap);
    let tempFields = tpl_2(cap);
    capReg = incOffset(capReg, ?, zeroExtend(offset), tempFields, True); //TODO split into separate incOffset and setOffset functions?
    return Exact {exact: capReg.isCapability, value: tuple2(capReg, getTempFields(capReg))};
  endfunction

  function Bit#(64) getBase (CapPipe cap);
    let capReg = tpl_1(cap);
    let tempFields = tpl_2(cap);
    return truncate(Capability128ccLibs::getBotFat(capReg, tempFields));
  endfunction

  function Bit#(65) getTop (CapPipe cap);
    let capReg = tpl_1(cap);
    let tempFields = tpl_2(cap);
    return truncate(Capability128ccLibs::getTopFat(capReg, tempFields));
  endfunction

  function Bit#(65) getLength (CapPipe cap);
    let capReg = tpl_1(cap);
    let tempFields = tpl_2(cap);
    return truncate(Capability128ccLibs::getLengthFat(capReg, tempFields));
  endfunction

  function Bool isInBounds (CapPipe cap, Bool inclusive);
    let capReg = tpl_1(cap);
    let tempFields = tpl_2(cap);
    return capInBounds(capReg, tempFields, inclusive);
  endfunction

  function Exact#(CapPipe) setBounds (CapPipe cap, Bit#(64) length);
    let capReg = tpl_1(cap);
    let tempFields = tpl_2(cap);
    match {.result, .exact} = Capability128ccLibs::setBounds(capReg, length);
    return Exact {exact: exact, value: tuple2(result, getTempFields(result))};
  endfunction

  function CapPipe nullWithAddr (Bit#(64) addr);
    let res = setAddress (nullCap, zeroExtend(addr), getTempFields(nullCap));
    return tuple2(res, getTempFields(res));
  endfunction

  function almightyCap = tuple2(defaultCapFat, getTempFields(defaultCapFat));

  function nullCap = tuple2(nullCap, getTempFields(nullCap));

endinstance

instance Cast #(CapMem, CapReg);
  function CapReg cast (CapMem thin);
    return unpackCap(unpack(thin));
  endfunction
endinstance

instance Cast #(CapReg, CapMem);
  function CapMem cast (CapReg fat);
     return pack(packCap(fat));
  endfunction
endinstance

instance Cast #(CapReg, CapPipe);
  function CapPipe cast (CapReg thin);
    return tuple2(thin, getTempFields(thin));
  endfunction
endinstance

instance Cast #(CapPipe, CapReg);
  function CapReg cast (CapPipe fat);
    return tpl_1(fat);
  endfunction
endinstance

endpackage
