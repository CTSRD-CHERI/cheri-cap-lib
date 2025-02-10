package zcheri_pkg;

    // size parameters
    ///////////////////////////////////////////////////////////////////////////

    localparam XLEN = 64;
    localparam CLEN = 2*XLEN;
    localparam CTLEN = 2*XLEN + 1;
    localparam LVLBITS = 1;

    // CHERI capability fields widths
    localparam RES_HI_W = 7;
    localparam SDP_W  = 4;
    localparam M_W = 1;
    localparam AP_W = 7 + LVLBITS;
    localparam CL_W = LVLBITS;
    localparam RES_LO_W = 16 - LVLBITS;
    localparam CT_W = 1;
    localparam EF_W = 1;
    localparam T_ALL_W = 12; // inclusive of TE
    localparam T_W = 9; // exclusive of TE
    localparam TE_W = 3;
    localparam B_ALL_W = 14; // inclusive of BE
    localparam B_W = 11; // exclusive of BE
    localparam BE_W = 3;
    localparam ADDR_W = XLEN; // CHERI capability address

    // type definitions
    ///////////////////////////////////////////////////////////////////////////

    // general helper types
    typedef logic bool_t;

    // primitive bitfield types of defined capability field widths (<FIELDNAME>_bits_t)
    typedef logic [RES_HI_W-1:0] RES_HI_bits_t;
    typedef logic [SDP_W-1:0] SDP_bits_t;
    typedef logic [M_W-1:0] M_bits_t;
    typedef logic [AP_W-1:0] AP_bits_t;
    typedef logic [CL_W-1:0] CL_bits_t;
    typedef logic [RES_LO_W-1:0] RES_LO_bits_t;
    typedef logic [CT_W-1:0] CT_bits_t;
    typedef logic [EF_W-1:0] EF_bits_t;
    typedef logic [T_ALL_W-1:0] T_all_bits_t;
    typedef logic [T_W-1:0] T_bits_t;
    typedef logic [TE_W-1:0] TE_bits_t;
    typedef logic [B_ALL_W-1:0] B_all_bits_t;
    typedef logic [B_W-1:0] B_bits_t;
    typedef logic [BE_W-1:0] BE_bits_t;
    typedef logic [ADDR_W-1:0] ADDR_bits_t;
    typedef logic [ADDR_W:0] ADDR_big_bits_t;

    // abstract datatypes
    typedef logic [LVLBITS-1:0] cap_lvl_t; // "capability level" type
    typedef SDP_bits_t SDP_t; // capability software defined permission
    typedef struct packed {
      cap_lvl_t SL;
      bool_t EL;
      bool_t LM;
      bool_t ASR;
      bool_t X;
      bool_t R;
      bool_t W;
      bool_t C;
    } AP_t; // capability architectural permissions
    typedef M_bits_t M_t; // capability mode, int ptr (1) or cap ptr (0)
    typedef cap_lvl_t CL_t; // capability level
    typedef CT_bits_t CT_t; // capability type, sealed(!=0) or not sealed(==0)
    typedef struct packed {
      bool_t EF; // exponent format - 1: zero_exp, 0: internal_exp
      union packed {
        struct packed {
          T_all_bits_t T;
          B_all_bits_t B;
        } zero_exp; // all bits used for T (top) and B (base)
        struct packed {
          T_bits_t T;
          TE_bits_t TE;
          B_bits_t B;
          BE_bits_t BE;
        } internal_exp; // bottom bits of T and B used for E (TE and BE)
      } TBE;
    } mem_bounds_t; // capability bounds
    typedef ADDR_bits_t ADDR_t; // capability address type
    typedef ADDR_big_bits_t ADDR_big_t; // large capability address type (ADDR_W + 1)

    // The CHERI capability memory format (validity tag included)
    typedef struct packed {
      bool_t tag;
      RES_HI_bits_t res_hi;
      SDP_t SDP;
      M_t M;
      AP_t AP;
      CL_t CL;
      RES_LO_bits_t res_lo;
      CT_t CT;
      mem_bounds_t bounds;
      ADDR_t addr;
    } cap_mem_t;
    // raw getters / setters
    // these getters / setters do not perform any checks and directly read
    // from / alter the capability bits
    `define def_cap_mem_raw_get(NAME, RETTYPE) \
    function automatic RETTYPE cap_mem_raw_get_``NAME(cap_mem_t cap); \
      return cap.``NAME; \
    endfunction
    `define def_cap_mem_raw_set(NAME, ARGTYPE) \
    function automatic cap_mem_t cap_mem_raw_set_``NAME(cap_mem_t cap, ARGTYPE NAME); \
      cap_mem_t new_cap = cap; \
      new_cap.NAME = NAME; \
      return new_cap; \
    endfunction
    `def_cap_mem_raw_get(tag, bool_t)
    `def_cap_mem_raw_set(tag, bool_t)
    `def_cap_mem_raw_get(res_hi, RES_HI_bits_t)
    `def_cap_mem_raw_set(res_hi, RES_HI_bits_t)
    `def_cap_mem_raw_get(SDP, SDP_t)
    `def_cap_mem_raw_set(SDP, SDP_t)
    `def_cap_mem_raw_get(M, M_t)
    `def_cap_mem_raw_set(M, M_t)
    `def_cap_mem_raw_get(AP, AP_t)
    `def_cap_mem_raw_set(AP, AP_t)
    `def_cap_mem_raw_get(CL, CL_t)
    `def_cap_mem_raw_set(CL, CL_t)
    `def_cap_mem_raw_get(res_lo, RES_LO_bits_t)
    `def_cap_mem_raw_set(res_lo, RES_LO_bits_t)
    `def_cap_mem_raw_get(CT, CT_t)
    `def_cap_mem_raw_set(CT, CT_t)
    `def_cap_mem_raw_get(bounds, mem_bounds_t)
    `def_cap_mem_raw_set(bounds, mem_bounds_t)
    `def_cap_mem_raw_get(addr, ADDR_t)
    `def_cap_mem_raw_set(addr, ADDR_t)

    // rich return type for set bounds operation
    typedef struct packed {
      cap_mem_t cap;
      bool_t exact;
      bool_t in_bounds;
      ADDR_t length;
      ADDR_t mask;
    } cap_mem_set_bounds_ret_t;

    // CHERI memory capability API
    // cap_mem_<fun_name>
    ///////////////////////////////////////////////////////////////////////////

    function automatic bool_t cap_mem_is_valid(cap_mem_t cap);
      // TODO
      return 1'b0;
    endfunction
    function automatic cap_mem_t cap_mem_set_valid(cap_mem_t cap, bool_t valid);
      // TODO
      return cap;
    endfunction
    function automatic bool_t cap_mem_is_derivable(cap_mem_t cap);
      // TODO
      return 1'b0;
    endfunction
    function automatic cap_mem_t cap_mem_seal(cap_mem_t cap);
      // TODO
      return cap;
    endfunction
    function automatic cap_mem_t cap_mem_unseal(cap_mem_t cap);
      // TODO
      return cap;
    endfunction
    function automatic ADDR_t cap_mem_base(cap_mem_t cap);
      // TODO
      return 0;
    endfunction
    function automatic ADDR_big_t cap_mem_top(cap_mem_t cap);
      // TODO
      return 0;
    endfunction
    function automatic ADDR_big_t cap_mem_length(cap_mem_t cap);
      // TODO
      return 0;
    endfunction
    function automatic ADDR_t cap_mem_offset(cap_mem_t cap);
      // TODO
      return 0;
    endfunction
    function automatic cap_mem_t cap_mem_set_address(cap_mem_t cap, ADDR_t address);
      // TODO
      return cap;
    endfunction
    function automatic cap_mem_t cap_mem_inc_offset(cap_mem_t cap, ADDR_t inc);
      // TODO
      return cap;
    endfunction
    function automatic bool_t cap_mem_is_in_bounds(cap_mem_t cap, bool_t inclusive);
      // TODO
      return 1'b0;
    endfunction
    function automatic cap_mem_set_bounds_ret_t cap_mem_set_bounds(cap_mem_t cap, ADDR_t length);
      // TODO
      cap_mem_set_bounds_ret_t ret;
      return ret;
    endfunction
    function automatic cap_mem_t cap_mem_set_type(cap_mem_t cap, CT_t);
      // TODO
      return cap;
    endfunction

    // CHERI in register capability API
    // cap_reg_<fun_name>
    ///////////////////////////////////////////////////////////////////////////

    typedef struct packed {
    } cap_reg_t; // TODO

    function automatic bool_t cap_reg_is_valid(cap_reg_t cap);
      // TODO
      return 1'b0;
    endfunction
    function automatic cap_reg_t cap_reg_set_valid(cap_reg_t cap, bool_t valid);
      // TODO
      return cap;
    endfunction
    function automatic bool_t cap_reg_is_derivable(cap_reg_t cap);
      // TODO
      return 1'b0;
    endfunction
    function automatic cap_reg_t cap_reg_seal(cap_reg_t cap);
      // TODO
      return cap;
    endfunction
    function automatic cap_reg_t cap_reg_unseal(cap_reg_t cap);
      // TODO
      return cap;
    endfunction
    function automatic ADDR_t cap_reg_base(cap_reg_t cap);
      // TODO
      return 0;
    endfunction
    function automatic ADDR_big_t cap_reg_top(cap_reg_t cap);
      // TODO
      return 0;
    endfunction
    function automatic ADDR_big_t cap_reg_length(cap_reg_t cap);
      // TODO
      return 0;
    endfunction
    function automatic ADDR_t cap_reg_offset(cap_reg_t cap);
      // TODO
      return 0;
    endfunction
    function automatic cap_reg_t cap_reg_set_address(cap_reg_t cap, ADDR_t address);
      // TODO
      return cap;
    endfunction
    function automatic cap_reg_t cap_reg_inc_offset(cap_reg_t cap, ADDR_t inc);
      // TODO
      return cap;
    endfunction
    function automatic bool_t cap_reg_is_in_bounds(cap_reg_t cap, bool_t inclusive);
      // TODO
      return 1'b0;
    endfunction
    function automatic cap_reg_set_bounds_ret_t cap_reg_set_bounds(cap_reg_t cap, ADDR_t length);
      // TODO
      cap_reg_set_bounds_ret_t ret;
      return ret;
    endfunction
    function automatic cap_reg_t cap_reg_set_type(cap_reg_t cap, CT_t);
      // TODO
      return cap;
    endfunction

endpackage
