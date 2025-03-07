module assert_prop_unique(
         input wire [63 : 0] prop_base,
         input wire [63 : 0] prop_len,
         input wire [63 : 0] prop_newBase,
         input wire [63 : 0] prop_newLen
       );
  wire prop_ok;

  module_prop_unique module_prop_unique_inst (
    .prop_unique_base(prop_base),
    .prop_unique_len(prop_len),
    .prop_unique_newBase(prop_newBase),
    .prop_unique_newLen(prop_newLen),
    .prop_unique(prop_ok)
  );

  always @(*) begin
    assert(prop_ok);
  end
endmodule

module assert_prop_exact(
         input wire [63 : 0] prop_base,
         input wire [63 : 0] prop_len
       );
  wire prop_ok;

  module_prop_exact module_prop_exact_inst (
    .prop_exact_base(prop_base),
    .prop_exact_len(prop_len),
    .prop_exact(prop_ok)
  );

  always @(*) begin
    assert(prop_ok);
  end
endmodule

module assert_prop_exactConditions(
         input wire [63 : 0] prop_base,
         input wire [63 : 0] prop_len
       );
  wire prop_ok;

  module_prop_exactConditions module_prop_exactConditions_inst (
    .prop_exactConditions_base(prop_base),
    .prop_exactConditions_len(prop_len),
    .prop_exactConditions(prop_ok)
  );

  always @(*) begin
    assert(prop_ok);
  end
endmodule

module assert_prop_getBase(
         input wire [63 : 0] prop_base,
         input wire [63 : 0] prop_len
       );
  wire prop_ok;

  module_prop_getBase module_prop_getBase_inst(
    .prop_getBase_base(prop_base),
    .prop_getBase_len(prop_len),
    .prop_getBase(prop_ok)
  );

  always @(*) begin
    assert(prop_ok);
  end
endmodule

module assert_prop_getTop(
         input wire [63 : 0] prop_base,
         input wire [63 : 0] prop_len,
         input wire [63 : 0] prop_addr
       );
  wire prop_ok;

  module_prop_getTop module_prop_getTop_inst(
    .prop_getTop_base(prop_base),
    .prop_getTop_len(prop_len),
    .prop_getTop_addr(prop_addr),
    .prop_getTop(prop_ok)
  );

  always @(*) begin
    assert(prop_ok);
  end
endmodule

module assert_prop_getLength(
         input wire [63 : 0] prop_base,
         input wire [63 : 0] prop_addr,
         input wire [63 : 0] prop_len
       );
  wire prop_ok;

  module_prop_getLength module_prop_getLength_inst(
    .prop_getLength_base(prop_base),
    .prop_getLength_len(prop_len),
    .prop_getLength_addr(prop_addr),
    .prop_getLength(prop_ok)
  );

  always @(*) begin
    assert(prop_ok);
  end
endmodule

module assert_prop_isInBounds(
         input wire [63 : 0] prop_base,
         input wire [63 : 0] prop_len,
         input wire [63 : 0] prop_addr
       );
  wire prop_ok;

  module_prop_isInBounds module_prop_isInBounds_inst(
    .prop_isInBounds_base(prop_base),
    .prop_isInBounds_len(prop_len),
    .prop_isInBounds_addr(prop_addr),
    .prop_isInBounds(prop_ok)
  );

  always @(*) begin
    assert(prop_ok);
  end
endmodule

module assert_prop_setAddr(
         input wire [63 : 0] prop_base,
         input wire [63 : 0] prop_len,
         input wire [63 : 0] prop_addr
       );
  wire prop_ok;

  module_prop_setAddr module_prop_setAddr_inst(
    .prop_setAddr_base(prop_base),
    .prop_setAddr_len(prop_len),
    .prop_setAddr_addr(prop_addr),
    .prop_setAddr(prop_ok)
  );

  always @(*) begin
    assert(prop_ok);
  end
endmodule

module assert_prop_fromToMem(
         input wire [128 : 0] prop_in,
       );
  wire prop_ok;

  module_prop_fromToMem module_fromToMem(
    .prop_fromToMem_in(prop_in),
    .prop_fromToMem(prop_ok)
  );

  always @(*) begin
    assert(prop_ok);
  end
endmodule

module assert_prop_setBounds(
         input wire [63 : 0] prop_base,
         input wire [63 : 0] prop_len,
         input wire [63 : 0] prop_addr,
         input wire [63 : 0] prop_new_len
       );
  wire prop_ok;

  module_prop_setBounds module_prop_setBounds_inst(
    .prop_setBounds_base(prop_base),
    .prop_setBounds_len(prop_len),
    .prop_setBounds_addr(prop_addr),
    .prop_setBounds_new_len(prop_new_len),
    .prop_setBounds(prop_ok)
  );

  always @(*) begin
    assert(prop_ok);
  end
endmodule
