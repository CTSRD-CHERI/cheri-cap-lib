CAP ?= 64
ifeq ($(CAP), 128)
BSCFLAGS = -D CAP128
else
BSCFLAGS = -D CAP64
endif

CAPTYPE ?= CapPipe
BSCFLAGS += -D CAPTYPE=$(CAPTYPE)

ARCH ?= RISCV
ifeq ($(ARCH), RISCV)
BSCFLAGS += -D RISCV
endif

BSV_VERILOG_WRAPPERS_DIR ?= $(CURDIR)/build/
BUILD_DIR = $(BSV_VERILOG_WRAPPERS_DIR)
COUNTEREXAMPLE_DIR = $(CURDIR)/counterexamples/
BSCFLAGS += -bdir $(BUILD_DIR)

all: verilog-wrappers blarney-wrappers

$(BUILD_DIR):
	mkdir -p $@

$(COUNTEREXAMPLE_DIR):
	mkdir -p $@

verilog-wrappers: CHERICapWrap.bsv CHERICap.bsv CHERICC_Fat.bsv $(BUILD_DIR)
	bsc $(BSCFLAGS) -vdir $(BSV_VERILOG_WRAPPERS_DIR) -verilog -u $<

verilog-props: CHERICapProps.bsv CHERICap.bsv CHERICC_Fat.bsv $(BUILD_DIR) $(COUNTEREXAMPLE_DIR)
	bsc $(BSCFLAGS) -vdir $(COUNTEREXAMPLE_DIR) -verilog -u $<

check-prop: assertions.sv verilog-props $(COUNTEREXAMPLE_DIR)
	sby --prefix $(COUNTEREXAMPLE_DIR) -f check.sby

blarney-wrappers: CHERICapWrap.py verilog-wrappers $(BUILD_DIR)
	./CHERICapWrap.py -o $(BUILD_DIR)/CHERIBlarneyWrappers $(BUILD_DIR)/*.v

.PHONY: clean clean-counterexamples full-clean

clean-counterexamples:
	rm -rf $(COUNTEREXAMPLE_DIR)

clean:
	rm -rf $(BUILD_DIR)

full-clean: clean clean-counterexamples
