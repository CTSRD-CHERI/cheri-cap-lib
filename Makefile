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

BSV_VERILOG_WRAPPERS_DIR ?= $(CURDIR)
BSCFLAGS += -vdir $(BSV_VERILOG_WRAPPERS_DIR)

all: verilog-wrappers blarney-wrappers

verilog-wrappers: CHERICapWrap.bsv CHERICap.bsv CHERICC_Fat.bsv
	bsc $(BSCFLAGS) -verilog -u $<

verilog-props: CHERICapProps.bsv CHERICap.bsv CHERICC_Fat.bsv
	bsc $(BSCFLAGS) -verilog -u $<

check-prop: assertions.sv verilog-wrappers verilog-props
	sby -f check.sby

blarney-wrappers: CHERICapWrap.py verilog-wrappers
	./CHERICapWrap.py -o CHERIBlarneyWrappers *.v

.PHONY: clean clean-verilog-wrappers

clean-verilog-wrappers: clean
	rm -f *.v

clean-blarney-wrappers: clean
	rm -f *.hs

clean:
	rm -f *.bo
