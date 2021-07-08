CAP ?= 64
ifeq ($(CAP), 128)
BSCFLAGS = -D CAP128
else
BSCFLAGS = -D CAP64
endif

ARCH ?= RISCV
ifeq ($(ARCH), RISCV)
BSCFLAGS += -D RISCV
endif

all: verilog-wrappers blarney-wrappers

verilog-wrappers: CHERICapWrap.bsv CHERICap.bsv CHERICC_Fat.bsv
	bsc $(BSCFLAGS) -verilog -u $<

blarney-wrappers: CHERICapWrapBlarney.py verilog-wrappers
	@./CHERICapWrapBlarney.py > CHERIBlarneyWrappers.hs

.PHONY: clean clean-verilog-wrappers

clean-verilog-wrappers: clean
	rm -f *.v

clean-blarney-wrappers: clean
	rm -f *.hs

clean:
	rm -f *.bo
