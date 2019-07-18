
CAP ?= 128
ifeq ($(CAP), 128)
BSCFLAGS = -D CAP128
else
BSCFLAGS = -D CAP64
endif

verilog-wrappers: CHERICapWrap.bsv CHERICap.bsv CHERICC_Fat.bsv
	bsc $(BSCFLAGS) -verilog -u $<

.PHONY: clean clean-verilog-wrappers

clean-verilog-wrappers: clean
	rm -f *.v

clean:
	rm -f *.bo
