KDIR ?= /lib/modules/$(shell uname -r)/source

BIN :=tail_usr.o 
TOOLS:= $(KDIR)/tools
INC = -I$(KDIR)/tools/testing/selftests/bpf \
      -I$(KDIR)/tools/lib \
      -I$(KDIR)/tools/include \
      -I$(KDIR)/tools/include/uapi \
      -I$(KDIR)/samples/bpf \
      -I$(KDIR)/tools/perf

all: $(BIN)

tail_usr.o: tail_usr.c
	gcc $< $(KDIR)/samples/bpf/bpf_load.c -o $@ $(INC) $(TOOLS)/lib/bpf/libbpf.a -lelf

clean:
	rm -f tail_usr.o 
