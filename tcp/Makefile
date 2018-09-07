CONFIG_MODULE_SG=n
obj-m := tcp_trace.o 
tcp_trace-objs += tcp_trace_helper.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
WARN_FLAGS += -Wall

CFLAGS_tcp_trace.o := -I$(src)

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: build clean 
