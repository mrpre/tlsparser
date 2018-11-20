ifneq  ($(KERNELRELEASE),)
obj-m +=tlspaser.o
tlspaser-objs := parser.o certparse.o pktparse.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD:=$(shell pwd)
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -f *.order *.mod.c *.ko *.o *.symvers *.cmd *.cmd.o ./.*.cmd
endif

