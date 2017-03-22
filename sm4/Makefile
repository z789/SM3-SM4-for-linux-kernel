ifneq ($(KERNELRELEASE),)
	obj-m := sm4_generic.o
else
	KERNELDIR ?= /lib/modules/`uname  -r`/build
	PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	rm -rf *.ko *.o *.mod.o *.mod.c *.symvers \.*.cmd .tmp_versions  modules.order
endif
