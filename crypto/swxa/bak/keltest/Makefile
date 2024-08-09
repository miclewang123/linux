# Makefile2.6
ifneq ($(KERNELRELEASE),)
#kbuild syntax. dependency relationshsip of files and target modules are listed here.

obj-m := test3.o

else
KBUILD_EXTRA_SYMBOLS=/home/wangyi/work/linux/crypto/swxa/keltest/bak/Module.symvers 
obj-m:=test.o 

PWD:=$(shell pwd) 

KERNDIR:=/lib/modules/$(shell uname -r)/build/ 

default: 
	$(MAKE) -C $(KERNDIR) M=$(PWD) modules

install: 
	$(MAKE) -C $(KERNDIR) M=$(PWD) modules_install 
	depmod -a 
clean: 
	$(MAKE) -C $(KERNDIR) M=$(PWD) clean 
endif









