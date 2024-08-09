# Makefile2.6
ifneq ($(KERNELRELEASE),)
#kbuild syntax. dependency relationshsip of files and target modules are listed here.

obj-m := test.o

else

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
