obj-m += tlbkit.o
tlbkit-objs := module.o bad.o

LIBNAME = capstone


all:
	KCPPFLAGS="-O0 -w" make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	objdump -d tlbkit.ko > tlbkit.objdump

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insmod:
	sudo dmesg -C
	sudo insmod tlbkit.ko
	sudo dmesg -wH --notime

rmmod:
	sudo rmmod tlbkit.ko
