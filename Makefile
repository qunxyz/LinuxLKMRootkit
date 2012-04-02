obj-m	:= lkm.o

KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm *.o modules.order Module.symvers lkm.mod.c .*.cmd
load:
	sudo insmod lkm.ko
unload:
	sudo rmmod lkm
dmesg:
	dmesg|tail -n50
test:
	sudo modprobe kvm
	sudo modprobe kvm-amd
	qemu -m 4G -hda archlinux.img -nographic -daemonize -redir tcp:2222::22 &
	sleep 5
	bash -c "ssh -i ~/.ssh/qemu -p 2222 lkm@localhost"
test64:
	sudo modprobe kvm
	sudo modprobe kvm-amd
	qemu-system-x86_64 -m 4G -hda archlinux64.img -nographic -daemonize -redir tcp:2223::22 &
	sleep 5
	bash -c "ssh -i ~/.ssh/qemu -p 2223 lkm@localhost"

endtest:
	pkill qemu
	sleep 3
	sudo rmmod kvm-amd
	sudo rmmod kvm
