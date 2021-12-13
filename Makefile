
all:
	make  -C sm3
	make  -C sm4
	make  -C sm34test

clean:
	make  -C sm3 clean
	make  -C sm4 clean
	make  -C sm34test clean

test:
	-sudo rmmod sm4_generic
	-sudo rmmod sm3
	sudo dmesg -C
	sudo insmod ./sm3/sm3.ko
	sudo insmod ./sm4/sm4_generic.ko
	-sudo insmod ./sm34test/sm34test.ko
	dmesg
	sudo rmmod sm4_generic
	sudo rmmod sm3
