# viarables
KERN_VERSION=$(shell uname -r)
KERNDIR = /lib/modules/${KERN_VERSION}/build

all:
	make -C ${KERNDIR} M=$(PWD) modules

clean:
	make -C ${KERNDIR} M=$(PWD) clean


# kbuild config
obj-m += km.o
km-y  := channel.o

