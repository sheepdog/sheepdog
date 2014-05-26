KDIR	?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD modules
clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install
