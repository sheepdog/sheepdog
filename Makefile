VERSION ?= $(shell git log -1 --pretty=format:%h-%p || echo "unknown-version")

PREFIX ?= /usr

CHECK_CC = cgcc
CHECK_CC_FLAGS = '$(CHECK_CC) -Wbitwise -Wno-return-void -no-compile $(ARCH)'

export VERSION PREFIX

.PHONY:all
all:
	$(MAKE) -C shepherd
	$(MAKE) -C collie

.PHONY:clean
clean:
	$(MAKE) -C shepherd clean
	$(MAKE) -C collie clean
	$(MAKE) -C lib clean

.PHONY:install
install:
	$(MAKE) -C shepherd install
	$(MAKE) -C collie install

.PHONY:check
check: ARCH=$(shell sh script/checkarch.sh)
check:
	CC=$(CHECK_CC_FLAGS) $(MAKE) all

.PHONY:check32
check32: override ARCH=-m32
check32:
	CC=$(CHECK_CC_FLAGS) $(MAKE) all

.PHONY:check64
check64: override ARCH=-m64
check64:
	CC=$(CHECK_CC_FLAGS) $(MAKE) all

