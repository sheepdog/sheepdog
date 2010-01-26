VERSION ?= $(shell git log -1 --pretty=format:%h-%p || echo "unknown-version")

PREFIX ?= /usr

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
