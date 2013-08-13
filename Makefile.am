SPEC			= $(PACKAGE_NAME).spec

TARFILE			= $(PACKAGE_NAME)-$(VERSION).tar.gz

EXTRA_DIST		= autogen.sh

AUTOMAKE_OPTIONS	= foreign

MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure depcomp	\
			  config.guess config.sub missing install-sh	\
			  autoheader automake autoconf config.status	\
			  config.log

dist_doc_DATA		= 

sheepdogsysconfdir	= ${SHEEPDOGCONFDIR}

sheepdogsysconf_DATA	= 

SUBDIRS			= lib dog sheep include script shepherd tools

if BUILD_SHEEPFS
SUBDIRS			+= sheepfs
endif

SUBDIRS			+= man

if BUILD_UNITTEST
SUBDIRS			+= tests/unit
endif

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/${localstatedir}/lib/sheepdog

uninstall-local:
	rmdir $(DESTDIR)/${localstatedir}/lib/sheepdog || :;

dist-clean-local:
	rm -f autoconf automake autoheader

clean-generic:
	rm -rf $(SPEC) $(TARFILE) cscope*
	find -name '*.orig' -or -name '*.rej' | xargs rm -f
	find -name '*.gcno' -or -name '*.gcda' -or -name '*.info' | xargs rm -f

cscope:
	@echo create cscope.out
	@find -name '*.[chS]' > cscope.files
	@cscope -bq

$(SPEC): $(SPEC).in
	rm -f $@-t $@
	LC_ALL=C date="$(shell date "+%a %b %d %Y")" && \
	sed \
	-e "s#@version@#$(VERSION)#g" \
	-e "s#@date@#$$date#g" \
	$< > $@-t
	chmod a-w $@-t
	mv $@-t $@

RPMBUILDOPTS = --define "_sourcedir $(abs_builddir)" \
		--define "_specdir $(abs_builddir)" \
		--define "_builddir $(abs_builddir)" \
		--define "_srcrpmdir $(abs_builddir)" \
		--define "_rpmdir $(abs_builddir)"

$(TARFILE):
	$(MAKE) dist

srpm: clean
	$(MAKE) $(SPEC) $(TARFILE)
	rpmbuild $(RPMBUILDOPTS) --nodeps -bs $(SPEC)

rpm: clean
	$(MAKE) $(SPEC) $(TARFILE)
	rpmbuild $(RPMBUILDOPTS) -ba $(SPEC)

deb:
	fakeroot ./debian/rules clean
	git log > debian/CHANGELOG
	rm -f debian/changelog
	dch -v $(shell echo $(PACKAGE_VERSION) | sed s/_/+/ | sed s/_/./g)-1 \
		--package sheepdog --create 'Local build'
	fakeroot ./debian/rules binary

CGCC=cgcc
CGCC_CFLAGS=-Wbitwise -Wno-return-void $(ARCH) -fno-common

sparse: ARCH=$(shell sh script/checkarch.sh)
sparse:
	$(MAKE) CC=$(CGCC) CFLAGS="$(CFLAGS) $(CGCC_CFLAGS)"

CHECK_STYLE=../script/checkpatch.pl -f --no-summary --terse
check-style:
	@for dir in lib dog sheep include sheepfs; do \
		make -C $$dir check-style CHECK_STYLE="$(CHECK_STYLE)"; \
	done

if BUILD_COVERAGE
coverage: clean check
	@rm -rf coverage

	@for dir in dog sheep tests/unit/dog tests/unit/sheep ; do\
		$(MAKE) -C $$dir coverage;				\
	done

	@lcov -a dog/dog.info -a sheep/sheep.info			\
	-a tests/unit/dog/dog.info -a tests/unit/sheep/sheep.info	\
	-o sheep.info &&						\
	lcov -r sheep.info /usr/include/\* -o sheep.info &&		\
	lcov -r sheep.info tests/unit/\* -o sheep.info &&		\
	genhtml sheep.info -o coverage
endif
