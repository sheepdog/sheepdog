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

SUBDIRS			= lib collie sheep include script man tests

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/${localstatedir}/lib/sheepdog

uninstall-local:
	rmdir $(DESTDIR)/${localstatedir}/lib/sheepdog || :;

dist-clean-local:
	rm -f autoconf automake autoheader

clean-generic:
	rm -rf $(SPEC) $(TARFILE) cscope*

cscope:
	@echo create cscope.out
	@find -name '*.[ch]' > cscope.files
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

