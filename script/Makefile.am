MAINTAINERCLEANFILES    = Makefile.in

EXTRA_DIST		= generic.in

noinst_HEADERS		= bash_completion_collie checkarch.sh start-sheepdog stop-sheepdog vditest

target_INIT             = generic

%: %.in Makefile
	rm -f $@-t $@
	sed \
		-e 's#@''SBINDIR@#$(sbindir)#g' \
		-e 's#@''SYSCONFDIR@#$(sysconfdir)#g' \
		-e 's#@''INITDDIR@#$(INITDDIR)#g' \
		-e 's#@''LOCALSTATEDIR@#$(localstatedir)#g' \
		$< > $@-t
	chmod 0755 $@-t
	mv $@-t $@

all-local: $(target_INIT)

clean-local:
	rm -rf $(target_INIT)

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(INITDDIR)
	$(INSTALL) -m 755 generic $(DESTDIR)/$(INITDDIR)/sheepdog

uninstall-local:
	cd $(DESTDIR)/$(INITDDIR) && \
		rm -f sheepdog
