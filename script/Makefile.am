MAINTAINERCLEANFILES    = Makefile.in

EXTRA_DIST		= generic.in

noinst_HEADERS		= bash_completion_dog checkarch.sh vditest gen_man.pl \
			  gen_bash_completion.pl

target_INIT             = generic

target_BASH_COMPLETION  = bash_completion_dog

bash_completion_dog: $(top_srcdir)/dog/dog gen_bash_completion.pl Makefile
	rm -f $@-t $@
	$(top_srcdir)/script/gen_bash_completion.pl $(top_builddir)/dog/dog > $@-t
	mv $@-t $@

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

all-local: $(target_INIT) $(target_BASH_COMPLETION)

clean-local:
	rm -rf $(target_INIT)
	rm -rf $(target_BASH_COMPLETION)

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(INITDDIR)
	$(INSTALL) -m 755 generic $(DESTDIR)/$(INITDDIR)/sheepdog
	$(INSTALL) -d $(DESTDIR)/$(sysconfdir)/bash_completion.d
	$(INSTALL) bash_completion_dog $(DESTDIR)/$(sysconfdir)/bash_completion.d/dog

uninstall-local:
	cd $(DESTDIR)/$(INITDDIR) && rm -f sheepdog
	cd $(DESTDIR)/$(sysconfdir)/bash_completion.d && rm -f dog
