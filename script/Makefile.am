MAINTAINERCLEANFILES    = Makefile.in

EXTRA_DIST		= sheepdog.in sheepdog.service.in sheepdog.sysconfig

noinst_HEADERS		= checkarch.sh vditest gen_man.pl gen_bash_completion.pl

initscript_SCRIPTS	= sheepdog
initscriptdir		= $(INITDDIR)

systemd_DATA = sheepdog.service
systemddir = $(systemdsystemunitdir)

completion_DATA		= dog
completiondir		= $(sysconfdir)/bash_completion.d

dog: gen_bash_completion.pl Makefile
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
	if [ $@ != "sheepdog.service" ]; then chmod 0755 $@-t; fi
	mv $@-t $@

all-local: $(initscript_SCRIPTS) $(systemd_SERVICES) $(completion_DATA)

clean-local:
	rm -rf $(initscript_SCRIPTS) $(systemd_SERVICES) $(completion_DATA)
