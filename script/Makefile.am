MAINTAINERCLEANFILES    = Makefile.in

EXTRA_DIST		= sheepdog.in

noinst_HEADERS		= checkarch.sh vditest gen_man.pl gen_bash_completion.pl

initscript_SCRIPTS	= sheepdog
initscriptdir		= $(INITDDIR)

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
	chmod 0755 $@-t
	mv $@-t $@

all-local: $(initscript_SCRIPTS) $(completion_DATA)

clean-local:
	rm -rf $(initscript_SCRIPTS) $(completion_DATA)
