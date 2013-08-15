MAINTAINERCLEANFILES    = Makefile.in

dist_man_MANS		= sheep.8 dog.8

if BUILD_SHEEPFS
dist_man_MANS 		+= sheepfs.8
endif

EXTRA_DIST		= sheep.8.in dog.8.in sheepfs.8.in

%.8: %.8.in Makefile $(top_srcdir)/script/gen_man.pl $(top_builddir)/%/$*
	rm -f $@-t $@
	@sed \
		-e "s#@DATE@#`date '+%Y-%m-%d'`#g" \
		-e "s#@OPTIONS@#$(shell $(top_srcdir)/script/gen_man.pl $(top_builddir)/$*/$*)#g" \
		$< > $@-t
	mv $@-t $@

all-local: $(dist_man_MANS)

clean-local:
	rm -rf $(dist_man_MANS)
