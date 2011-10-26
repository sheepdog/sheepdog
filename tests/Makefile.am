$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	@{ \
	echo '# Signature of the current package.'; \
	echo 'm4_define([AT_PACKAGE_NAME], [$(PACKAGE_NAME)])'; \
	echo 'm4_define([AT_PACKAGE_TARNAME], [$(PACKAGE_TARNAME)])'; \
	echo 'm4_define([AT_PACKAGE_VERSION], [$(PACKAGE_VERSION)])'; \
	echo 'm4_define([AT_PACKAGE_STRING], [$(PACKAGE_STRING)])'; \
	echo 'm4_define([AT_PACKAGE_BUGREPORT], [$(PACKAGE_BUGREPORT)])'; \
	echo 'm4_define([AT_PACKAGE_URL], [$(PACKAGE_URL)])'; \
	} > '$(srcdir)/package.m4'

EXTRA_DIST =
TESTSUITE = $(srcdir)/testsuite
AUTOTEST = $(AUTOM4TE) --language=autotest

check-local: atconfig $(srcdir)/package.m4
	@{ \
	echo 'AT_INIT()'; \
	echo 'AT_COLOR_TESTS'; \
	for f in *.py; do \
		f=$${f%.py}; \
		echo "AT_BANNER([$$f])"; \
		python -c "import $$f; import sys; \
			[sys.stdout.write( \
				'AT_SETUP([' + f + '])\n' + \
				'AT_CHECK([ \
					PYTHONPATH=$(abs_srcdir) \
					SHEEP=$(abs_top_builddir)/sheep/sheep \
					COLLIE=$(abs_top_builddir)/collie/collie \
					python -c \'import $$f; $$f.' + f + '()\' \
				],,stdout,stderr)\n' + \
				'AT_CLEANUP()\n' \
			) for f in dir($$f) if f.startswith('test_')]"; \
	done \
	} > '$(TESTSUITE).at'
	$(AUTOTEST) -I '$(srcdir)' -o '$(TESTSUITE)' '$(TESTSUITE).at'
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || $(SHELL) '$(TESTSUITE)' --clean
