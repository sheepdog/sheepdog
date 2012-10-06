#!/bin/sh
arch=`gcc -dumpmachine`

case $arch in
`echo $arch | grep x86_64`)
	echo -D__SIZEOF_POINTER__=8 -m64
	;;
`echo $arch | grep "i[3-6]86"`)
	echo -D__SIZEOF_POINTER__=4 -m32
	;;
*)
	echo '
	Failed to parse your architecture.
	Please run

	$ make check32

	or

	$ make check64

	manually.
	'
	exit 1
;;
esac
