#!/bin/sh

# Copyright (C) 2014 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "***********************************************"
echo "This test will use a radius server on localhost"
echo "and which can be executed with run-server.sh   "
echo "***********************************************"

TMPFILE=tmp.out

if test -z "$SERVER_IP";then
	echo "the variable SERVER_IP is not defined"
	exit 77
fi

sed 's/localhost/127.1.1.1:9999,'$SERVER_IP'/g' <$srcdir/radiusclient.conf >radiusclient-temp.conf
sed 's/localhost/'$SERVER_IP'/g' <$srcdir/servers >servers-temp

../src/radiusclient -D -i -f radiusclient-temp.conf  User-Name=test Password=test | tee $TMPFILE
if test $? != 0;then
	echo "Error in PAP auth"
	exit 1
fi

grep "^Framed-Protocol                  = 'PPP'$" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in data received by server (Framed-Protocol)"
	cat $TMPFILE
	exit 1
fi

grep "^Framed-IP-Address                = '192.168.1.190'$" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in data received by server (Framed-IP-Address)"
	cat $TMPFILE
	exit 1
fi

grep "^Framed-Route                     = '192.168.100.5/24'$" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in data received by server (Framed-Route)"
	cat $TMPFILE
	exit 1
fi

grep "^Request-Info-Secret = testing123$" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in request info data (secret)"
	cat $TMPFILE
	exit 1
fi

grep "^Request-Info-Vector = " $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in request info data (vector)"
	cat $TMPFILE
	exit 1
fi

rm -f servers-temp
#cat $TMPFILE
rm -f $TMPFILE
rm -f radiusclient-temp.conf

exit 0
