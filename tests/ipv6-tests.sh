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

if test -z "$SERVER_IP6";then
	echo "the variable SERVER_IP6 is not defined"
	exit 77
fi

sed 's/::1/'$SERVER_IP6'/g' <$srcdir/radiusclient-ipv6.conf >radiusclient-temp.conf 
sed 's/::1/'$SERVER_IP6'/g' <$srcdir/servers-ipv6 >servers-ipv6-temp

../src/radiusclient -f radiusclient-temp.conf  User-Name=test6 Password=test >$TMPFILE
if test $? != 0;then
	echo "Error in PAP IPv6 auth"
	exit 1
fi

grep "^Framed-IPv6-Prefix               = '2000:0:0:106::/64'$" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in data received by server (Framed-IPv6-Prefix)"
	cat $TMPFILE
	exit 1
fi

rm -f servers-temp 
rm -f $TMPFILE
rm -f radiusclient-temp.conf

exit 0
