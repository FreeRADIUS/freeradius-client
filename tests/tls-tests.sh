#!/bin/sh

# Copyright (C) 2014 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"
TMPFILE=tmp.out

echo "***********************************************"
echo "This test will use a radius-tls server on localhost"
echo "and which can be executed with run-server.sh   "
echo "***********************************************"


if test -z "$SERVER_IP";then
	echo "the variable SERVER_IP is not defined"
	exit 77
fi

sed 's/localhost/'$SERVER_IP'/g' <$srcdir/dtls/radiusclient-tls.conf >radiusclient-tls-temp.conf 
sed 's/localhost/'$SERVER_IP'/g' <$srcdir/servers >servers-tls-temp

# Test whether a TLS session will succeed
../src/radiusclient -f radiusclient-tls-temp.conf  User-Name=test Password=test >$TMPFILE
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

# Test whether a TLS invalidated session for some reason will reconnect
./tls-restart -f radiusclient-tls-temp.conf  User-Name=test Password=test >$TMPFILE
if test $? != 0;then
	echo "Error in session restart"
	exit 1
fi

rm -f $TMPFILE
rm -f servers-tls-temp radiusclient-tls-temp.conf
exit 0
