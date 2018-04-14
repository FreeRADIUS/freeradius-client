#!/bin/sh
#
# License: 2-clause BSD
#
# Copyright (c) 2016, Martin Belanger <Martin_Belanger@dell.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the FreeBSD Project.


srcdir="${srcdir:-.}"

echo "***********************************************"
echo "This test will use a radius server on localhost"
echo "and which can be executed with run-server.sh   "
echo "The test sends a basic EAP message and expects "
echo "an Acess-Challenge response. The test does not "
echo "go beyond this point as there is no real EAP   "
echo "service capable of handling a full EAP request "
echo "***********************************************"

TMPFILE=tmp$$.out

if test -z "$SERVER_IP";then
	echo "the variable SERVER_IP is not defined"
	exit 77
fi

sed 's/localhost/'$SERVER_IP'/g' <$srcdir/radiusclient.conf >radiusclient-temp.conf
sed 's/localhost/'$SERVER_IP'/g' <$srcdir/servers >servers-temp


# NOTE: The string 2:0:0:9:1:74:65:73:74 is equivalent to defining a C array as
#       follows:
#           uint8_t eap_msg[] = { 2, 0, 0, 9, 1, 't', 'e', 's', 't' };
#
#       which corresponds to this EAP message:
#           Code       = 2       (8-bit)  -> 2 for Response
#           Identifier = 0       (8-bit)
#           Length     = 9       (16-bit)
#           Type       = 1       (8-bit)  -> 1 for Identity
#           Data       = "test"  (string)

../src/radiusclient -f radiusclient-temp.conf -e 2:0:0:9:1:74:65:73:74 User-Name=test Password=test >$TMPFILE
if test $? != 0;then
	echo "Error in PAP auth"
	exit 1
fi

grep "^EAP-Message                      = " $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in data received by server (EAP-Message)"
	cat $TMPFILE
	exit 1
fi

grep "^Message-Authenticator            =" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in data received by server (Message-Authenticator)"
	cat $TMPFILE
	exit 1
fi

grep "^State                            =" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in data received by server (State)"
	cat $TMPFILE
	exit 1
fi

rm -f servers-temp
#cat $TMPFILE
rm -f $TMPFILE
rm -f radiusclient-temp.conf

exit 0
