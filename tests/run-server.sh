#!/bin/sh
#
# Copyright (C) 2015 Red Hat
#
#   Copyright (c) 2014 Red Hat, Inc.
#   
#   All rights reserved.
#   
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#   1. Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#   2. Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#   
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
#   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#   ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
#   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.

srcdir=${srcdir:-.}

#this test can only be run as root
id|grep root >/dev/null 2>&1
if [ $? != 0 ];then
	exit 77
fi

CONFIG="radius"
IMAGE=radius-test
IMAGE_NAME=test_radius
DOCKER_DIR=docker
TMP=$IMAGE_NAME.tmp

if test -x /usr/bin/docker;then
DOCKER=/usr/bin/docker
else
DOCKER=/usr/bin/docker.io
fi

if ! test -x $DOCKER;then
	echo "The docker program is needed to perform this test"
	exit 77
fi

stop() {
	$DOCKER stop $IMAGE_NAME
	$DOCKER rm $IMAGE_NAME
	exit 1
}

if test "$1" = "stop";then
	stop
fi

$DOCKER stop $IMAGE_NAME >/dev/null 2>&1
$DOCKER rm $IMAGE_NAME >/dev/null 2>&1

rm -f $DOCKER_DIR/Dockerfile

$DOCKER pull fedora:21
if test $? != 0;then
	echo "Cannot pull docker image"
	$UNLOCKFILE
	exit 1
fi

cp $DOCKER_DIR/Dockerfile-$CONFIG $DOCKER_DIR/Dockerfile

if test ! -f $DOCKER_DIR/Dockerfile;then
	echo "Cannot test in this system"
	$UNLOCKFILE
	exit 77
fi

echo "Creating image $IMAGE"
$DOCKER build -t $IMAGE $DOCKER_DIR/
if test $? != 0;then
	echo "Cannot build docker image"
	exit 1
fi

$DOCKER run -P --privileged=true --tty=false -d --name test_radius $IMAGE
if test $? != 0;then
	echo "Cannot run docker image"
	exit 1
fi

IP=`$DOCKER inspect $IMAGE_NAME | grep IPAddress | cut -d '"' -f 4`
if test -z "$IP";then
	echo "Detected IP is null!"
	stop
fi
echo "$IP"

exit 0
