#!/bin/sh

touch config.rpath && autoreconf -fvi && ./configure --with-tls
