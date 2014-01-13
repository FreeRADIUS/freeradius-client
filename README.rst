The FreeRADIUS client
=====================

0. BRANCH STATE
---------------
|BuildStatus|_

.. |BuildStatus| image:: https://travis-ci.org/FreeRADIUS/freeradius-client.png
.. _BuildStatus: https://travis-ci.org/FreeRADIUS/freeradius-client

1. INTRODUCTION
---------------
FreeRADIUS Client is a framework and library for writing RADIUS Clients
which additionally includes radlogin, a flexible RADIUS aware login
replacement, a command line program to send RADIUS accounting records
and a utility to query the status of a (Merit) RADIUS server.

All these programs are based on a library which lets you develop a 
RADIUS-aware application in less than 50 lines of C code.

The most current documentation is available online at:
	http://wiki.freeradius.org/project/Radiusclient

It is highly portable and runs on Linux, many BSD variants and Solaris.

FreeRADIUS Client is known to compile on the following platforms:

- Compiled on:
   * i386-pc-bsdi2.1
   * sparc-unknown-netbsd1.2.1
   * i386-unknown-freebsd2.2.6
	
- Compiled and tested on:
   * x86 Linux
   * x86_64 Linux
   * sparc-sun-solaris2.5.1

2. Security note
----------------
This code has not yet been fully audited by the FreeRADIUS project, as it
has only recently been adopted by the FreeRADIUS project to continue 
development and support.  Any security related issues should be reported 
to the project either via email:

security at freeradius dot org

or via the FreeRADIUS bugtracker:

http://bugs.freeradius.org/

As is the case with any open-source project, patches in addition to
bug reports are always welcome.

Additional Security related information on the FreeRADIUS project:

http://www.freeradius.org/security.html
