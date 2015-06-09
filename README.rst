The radcli library
==================

0. BRANCH STATE
---------------
|BuildStatus|_

.. |BuildStatus| image:: https://travis-ci.org/radcli/radcli.png
.. _BuildStatus: https://travis-ci.org/radcli/radcli


1. INTRODUCTION
---------------
The radcli library is a library for writing RADIUS Clients. The library's
approach is to allow writing RADIUS-aware application in less than 50 lines
of C code. It was based originally on freeradius-client and is source
compatible with it.

For the development of the openconnect VPN server, I needed a simple library to
allow using radius for authentication and accounting without having to understand
the internals of radius. Such library was the freeradius-client library, but
it had too much legacy code centered around radlogin, a tool which is of no
significance today, was IPv4-only and had no releases for several years.
This library addresses these shortcomings, adds package management via
pkg-config, adds support for TLS and DTLS, provides documentation of the API,
and will include any new features for the task. It is provided as a shared
library in case it is useful to other projects as well, and is also made source
compatible with radiusclient-ng and freeradius-client.


2. Documentation
----------------

Documentation and examples are available at:
http://radcli.github.io/radcli/

3. Bug reporting
----------------

Please use the issue tracker at:
https://github.com/radcli/radcli/issues
