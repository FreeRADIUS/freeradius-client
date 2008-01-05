Summary:        FreeRADIUS Client Software
Name:		freeradius-client-snapshot
Version:	1.1.6
Release:	0
Obsoletes:      radiusc radiusclient radiusclient-ng
Group:          Productivity/Networking/Radius/Clients
License:	Artistic License
Packager:	Peter Nixon
URL:		http://www.freeradius.org/
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Prefix:		%{_prefix}
Requires:	%{name}-libs = %{version}-%{release}

%description
A portable, easy-to-use and standard compliant library suitable for developing free and commercial software that need support for a RADIUS protocol (RFCs 2128 and 2139). 

%package libs
Summary:	A portable, easy-to-use and standard compliant library for RADIUS protocol (RFCs 2128 and 2139).
Group:          Development/Libraries

%description libs
The package contains the shared library of FreeRADIUS Client

%package devel
Summary:	Header files, libraries and development documentation for %{name}.
Group:		Development/Libraries
Requires:	%{name}-libs = %{version}-%{release}

%description devel
This package contains the header files, static libraries and development
documentation for %{name}. You need to install %{name}-devel if you want to develop applications using %{name}.

%if 0%{?suse_version} > 930
%debug_package
%endif

%prep
%setup -q

%build
%define localstatedir /var/lib
rm missing
%if 0%{?suse_version} > 900
%{suse_update_config -f}
%endif
libtoolize --force
aclocal
automake -ac
autoconf
CFLAGS="$RPM_OPT_FLAGS -Wall" \
CXXFLAGS="$RPM_OPT_FLAGS -Wall -fmessage-length=0" \
        %configure \
        --localstatedir=%{localstatedir} \
        --enable-shadow \
        --with-secure-path

make

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}
make "DESTDIR=$RPM_BUILD_ROOT" install
rm -f $RPM_BUILD_ROOT/%{_sbindir}/login.radius
rm -f login.radius/Makefile*
rm -f login.radius/migs/Makefile*

rm -f %{buildroot}%{_libdir}/*.la

%post
%{run_ldconfig}

%postun
%{run_ldconfig}

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%files
%defattr(-, root, root)
%doc doc/* BUGS COPYRIGHT README README.radexample
%dir %{_sysconfdir}/radiusclient
%{_sysconfdir}/radiusclient/dictionary
%{_sysconfdir}/radiusclient/dictionary.*
%config(noreplace) %{_sysconfdir}/radiusclient/radiusclient.conf
%config(noreplace) %{_sysconfdir}/radiusclient/issue
%config(noreplace) %{_sysconfdir}/radiusclient/port-id-map
%config(noreplace) %{_sysconfdir}/radiusclient/servers
%{_sbindir}/*

%files libs
%defattr(-, root, root)
%{_libdir}/*.so.*
%{_libdir}/*.so

%files devel
%defattr(-, root, root)
%{_libdir}/*.a
%{_includedir}/*.h

%changelog
* Sun Jan 06 2008 Peter Nixon
- Update to match upcoming freeradius-client release
* Sun Nov 19 2006 Peter Nixon
- Converted spec from radiusclient package to work with FreeRADIUS Client
- Split out separate -devel and -libs packages
* Wed Jan 25 2006 - mls@suse.de
- converted neededforbuild to BuildRequires
* Thu Nov 18 2004 - ro@suse.de
- fixed file list
* Sat Jan 10 2004 - adrian@suse.de
- add %%defattr
* Thu Jul 31 2003 - mjancar@suse.cz
- use %%run_ldconfig
* Thu May 29 2003 - mjancar@suse.cz
- remove Makefiles from documentation
* Wed May 28 2003 - mjancar@suse.cz
- update to 0.3.2
- move localstatedir to /var/lib
- remove unpackaged files from buildroot
* Wed Apr 02 2003 - ro@suse.de
- fixed patch radiusclient-0.3.1-fix.dif
* Tue Apr 02 2002 - postadal@suse.cz
- fixed to compile with autoconf-2.53
* Wed Mar 20 2002 - postadal@suse.cz
- secfix (VU#589523 -buffer overflow in the function that calculates message digests)
- fixed login.expamle, README.SuSE
* Thu Jan 10 2002 - cihlar@suse.cz
- use %%{_libdir}
* Tue Nov 06 2001 - cihlar@suse.cz
- fixed to compile with automake 1.5
* Wed Jun 06 2001 - cihlar@suse.cz
- fixed to compile with new libtool
* Mon Mar 26 2001 - cihlar@suse.cz
- moved whole files from dif
- fixed to compile
* Wed Nov 29 2000 - smid@suse.cz
- renamed: raduisc => radiusclient
* Wed May 24 2000 - cihlar@suse.cz
- fixed to compile
- added BuildRoot
* Sun Apr 09 2000 - bk@suse.de
- added suse update config macro
* Mon Sep 13 1999 - bs@suse.de
- ran old prepare_spec on spec file to switch to new prepare_spec.
* Thu Jun 10 1999 - kukuk@suse.de
- Remove %%dir for doc tree
* Sun Mar 01 1998 - tmg@suse.de
- README.SuSE again
* Tue Feb 10 1998 - tmg@suse.de
- initial spec file
- fixed paths in radiusclient.conf
- login.example - simplistic example login.radius script
- README.SuSE
