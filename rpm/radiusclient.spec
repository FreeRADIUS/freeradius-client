%define name	radiusclient
%define ver		0.3.3
%define rel		0

Summary:	A portable, easy-to-use and standard compliant library for RADIUS protocol (RFCs 2128 and 2139).
Name:		%name
Version:	%ver
Release:	%rel
License:	BSD License
Group:		Applications/Internet
Packager:	Daniel Mierla <mierla@fokus.fraunhofer.de>
Vendor:		iptel.org, http://www.iptel.org
URL:		http://download.berlios.de/radiusclient-ng
Source:		http://download.berlios.de/radiusclient-ng/radiusclient-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-root
Conflicts:	radiusclient-devel < %ver
Prefix:		%{_prefix}

%description
A portable, easy-to-use and standard compliant library suitable for developing free and commercial software that need support for a RADIUS protocol (RFCs 2128 and 2139). This is the next generation of radius client libarary you may find at http://www.cityline.net/~lf/radius/ and seems to be no longer maintaned.

%package devel
Summary:	Header files, libraries and development documentation for %{name}.
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}

%description devel
This package contains the header files, static libraries and development
documentation for %{name}. You need to install %{name}-devel if you want to develop applications using %{name}.

%prep
%setup

%build
%configure
make

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}
%makeinstall pkgsysconfdir="%{buildroot}%{_sysconfdir}/%{name}"

rm -f %{buildroot}%{_libdir}/*.la

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%files
%defattr(-, root, root)
%doc README README.radexample CHANGES COPYRIGHT BUGS doc/instop.html
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/
%{_sbindir}/*
%{_libdir}/*.so.*

%files devel
%defattr(-, root, root)
%{_libdir}/*.a
%{_libdir}/*.so
%{_includedir}/*.h

%changelog
* Tue Dec 01 2003 Daniel Mierla <mierla@fokus.fraunhofer.de>
- First version of the spec file
