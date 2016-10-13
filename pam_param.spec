Name:           pam_param
Version:        0.1
Release:        %{?!rel:1}
License:        GPLv3
Vendor:         Development Gateway
Summary:        PAM module for configurable LDAP account lookups
Source:         %name.zip
Source1:        inih.zip
BuildRequires:  cmake >= 2.8.11

%package test
Summary:        Test utility for %name PAM module
Requires:				%name

%description
This PAM module provides account service using configurable LDAP lookups. It's
designed to look up role-based permissions in LDAP. It will determine DNs of
the user and current host, then search for entries which have these DNs in
their attributes, e.g. member. It also allows defining a search for super admin
accounts which will have access to any host.

%description test
Account facility test utility for %name PAM module.

%define _moduledir %{_libdir}/security
%define _secconfdir %{_sysconfdir}/security
%define _pamconfdir %{_sysconfdir}/pam.d

%prep
%setup -n %name
%setup -D -T -a 1 -n %name

%build
cmake \
	-DCONFIGFILE:FILE=%{_secconfdir}/%name.ini \
	-DMODULEDIR:PATH=%{_moduledir} \
	-DSBINDIR:PATH=%_sbindir \
	-DSECCONFDIR:PATH=%{_secconfdir} \
	-DPAMCONFDIR:PATH=%{_pamconfdir} \
	-DCMAKE_BUILD_TYPE=RelWithDebInfo \
	.
make

%install
make DESTDIR=%buildroot install

%files
%{_moduledir}/*
%config %attr(0600,-,-) %{_secconfdir}/%name.ini
%doc LICENSE-php

%files test
%_sbindir/*
%config %{_pamconfdir}/%{name}_test

%clean
rm -rf %_buildrootdir
