# Copyright 2016 Development Gateway, Inc
# This file is part of pam_param, see COPYING
%define esc_sha  ed4d4e107cc2279858818005b684f4f1b17e86d6
%define inih_sha f5609c8eae118fc3053c2fe3d02c023c8f0d176c

Name:           pam-param
Version:        0.2
Release:        %{rel}%{!?rel:1}
License:        GPLv3
Vendor:         Development Gateway
Summary:        PAM module for configurable LDAP account lookups
Source:         https://github.com/devgateway/pam-param/archive/v%{version}.tar.gz
Source1:        https://github.com/benhoyt/inih/archive/%{inih_sha}.tar.gz
Source2:        https://github.com/devgateway/ldapescape/archive/%{esc_sha}.tar.gz
#BuildRequires:  cmake >= 2.8.11

%package test
Summary:        Test utility for %name PAM module
Requires:       %name

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
%setup
gzip -dc "%SOURCE1" | tar -C inih -xvvf - --strip-components=1
gzip -dc "%SOURCE2" | tar -C ldapescape -xvvf - --strip-components=1

%build
cmake \
	-DCONFIGFILE:FILE=%{_secconfdir}/%name.ini \
	-DMODULEDIR:PATH=%{_moduledir} \
	-DSBINDIR:PATH=%_sbindir \
	-DCMAKE_BUILD_TYPE=RelWithDebInfo \
	.
make

%install
make DESTDIR=%buildroot install
mkdir -p %buildroot%{_secconfdir}
install -m 0660 samples/pam_param.ini %buildroot%{_secconfdir}/
mkdir -p %buildroot%{_pamconfdir}
install -m 0644 samples/pam_param_test.pamd %buildroot%{_pamconfdir}/pam_param_test

%files
%{_moduledir}/*
%_mandir/man*/*
%config %attr(0600,-,-) %{_secconfdir}/%name.ini
%doc COPYING

%files test
%_sbindir/*
%config %{_pamconfdir}/%{name}_test

%clean
rm -rf %_buildrootdir
