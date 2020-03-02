# Copyright 2016-2017 Development Gateway, Inc
# This file is part of pam_param, see COPYING
%define esc_sha  5795e78c34b7720aee938806c3606defcb0711de
%define inih_sha 0ee2bf26abccc63ee0a5a416ed9cdf4d113d8c25
%define module_name pam_param

Name:           pam-param
Version:        0.3
Release:        %{rel}%{!?rel:1}
License:        GPLv3
Vendor:         Development Gateway
Summary:        PAM module for configurable LDAP account lookups
Source:         https://github.com/devgateway/pam-param/archive/v%{version}.tar.gz
Source1:        https://github.com/benhoyt/inih/archive/%{inih_sha}.tar.gz
Source2:        https://github.com/devgateway/ldapescape/archive/%{esc_sha}.tar.gz
BuildRequires:  cmake >= 2.8.11, make, gcc, openldap-devel, pam-devel

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

%define _secconfdir %{_sysconfdir}/security
%define _pamconfdir %{_sysconfdir}/pam.d

%prep
%setup
gzip -dc "%SOURCE1" | tar -C inih -xvvf - --strip-components=1
gzip -dc "%SOURCE2" | tar -C ldapescape -xvvf - --strip-components=1

%build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .
make

%install
make DESTDIR=%buildroot install
mkdir -p %buildroot%{_secconfdir}
install -m 0660 samples/pam_param.ini %buildroot%{_secconfdir}/
mkdir -p %buildroot%{_pamconfdir}
install -m 0644 samples/pam_param_test.pam %buildroot%{_pamconfdir}/pam_param_test

%files
%{_libdir}/security/*
%{_mandir}/man*/*
%config %attr(0600,-,-) %{_secconfdir}/%{module_name}.ini
%doc COPYING

%files test
%{_sbindir}/*
%config %{_pamconfdir}/%{module_name}_test

%clean
rm -rf %{_buildrootdir}
