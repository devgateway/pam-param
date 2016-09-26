Name:           pam_param
Version:        0.1
Release:        1
License:        GPLv3
Vendor:         Development Gateway
Summary:        PAM module for configurable LDAP account lookups
Source:         %name.zip
Source1:        inih.zip
#BuildRequires:  cmake >= 2.8

%package test
Summary:        Test utility for %name PAM module

%description
This PAM module provides account service using configurable LDAP lookups. It's
designed to look up role-based permissions in LDAP. It will determine DNs of
the user and current host, then search for entries which have these DNs in
their attributes, e.g. member. It also allows defining a search for super admin
accounts which will have access to any host.

%description test
Account facility test utility for %name PAM module.

%define _pamlibdir %{_libdir}
%define _secconfdir %{_sysconfdir}/security
%define _pamconfdir %{_sysconfdir}/pam.d

%prep
%setup -n %name
%setup -D -T -a 1 -n %name

%build
cmake \
	-DMODULEDIR:PATH=%{_pamlibdir} \
	-DSBINDIR:PATH=%_sbindir \
	-DSECCONFDIR:PATH=%{_secconfdir} \
	-DPAMCONFDIR:PATH=%{_pamconfdir} \
	.
make

%install
make DESTDIR=%buildroot install

%files
%{_pamlibdir}
%config %attr(0600,-,-) %{_secconfdir}/%name.ini

%files test
%_sbindir
%config %{_pamconfdir}/%{name}_test

%clean
rm -rf %_buildrootdir
