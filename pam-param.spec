Name:           pam_param
Version:        0.1
License:        GPLv3
Vendor:         Development Gateway
Summary:        PAM module for configurable LDAP account lookups
Source:         %name.tgz
BuildRequires:  cmake >= 2.8

%define _pamlibdir %{_libdir}
%define _secconfdir %{_sysconfdir}/security
%define _pamconfdir %{_sysconfdir}/pam.d

%description
This PAM module provides account service using configurable LDAP lookups. It's
designed to look up role-based permissions in LDAP. It will determine DNs of
the user and current host, then search for entries which have these DNs in
their attributes, e.g. member. It also allows defining a search for super admin
accounts which will have access to any host.

%prep
%setup -n %name

%build
%__cmake \
	-DMODULEDIR:PATH=%{_pamlibdir} \
	-DLIBEXECDIR:PATH=%_libexecdir \
	-DSECCONFDIR:PATH=%{_secconfdir} \
	-DPAMCONFDIR:PATH=%{_pamconfdir} \
	.
%__make

%install
%__make DESTDIR=%_buildrootdir install

%files

%clean
rm -rf %_buildrootdir
