%define _libdir /%{_lib}

Summary: PAM module for auto blacklisting
Name: pam_abl
Version: 0.9.0
Release: 1%{?dist}
License: GPL
Group: System Environment/Base
URL: http://pam-abl.sourceforge.net

Packager: Your Name <your.name@email.net>

Source: pam_abl-0.9.0-Source.tar.gz
BuildRequires: pam-devel, db4-devel, libdb-devel, kyotocabinet-devel, zlib-devel, cmake
Requires: kyotocabinet, db4
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
Provides auto blacklisting of hosts and users responsible for repeated failed
authentication attempts.  Once blacklisted, it will be impossible to
successfully authenticate.  Commands also can be configured to run when
blacklisting is triggered to add firewall rules etc.

A command line tool allows you to manually fail, unblock and query users or
hosts in the database.

%prep
%setup -n %{name}-%{version}-Source

%build
cmake -DCMAKE_BUILD_TYPE=Debug .
make VERBOSE=1

%install
install -Dp -m0755 pam_abl.so %{buildroot}%{_libdir}/security/pam_abl.so
install -Dp -m0755 pam_abl_bdb.so %{buildroot}%{_libdir}/security/pam_abl_bdb.so
install -Dp -m0755 pam_abl_kc.so %{buildroot}%{_libdir}/security/pam_abl_kc.so
install -Dp -m0644 conf/pam_abl.conf %{buildroot}%{_sysconfdir}/security/pam_abl.conf
install -Dp -m0755 pam_abl %{buildroot}%{_sbindir}/pam_abl
install -Dp -m0755 doc/pam_abl.conf.5 %{buildroot}%{_mandir}/man5/pam_abl.conf.5
install -Dp -m0755 doc/pam_abl.1 %{buildroot}%{_mandir}/man1/pam_abl.1
install -Dp -m0755 doc/pam_abl.8 %{buildroot}%{_mandir}/man8/pam_abl.8


%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%config(noreplace) %{_sysconfdir}/security/pam_abl.conf
%{_libdir}/security/pam_abl.so
%{_libdir}/security/pam_abl_bdb.so
%{_libdir}/security/pam_abl_kc.so
%{_sbindir}/pam_abl
%doc %{_mandir}/man5/pam_abl.conf.5*
%doc %{_mandir}/man1/pam_abl.1*
%doc %{_mandir}/man8/pam_abl.8*

