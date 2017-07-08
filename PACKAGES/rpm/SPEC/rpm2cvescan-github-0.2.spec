%define debug_package %{nil}
Name: rpm2cvescan
Version: 0.2
Release: 1.el6
Summary: RPM to cve/rhsa scanner
Packager: SecurityGuy <securityguy@fakedomain.com>
Group: Applications/System
License: GPLv2
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: rpm, perl-XML-Simple
BuildRequires: rpm-build
URL: https://github.com/bigHosting/rpm2cvescan

%description
Report what RHEL/CentOS 5/6/7 packages are vulnerable based on 'rpm -qa'

%prep
%setup -q

%build

%install
mkdir -p $RPM_BUILD_ROOT/usr/local/bin

install -m 0700 rpm2cvescan.pl $RPM_BUILD_ROOT/usr/local/bin/rpm2cvescan.pl
install -m 0700 rpm2cvescan-download.sh $RPM_BUILD_ROOT/usr/local/bin/rpm2cvescan-download.sh
install -m 0700 rpmvercmp.el6 $RPM_BUILD_ROOT/usr/local/bin/rpmvercmp.el6
install -m 0700 rpmvercmp.el7 $RPM_BUILD_ROOT/usr/local/bin/rpmvercmp.el7

%files
%defattr(-,root,root)
%doc README
%attr(0700,root,root) /usr/local/bin/rpm2cvescan.pl
%attr(0700,root,root) /usr/local/bin/rpm2cvescan-download.sh
%attr(0700,root,root) /usr/local/bin/rpmvercmp.el6
%attr(0700,root,root) /usr/local/bin/rpmvercmp.el7

%clean
rm -rf $RPM_BUILD_ROOT

%pre

%post

%preun

%postun

%posttrans

%changelog
* Fri Jul 7 2017 SecurityGuy <securityteam@fakedomain.com> -2
- Added support for el5/el7
* Fri May 1 2017 SecurityGuy <securityteam@fakedomain.com> -1
- Initial build
