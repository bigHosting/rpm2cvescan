%define debug_package %{nil}
Name: rpm2cvescan
Version: 0.1
Release: 1
Summary: RPM to cve/rhsa scanner
Packager: SecurityGuy <securityguy@fakedomain.com>
Group: Applications/System
License: GPLv2
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: rpm, perl-XML-Simple
BuildRequires: rpm-build

%description
Report what RHEL6/CentOS packages are vulnerable based on 'rpm -qa'

%prep
%setup -q

%build

%install
mkdir -p $RPM_BUILD_ROOT/usr/local/bin

install -m 0700 rpm2cvescan.pl $RPM_BUILD_ROOT/usr/local/bin/rpm2cvescan.pl
install -m 0700 rpm2cvescan-download.sh $RPM_BUILD_ROOT/usr/local/bin/rpm2cvescan-download.sh
install -m 0700 rpmvercmp $RPM_BUILD_ROOT/usr/local/bin/rpmvercmp

%files
%defattr(-,root,root)
%doc README
%attr(0700,root,root) /usr/local/bin/rpm2cvescan.pl
%attr(0700,root,root) /usr/local/bin/rpm2cvescan-download.sh
%attr(0700,root,root) /usr/local/bin/rpmvercmp
%clean
rm -rf $RPM_BUILD_ROOT

%pre

%post

%preun

%postun

%posttrans

%changelog
* Fri May 1 2017 SecurityGuy <securityteam@fakedomain.com> -1
- Initial build

