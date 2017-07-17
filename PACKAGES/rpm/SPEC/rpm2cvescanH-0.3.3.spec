%define debug_package %{nil}
Name: rpm2cvescanH
Version: 0.3
Release: 3.el6
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
mkdir -p $RPM_BUILD_ROOT/localservices/rpm2cvescanH
mkdir -p $RPM_BUILD_ROOT/etc/cron.d

install -m 0700 rpm2cvescanH.pl $RPM_BUILD_ROOT/localservices/rpm2cvescanH/rpm2cvescanH.pl
install -m 0700 rpm2cvescanH-download.sh $RPM_BUILD_ROOT/localservices/rpm2cvescanH/rpm2cvescanH-download.sh
install -m 0700 rpmvercmp.el6 $RPM_BUILD_ROOT/localservices/rpm2cvescanH/rpmvercmp.el6
install -m 0700 rpm2cvescanH.crond $RPM_BUILD_ROOT/etc/cron.d/rpm2cvescanH

%files
%defattr(-,root,root)
%doc README
%attr(0700,root,root) /localservices/rpm2cvescanH/rpm2cvescanH.pl
%attr(0700,root,root) /localservices/rpm2cvescanH/rpm2cvescanH-download.sh
#%attr(0700,root,root) /localservices/rpm2cvescanH/rpmvercmp.el5
%attr(0700,root,root) /localservices/rpm2cvescanH/rpmvercmp.el6
#%attr(0700,root,root) /localservices/rpm2cvescanH/rpmvercmp.el7
%attr(0600,root,root) /etc/cron.d/rpm2cvescanH

%clean
rm -rf $RPM_BUILD_ROOT

%pre

%post

%preun

%postun

%posttrans

%changelog
* Mon Jul 17 2017 SecurityGuy <securityteam@fakedomain.com> -1
- Initial build
