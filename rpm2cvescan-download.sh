#!/bin/sh

# download the files

#/usr/bin/wget -N "https://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml"
/usr/bin/wget -N "https://www.redhat.com/security/data/metrics/rpm-to-cve.xml"
/usr/bin/wget -N "https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL5.xml"
/usr/bin/wget -N "https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL6.xml"
/usr/bin/wget -N "https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml"
/usr/bin/wget -N "https://www.redhat.com/security/data/metrics/rhsamapcpe.txt"
/usr/bin/wget -N "https://www.redhat.com/security/data/metrics/cve_dates.txt"

