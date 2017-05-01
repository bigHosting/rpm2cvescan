#!/bin/sh

# download the files

#/usr/bin/wget -N "https://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml"
/usr/bin/wget -N "https://www.redhat.com/security/data/metrics/rpm-to-cve.xml"
/usr/bin/wget -N "https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL6.xml"
/usr/bin/wget -N "https://www.redhat.com/security/data/metrics/rhsamapcpe.txt"

