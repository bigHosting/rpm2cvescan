#!/usr/bin/perl

use warnings;
use strict;

use RPM4;

#RPM4::rpmvercmp("1mdk", "1mdk") ==  0, "rpmvercmp with =");
#ok(RPM4::rpmvercmp("1mdk", "2mdk") == -1, "rpmvercmp with <");
#ok(RPM4::rpmvercmp("2mdk", "1mdk") ==  1, "rpmvercmp with >");

#perl cmp1.pl kernel-4.18.1 kernel-4.18.2

my $pkg_v1 = 'kernel-4.18.1';
my $pkg_v2 = 'kernel-4.18.2';


my $ret = rpmvercmp($pkg_v1, $pkg_v2);
print "RPM ver cmp: $ret\n";

if ( $ret eq '-1' )
{
         print "\n=====  $pkg_v1  (upgrade to $pkg_v2) =====\n";
}
