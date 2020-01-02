#!/usr/bin/perl

use warnings;
use strict;

my $pkg_v1 = 'kernel-4.18.1';
my $pkg_v2 = 'kernel-4.18.2';

my $cmd = sprintf ("./rpmvercmp.el8 %s %s '>'", $pkg_v1, $pkg_v2);
system($cmd);

if ($? == 256)
{
         print "\n=====  $pkg_v1  (upgrade to $pkg_v2) =====\n";
}
