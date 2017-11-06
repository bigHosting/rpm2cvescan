#!/usr/bin/perl

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

#
# (c) SecurityGuy
#

# CHANGELOG:
#    2017.11.02 - dbus-glib-0:0.86-6.el6_4 om RH is in fact dbus-glib-0:0.86-6.el6 on CentOS
#    2017.10.31 - removed '.centos' packages as our main CVE source is RedHat, we will skip the following packages on CentOS:
#                 abrt*
#                 initscripts*
#                 ntp*
#                 yum*
#    2017.08.01 - added support showing only one package ( --show-only=openssl )
#    2017.07.07 - added support for el5 & el7
#    2017.06.12 - added exclude list
#    2017.05.02 - added hostname to csv output
#               - added cmdline options
#               - add scanID
#    2017.05.01 - added CVE2DATE to csv output
#    2017.04.30 - added CVE2RHSA info
#    2017.04.25 - fixed a bug in reporting
#    2017.04.22 - initial release

# USAGE:
#    perl $0  [--json]  [--csv]  [--debug]
#
#    perl $0 -j
#    perl $0 --debug --json --exclude=bash --exclude=php
#    perl $0 --debug --json --show-only=openssl
#
#


use strict;
use warnings;

# check if modules exist
eval { require XML::Simple; };
if ($@) { die "[*]: $0: ERROR: require module XML::Simple: can't load module $@\n on CentOS: yum install perl-XML-Simple";}

eval { require utf8; };
if ($@) { die "[*]: $0: ERROR: require module utf8: can't load module $@\n on CentOS: yum install perl-utf8-all";}


use XML::Simple;
use utf8;
#use JSON;
use Data::Dumper 'Dumper';
use Getopt::Long;
#use POSIX qw(strftime);
#use Digest::MD5 qw(md5 md5_hex md5_base64);

$| = 1;

#######################
#####  FUNCTIONS  #####
#######################

# 'uniq' an array of elements
sub uniq {
  my (@input) = @_;
  my %all = ();
  @all{@input} = 1;
  return (keys %all);
}

sub date_info
{
        my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);

        $year += 1900;
        $mon  = sprintf("%02d", $mon+1);
        $mday = sprintf("%02d", $mday);
        $hour = sprintf("%02d", $hour);
        $min  = sprintf("%02d", $min);
        $sec  = sprintf("%02d", $sec);

        my ($datestamp) = '[' . $year ."-" . $mon ."-" . $mday ." " . $hour . ":" . $min .":" . $sec . ']';
        return ($datestamp);
}

#  my @array = file2array("/proc/version");
sub file2array
{
    (my $filename) = @_; 
    my @lines = ( 'unknown' );
    if ( -e -r $filename )
    {
            open FILE,"$filename";
            @lines = <FILE>;
            close FILE;
    }
    return @lines;
}

#############################
#####  cmdline options  #####
#############################
GetOptions( \ my %options,
        'd|debug'   => \ my $debug,
        'c|csv'     => \ my $csv,
        'j|json'    => \ my $json,
        's|show-only=s'  => \ my $showonly,
        'x|exclude=s'    => \ my @excludes,
);



##########################
#####  GLOBAL  VARs  #####
##########################

my $xmlrpm;
my $xmlrhsa;

# stats
my $counter_cve      = 0;
my $counter_pkg      = 0;
my $counter_highrisk = 0;



binmode(STDIN,  ':encoding(utf8)');
binmode(STDOUT, ':encoding(utf8)');
binmode(STDERR, ':encoding(utf8)');

my $hostname = `/bin/hostname -f`;
$hostname =~ s/^\s+|\s+$//g;
$hostname =~ s/\n+//g;

##########################
#####  supported OS  #####
##########################
my %supported = (
        'el5' => 'com.redhat.rhsa-RHEL5.xml',
        'el6' => 'com.redhat.rhsa-RHEL6.xml',
        'el7' => 'com.redhat.rhsa-RHEL7.xml',
);

my %ditro_v = (
        'release 5' => 'el5',
        'release 6' => 'el6',
        'release 7' => 'el7',
);


# running kernel detection
my $kernel    = join '', file2array("/proc/version");
(undef, undef, $kernel) = split(/\s+/,$kernel);
$kernel =~ s/\.x86_64//g;
next if ( length ($kernel) eq 0 );

my $kernel_format = "kernel-0:" . $kernel;
my %kernel_version = (
       one => " kernel",
       two => " kernel-" . $kernel,
);

print "[*] $0 INFO: " . &date_info . " getting distro info\n" if ($debug);
my $distro = `/bin/rpm --nosignature --nodigest -qf /etc/redhat-release --qf '%{N}-%{V}-%{R}'`;

my $cve2score_input = 'NA';
my $distro_version  = 'el6'; # set default

foreach my $entry (keys %supported)
{
        if ( $distro =~ m/$entry/i)
        {
                $cve2score_input = $supported{$entry};
                $distro_version  = $entry;
        }
}


if ($cve2score_input eq 'NA')
{
        print "[*] $0 ERROR: OS not supported\n";
        exit(1);
}


# ScanID =  $(date +"%Y%g%d%H%M"|md5sum|cut -c 1-15)
#my $ScanID = strftime "%Y%g%d%H%M", (localtime(time()) );
#$ScanID    = md5_hex($ScanID);
#$ScanID    = substr($ScanID, 0, 15);


####################################
######  build CVE 2 RHSA hash  #####
####################################
my %CVE2RHSA = ();
my $rhsamapcpe = "rhsamapcpe.txt";
if ( -f -r $rhsamapcpe)
{
        print "\n[*] $0 INFO: " . &date_info . " reading from $rhsamapcpe\n" if ($debug);
        open(RHSA2CVE,"<$rhsamapcpe");
        foreach my $line (<RHSA2CVE>)
        {
                my ($r,$c, undef)=split(' ', $line);
                $c =~ s/CAN-/CVE-/g;
                foreach my $cve (split(',',$c))
                {
                        $CVE2RHSA{$cve} .= $r." ";
                }
        }
        close(RHSA2CVE);
}


#################################
#####  read rpm-to-cve.xml  #####
#################################
my $r = "rpm-to-cve.xml";
if ( ! ( -f -r $r ) )
{
        die ("[*] $0: ERROR: cannot open file $r $!");
}

print "\n[*] $0 INFO: " . &date_info . " reading from $r\n" if ($debug);
# /usr/bin/wget -N "https://www.redhat.com/security/data/metrics/rpm-to-cve.xml"
if (not($xmlrpm = XMLin( $r, ForceArray => ['cve'] )))
{
        die ("[*]: $0: ERROR: XMLin: Could not parse file: $!\n");
}

##############################################################################################################
##### hash format: $rpm2cve{bash-0:4.1.2-48.el6} = ('CVE-2016-0634', 'CVE-2016-7543', 'CVE-2016-9401');  #####
##############################################################################################################
my ( %rpm2cve, %xmlrpmver );
my $counter_rpm2cve = 0;
foreach my $entry ( sort @{$xmlrpm->{'rpm'}} )
{
        # safety checks!
        if (! defined($entry->{'rpm'}) )
        {
                #print "SKIPPING rpm " . Dumper (\$entry);
                next;
        }

        $counter_rpm2cve++;

        # entry name
        my $rpm_name = $entry->{'rpm'};

        # 32 duplicates ?
        #if ( exists ( $rpm2cve{$rpm_name} ))
        #{
        #        print Dumper (\$rpm2cve{$rpm_name});
        #}

        # only look at our distro version
        next if ($rpm_name !~ /$distro_version/);

        my @advisory;
        if ( (defined ($entry->{cve})) && (scalar(@{$entry->{'cve'}}) > 0) )
        {
                # get a sorted list of cves and push it to hash for later processing
                @advisory = ( sort @{$entry->{'cve'}}  );
                push ( @{ $rpm2cve{$rpm_name} }, @advisory );
        }

        # as it turns out there are 211 entries with no CVE but have RHSA
        if ( (!defined ($entry->{cve})) && (defined($entry->{erratum}->{content})) )
        {
                #print  Dumper(\$entry);
                # push the RHSA advisory instead of CVE!
                push (@advisory, $entry->{erratum}->{content});
        }

        # create hash:
        if ( scalar(@advisory) > 0 )
        {
                #print "FOUND ADVISORY $rpm_name @advisory\n";
                push ( @{ $rpm2cve{$rpm_name} }, @advisory);
        }


        #  $xmlrpmver{'gcc-c++-ppc32-0'} => [
        #                       '3.2.3-59',
        #                       '3.2.3-60',
        #                       '3.4.6-11.el4_8.1',
        #                       '3.4.6-8'
        #                     ],
        my ($rpm_ne, $rpm_vr) = split (/:/, $rpm_name);
        push (@{ $xmlrpmver{$rpm_ne} }, $rpm_vr);
        @{ $xmlrpmver{$rpm_ne} } =  &uniq(@{ $xmlrpmver{$rpm_ne} });

}
$xmlrpm=''; # free the mem
print "[*] $0 INFO: " . &date_info . " rpm2cve    " . scalar (keys %rpm2cve)   . ", counted entries " . $counter_rpm2cve . "\n" if ($debug);
print "[*] $0 INFO: " . &date_info . " xmlrpmver  " . scalar (keys %xmlrpmver) . "\n" if ($debug);



print "[*] $0 INFO: " . &date_info . " getting the list of rpms #1: packageslist\n" if ($debug);
my $packagelist = `/bin/rpm --nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}\n'`;
# hash format:  'unzip-0:6.0-5.el6'  =>  'unzip',
my %packages_list = map  { split(/\s+/, $_, 2) } grep { m/\s+/ } split(/\n/, $packagelist);

# exceptions: RH != CentOS
if ( exists ( $packages_list{'dbus-glib-0:0.86-6.el6'} ))
{
        delete $packages_list{'dbus-glib-0:0.86-6.el6'};
        $packages_list{'dbus-glib-0:0.86-6.el6_4'} = 'dbus-glib';
}
if ( exists ( $packages_list{'dbus-glib-devel-0:0.86-6.el6'} ))
{
        delete $packages_list{'dbus-glib-devel-0:0.86-6.el6'};
        $packages_list{'dbus-glib-devel-0:0.86-6.el6_4'} = 'dbus-glib-devel';
}

$counter_pkg = scalar(keys%packages_list);

# remove ^kernel* from the package list
print "[*] $0 INFO: " . &date_info . " removing rpms with '^kernel*' and '.centos' name from packages_list\n" if ($debug);
foreach my $p ( keys %packages_list )
{
        delete $packages_list{$p} if ( $p =~ m/^kernel/ );
        delete $packages_list{$p} if ( $p =~ m/\.centos/ ); # RH does not have centos packages
}

print "[*] $0 INFO: " . &date_info . " adding kernel info to packages_list: key " . $kernel_format . " value " . $kernel_version{one} . "\n" if ($debug);
$packages_list{$kernel_format} = $kernel_version{one};


print "[*] $0 INFO: " . &date_info . " getting the list of rpms #2: packages_nice\n" if ($debug);
$packagelist      = `/bin/rpm --nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}-%{V}-%{R}\n'`;
my %packages_nice = map  { split(/\s+/, $_, 2) } grep { m/\s+/ } split(/\n/, $packagelist);

# exceptions: RH != CentOS
if ( exists ( $packages_nice{'dbus-glib-0:0.86-6.el6'} ))
{
        delete $packages_nice{'dbus-glib-0:0.86-6.el6'};
        $packages_nice{'dbus-glib-0:0.86-6.el6_4'} = 'dbus-glib-0.86-6.el6_4';
}
if ( exists ( $packages_nice{'dbus-glib-devel-0:0.86-6.el6'} ))
{
        delete $packages_nice{'dbus-glib-devel-0:0.86-6.el6'};
        $packages_nice{'dbus-glib-devel-0:0.86-6.el6_4'} = 'dbus-glib-devel0.86-6.el6_4';
}

print "[*] $0 INFO: " . &date_info . " removing rpms with '^kernel*' and '.centos' name from packages_nice\n" if ($debug);
# remove ^kernel* from the package list
foreach my $p ( keys %packages_nice )
{
        delete $packages_nice{$p} if ( $p =~ m/^kernel/ );
        delete $packages_list{$p} if ( $p =~ m/\.centos/ ); # RH does not have centos packages
}
# add kernel version
$packages_nice{$kernel_format} = $kernel_version{two};
print "[*] $0 INFO: " . &date_info . " adding kernel info to packages_nice: key " . $kernel_format . " value " . $kernel_version{two} . "\n" if ($debug);


print "[*] $0 INFO: " . &date_info . " getting a list of installed packages #3: packages_installed\n" if ($debug);
# array format: ('...', '....' )
my @packages_installed = keys %packages_list;
@packages_installed    = sort (&uniq(@packages_installed));


#################################################
#####  read from com.redhat.rhsa-RHELX.xml  #####
#################################################

my %cve2score;
if ( -f -r $cve2score_input )
{
        print "[*] $0 INFO: " . &date_info . " $cve2score_input\n" if ($debug);
        # Open RHSA xml, force cve to be array
        if (not($xmlrhsa = XMLin($cve2score_input,ForceArray => [  'cve' ])))
        {
                die ("[*]: $0: ERROR: XMLin: Could not parse $cve2score_input file: $!\n");
        }

        print "[*] $0 INFO: " . &date_info . " parsing $cve2score_input\n" if ($debug);
        foreach my $rhsa ( sort keys %{ $xmlrhsa->{definitions}->{definition} } )
        {
                # define the entry
                my $entry = $xmlrhsa->{definitions}->{definition}->{$rhsa};

                # CVE info
                if (defined ($entry->{metadata}->{advisory}->{cve}))
                {
                        foreach my $cve ( @{ $entry->{metadata}->{advisory}->{cve} })
                        {
                                if ( (defined ( $cve->{content} )) && (defined ($cve->{cvss2})) )
                                {
                                        next if ( $cve->{content} !~ m/^CVE/i );
                                        my $cve_id   = $cve->{content};
                                        my $score_id = $cve->{cvss2};
                                        my ($score) = ($score_id =~ m{^(\d+(\.\d+)?)});
                                        $cve2score{$cve_id} = $score;
                                }
                        }
                }
        }
}
$xmlrhsa=''; # free the used mem


my %vulnerable_software;

print "[*] $0 INFO: " . &date_info . " looping through the list of installed packages and comparing rpm versions\n" if ($debug);
foreach my $pkg ( @packages_installed )
{
        if ($showonly)
        {
                next if ( $pkg !~ m/$showonly/i );
        }

        my $skip = 0;
        if ( @excludes )
        {
                foreach my $exclude_rpm ( @excludes )
                {
                        if ( $pkg =~ m/$exclude_rpm/i )
                        {
                                $skip = 1;
                                last;
                        }
                }
        }

        next if ($skip == '1');
        # split by ':'
        my ($ne, $vr) = split( /:/, $pkg );

        if ( exists $xmlrpmver{$ne} )
        {
                #print "Comparing $ne   $vr  with  @{ $xmlrpmver{$ne} } \n";
                foreach my $version ( sort(&uniq(@{ $xmlrpmver{$ne} })) )
                {
                        my $pkg_v1 = $packages_nice{$pkg};
                        my $pkg_v2 = $packages_list{$pkg} . "-" . $version;

                        # skip if we compare the same version
                        next if ( $pkg_v1 eq $pkg_v2 );

                        my $cmd = sprintf ("./rpmvercmp.%s %s %s '>'", $distro_version, $pkg_v1, $pkg_v2 );
                        system ($cmd);
                        #print "Command returned: " . $? . "\n";
                        if ($? == 256)
                        {
                                #print "\n=====  $pkg_v1  (upgrade to $pkg_v2) =====\n";
                                #$counter_pkg++;

                                # we need this to pull vulns fixed in the new version that affects older one
                                my $new = $ne . ":" . $version;
                                #print "NEW $new\n";

                                if ( exists ( $rpm2cve{$new} ))
                                {
                                        if ( scalar ( @{ $rpm2cve{"$new"} }) > 0)
                                        {
                                                my @vulns = @{ $rpm2cve{"$new"} };
                                                #print "$pkg_v2 fixes @vulns\n";
                                                foreach my $cve (@vulns)
                                                {
                                                        push ( @{ $vulnerable_software{$pkg_v1} }, $cve);
                                                }
                                        }
                                }
                        }
                }
        }
}


my %CVE2DATE;

print "[*] $0 INFO: " . &date_info . " loading cve_dates in memory\n\n" if ($debug);
if ( -f -r "cve_dates.txt" )
{
        open(CVEDATES,"<cve_dates.txt");
        while(<CVEDATES>)
        {
                s/CAN/CVE/;
                next unless (my ($cve,$data) = m/^(CVE-\d{4}-\d+\S*)\s*(.*)/);
                foreach my $segment (split(/,/,$data))
                {
                        # split by '='
                        my ($name,$value) = split(/=/,$segment);

                        # skip is name is not public as we're interested in public date only
                        next if ( $name !~ m{public}i);

                        # trim date to 8 chars
                        $value = substr($value, 0, 8) if (length ($value) > 8);

                        # assign to hash
                        $CVE2DATE{$cve}=$value;
                }
        }
        close(CVEDATES);
}

# csv format for using grep
my $csv_output  = '';
my $json_output = '';

print "[*] $0 INFO: " . &date_info . " printing the list of vulnerable rpms\n\n" if ($debug);
foreach my $key ( sort keys %vulnerable_software )
{
        print "\n\n=====  $key  =====\n";

        foreach my $cve ( sort (&uniq(@{ $vulnerable_software{$key} })) )
        {

                    my $score = 0;
                    if ( exists ($cve2score{$cve}))
                    {
                            $score = $cve2score{$cve};
                    }

                    my $rhsa = "RHSA N/A";
                    if ( exists ( $CVE2RHSA{$cve}))
                    {
                            $rhsa = $CVE2RHSA{$cve};
                            $rhsa =~ s/\s+$//;
                    }

                    my $date = "DATE N/A";
                    if ( exists ( $CVE2DATE{$cve}))
                    {
                            $date = $CVE2DATE{$cve};
                    }

                    printf  "%-40s%-20s\n", $cve, $score;
                    $counter_cve++;
                    $counter_highrisk++ if ($score > 6.9);

                    if ( $csv )
                    {
                            $csv_output .= sprintf ("VULN,%s,%s,%s,%s,%s,%s,%s\n", $key, $cve, $score, $rhsa, $date, $hostname, $distro);
                    }

                    if ($json)
                    {
                            my %json_data  = ();
                            # build json data
                            $json_data{hService}        = "VULNS";
                            $json_data{vulnPackage}     = $key;
                            $json_data{ScannedHostName} = $hostname;
                            $json_data{vulnDistro}      = $distro;
                            $json_data{vulnCVE}         = $cve;
                            $json_data{vulnCVEDate}     = $date;
                            $json_data{vulnSrcRHSA}     = $rhsa;
                            $json_data{vulnScore}       = $score;
                            #$json_data{ScanID}          = $ScanID;

                            #$json_output .= encode_json (\%json) . "\n";
                            $json_output .=  "{" . join (", ", map {join (":", '"' . "$_" . '"', '"' . $json_data{$_} . '"')} sort keys %json_data) . "}\n";
                    }
        }
}

print "\n\nTOTAL_PACKAGES=$counter_pkg, TOTAL_SCANNED_UNIQ_PACKAGES=" . scalar(@packages_installed) . ", AFFECTED_PACKAGES=" . scalar (keys %vulnerable_software) . " CVEs=" . $counter_cve . " HIGHRISK=" . $counter_highrisk . "\n\n";


# CSV
if ( ( $csv ) && ( length ($csv_output) > 5 ) )
{
        print $csv_output . "\n";
}

# JSON
if ( ( $json ) && ( length ($json_output) > 5 ) )
{
        print $json_output;
}

