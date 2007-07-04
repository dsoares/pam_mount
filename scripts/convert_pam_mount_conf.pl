#!/usr/bin/perl -w
#
#	convert tool for pam_mount.conf 
#
#	Copyright (c) 2007 SUSE LINUX Products GmbH, Nuernberg, Germany.
#	This file is under the same license as pam_mount itself.
#
#	Please submit bugfixes or comments via http://bugs.opensuse.org/
#
use Data::Dumper;
use Getopt::Long;
use IO::File;
use XML::Writer;
use strict;

my $OLD_CONF = "-";
my $NEW_CONF = "-";
my $debug = 0;

&Getopt::Long::Configure(qw(bundling));
&GetOptions(
	"i=s" => \$OLD_CONF,
	"o=s" => \$NEW_CONF,
	"d"   => \$debug,
);

my %callbacks = (
	"debug"           => \&callback_debug,
	"mkmountpoint"    => \&callback_mkmountpoint,
	"fsckloop"        => \&callback_fsckloop,
	"luserconf"       => \&callback_luserconf,
	"options_allow"   => \&callback_options_allow,
	"options_deny"    => \&callback_options_deny,
	"options_require" => \&callback_options_require,
	"lsof"            => \&callback_lsof,
	"fsck"            => \&callback_fsck,
	"losetup"         => \&callback_losetup,
	"unlosetup"       => \&callback_unlosetup,
	"cifsmount"       => \&callback_cifsmount,
	"smbmount"        => \&callback_smbmount,
	"ncpmount"        => \&callback_ncpmount,
	"smbumount"       => \&callback_smbumount,
	"ncpumount"       => \&callback_ncpumount,
	"fusemount"       => \&callback_fusemount,
	"fuseumount"      => \&callback_fuseumount,
	"umount"          => \&callback_umount,
	"lclmount"        => \&callback_lclmount,
	"cryptmount"      => \&callback_cryptmount,
	"nfsmount"        => \&callback_nfsmount,
	"mntagain"        => \&callback_mntagain,
	"mntcheck"        => \&callback_mntcheck,
	"pmvarrun"        => \&callback_pmvarrun,
	"volume"          => \&callback_volume,
);

my $output = new IO::File(">$NEW_CONF");
my $writer = new XML::Writer(OUTPUT => $output, UNSAFE => 1);

$writer->xmlDecl("UTF-8");
$writer->startTag("pam_mount");
$writer->raw("\n");

sub callback_debug(@)
{
	my @fields = @_;

	$writer->emptyTag("debug", "enable" => $fields[1]);
	$writer->raw("\n");
}

sub callback_mkmountpoint(@)
{
	my @fields = @_;

	$writer->emptyTag("mkmountpoint", "enable" => $fields[1]);
	$writer->raw("\n");
}

sub callback_fsckloop(@)
{
	my @fields = @_;

	$writer->emptyTag("fsckloop", "device" => $fields[1]);
	$writer->raw("\n");
}

sub callback_luserconf(@)
{
	my @fields = @_;

	$writer->emptyTag("luserconf", "name" => $fields[1]);
	$writer->raw("\n");
}

sub callback_options_allow(@)
{
	my @fields = @_;

	$writer->emptyTag("mntoptions", "allow" => $fields[1]);
	$writer->raw("\n");
}

sub callback_options_deny(@)
{
	my @fields = @_;

	$writer->emptyTag("mntoptions", "deny" => $fields[1]);
	$writer->raw("\n");
}

sub callback_options_require(@)
{
	my @fields = @_;

	$writer->emptyTag("mntoptions", "require" => $fields[1]);
	$writer->raw("\n");
}

sub callback_lsof(@)
{
	my @fields = @_;

	shift @fields;

	$writer->startTag("lsof");
	$writer->characters(join(" ", @fields));
	$writer->endTag("lsof");
	$writer->raw("\n");
}

sub callback_fsck(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("fsck");
	$writer->characters(join(" ", @fields));
	$writer->endTag("fsck");
	$writer->raw("\n");
}

sub callback_losetup(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("losetup");
	$writer->characters(join(" ", @fields));
	$writer->endTag("losetup");
	$writer->raw("\n");
}

sub callback_unlosetup(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("unlosetup");
	$writer->characters(join(" ", @fields));
	$writer->endTag("unlosetup");
	$writer->raw("\n");
}

sub callback_cifsmount(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("cifsmount");
	$writer->characters(join(" ", @fields));
	$writer->endTag("cifsmount");
	$writer->raw("\n");
}

sub callback_smbmount(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("smbmount");
	$writer->characters(join(" ", @fields));
	$writer->endTag("smbmount");
	$writer->raw("\n");
}

sub callback_ncpmount(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("ncpmount");
	$writer->characters(join(" ", @fields));
	$writer->endTag("ncpmount");
	$writer->raw("\n");
}

sub callback_smbumount(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("smbumount");
	$writer->characters(join(" ", @fields));
	$writer->endTag("smbumount");
	$writer->raw("\n");
}

sub callback_ncpumount(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("ncpumount");
	$writer->characters(join(" ", @fields));
	$writer->endTag("ncpumount");
	$writer->raw("\n");
}

sub callback_fusemount(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("fusemount");
	$writer->characters(join(" ", @fields));
	$writer->endTag("fusemount");
	$writer->raw("\n");
}

sub callback_fuseumount(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("fuseumount");
	$writer->characters(join(" ", @fields));
	$writer->endTag("fuseumount");
	$writer->raw("\n");
}

sub callback_umount(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("umount");
	$writer->characters(join(" ", @fields));
	$writer->endTag("umount");
	$writer->raw("\n");
}

sub callback_lclmount(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("lclmount");
	$writer->characters(join(" ", @fields));
	$writer->endTag("lclmount");
	$writer->raw("\n");
}

sub callback_cryptmount(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("cryptmount");
	$writer->characters(join(" ", @fields));
	$writer->endTag("cryptmount");
	$writer->raw("\n");
}

sub callback_nfsmount(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("nfsmount");
	$writer->characters(join(" ", @fields));
	$writer->endTag("nfsmount");
	$writer->raw("\n");
}

sub callback_mntagain(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("mntagain");
	$writer->characters(join(" ", @fields));
	$writer->endTag("mntagain");
	$writer->raw("\n");
}

sub callback_mntcheck(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("mntcheck");
	$writer->characters(join(" ", @fields));
	$writer->endTag("mntcheck");
	$writer->raw("\n");
}

sub callback_pmvarrun(@)
{
	my @fields = @_;

	shift @fields;
	$writer->startTag("pmvarrun");
	$writer->characters(join(" ", @fields));
	$writer->endTag("pmvarrun");
	$writer->raw("\n");
}

sub callback_volume(@)
{
	my @fields = @_;

	shift @fields;

	my %attr = (
		"invert" => 0,
		"fstype" => "auto",
	);
	
	if ($fields[0] =~ /^\@\@(.*)/) {
		$attr{sgrp} = "$1";
	} elsif ($fields[0] =~ /^\@(.*)/) {
		$attr{pgrp} = "$1";
	} else {
		$attr{user} = "$fields[0]";
	}
	
	# search for wrong splits 
	# happens at 'a value' or "a value"
	# and remove quotes around a single value. "value" or 'value'
	my @new_fields = ();
	my $nf         = undef;
	my $char       = undef;
	
	foreach my $f (@fields) {
		if (!defined $nf && $f =~ /^'(.+)'$/) {
			push(@new_fields, $1);
		} elsif (!defined $nf && $f =~ /^"(.+)"$/) {
			push(@new_fields, $1);
		} elsif (!defined $nf && $f =~ /^'([^']+)$/) {
			$nf   = $1;
			$char = "'";
		} elsif (!defined $nf && $f =~ /^"([^"]+)$/) {
			$nf   = $1;
			$char = "\"";
		} elsif (defined $nf && $f =~ /^([^$char]+)$char$/) {
			$nf  .= " $1";
			push(@new_fields, $nf);
			$nf   = undef;
			$char = undef;
		} elsif(defined $nf) {
			$nf .= " $f";
		} else {
			push(@new_fields, $f);
		}
	}
	@fields = @new_fields;
	if ($debug) {
		print STDERR Data::Dumper->Dump([@new_fields])
	}
	
	foreach my $i (2..7) {
		$fields[$i] =~ s/&/\%(USER)/g;
		$fields[$i] =~ s/\\\s/ /g;
	}

	if (exists $fields[1] && defined $fields[1]) {
		$attr{fstype}     = $fields[1];
	}
	if (exists $fields[2] && defined $fields[2]) {
		$attr{server}     = $fields[2];
	}
	if (exists $fields[3] && defined $fields[3]) {
		$attr{path}       = $fields[3];
	}
	if (exists $fields[4] && defined $fields[4]) {
		$attr{mountpoint} = $fields[4];
	}
	if (exists $fields[5] && defined $fields[5]) {
		$attr{options}    = $fields[5];
	}
	if (exists $fields[6] && defined $fields[6]) {
		$attr{fskeycipher}= $fields[6];
	}
	if (exists $fields[7] && defined $fields[7]) {
		$attr{fskeypath}  = $fields[7];
	}

	$writer->emptyTag("volume", %attr );
	$writer->raw("\n");
}

sub parse_conf()
{
	my @file = ();
	open(OUT, "<$OLD_CONF") or die "Cannot open $OLD_CONF:$!";
	@file = <OUT>;
	close OUT;
	
	foreach my $line (@file) {
		next if ($line =~ /^\s*#/);
		next if ($line =~ /^\s*$/);

		my @fields = split(/(?<!\\)\s/, $line);
		chomp(@fields);

		if (exists $callbacks{$fields[0]}) {
			if ($debug) {
				print STDERR "callback_$fields[0] called: ",
				      join(" ", @fields), "\n";
			}

			$callbacks{$fields[0]}->(@fields);
		} else {
			print STDERR "Unknown command: $fields[0]\n";
		}
	}
}

&parse_conf();

$writer->endTag("pam_mount");
$writer->end();
$output->close();
