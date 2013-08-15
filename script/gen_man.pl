#!/usr/bin/perl
#
# Genrate sheepdog manuals from help messages
#

use strict;

my ($cwd) = ($0 =~ m%^(.+/)%);
my $program = $ARGV[0];

## generator functions

sub sheep {
    my ($line) = @_;

    if ($line =~ /^  ([^,]+), (\S+)\s+(.+)/) {
	my ($opt, $longopt, $desc) = ($1, $2, $3);
	print escape(header("$opt, $longopt") . "\n");
	print escape("$desc\n");

	next if ($opt eq '-h');

	# extract detailed help if available
	my $tmpfile = `mktemp`;
	chomp($tmpfile);
	my $help = `$program $tmpfile $opt 2> /dev/null`;
	unlink $tmpfile;

	$help =~ s/^\s+\$.+/\n$&\n/mg;
	print escape("\n$help");
    }
}

sub dog {
    my ($line) = @_;

    if ($line =~ /^  (.+?)  \s+(.+)/) {
	my ($cmd, $desc) = ($1, $2);
	my $help = join '', `$program $cmd -h`;

	$help =~ s/Usage: dog (.*)/header($1)/e;
	$help =~ s/^([A-Z][ a-zA-Z]*:)/\n$1/mg;

	print escape("$help\n");
	print escape("Description:\n  $desc\n");
    }
}

sub sheepfs {
    my ($line) = @_;

    if ($line =~ /^  ([^,]+), (\S+)\s+(.+)/) {
	my ($opt, $longopt, $desc) = ($1, $2, $3);
	print escape(header("$opt, $longopt") . "\n");
	print escape("$desc\n");
    }
}

## helper functions

sub header {
    my ($str) = @_;

    return ".TP\n.BI \"$str\"";
}

sub escape {
    my ($str) = @_;

    $str =~ s/\t/  /g;
    $str =~ s/\\/\\\\\\/g;
    $str =~ s/"/\\"/g;
    $str =~ s/#/\\#/g;
    $str =~ s/\$/\\\$/g;
    $str =~ s/\n/\\n/g;

    return $str;
}

## main routine

open IN, "$program -h |" or die "cannot find $program\n";
my @help = <IN>;
close IN;

foreach my $help (@help) {
    my ($func) = ($program =~ m#.*/(.+)#);
    chomp($help);
    eval "$func(\"$help\")";
}
