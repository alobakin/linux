#!/usr/bin/env perl
# SPDX-License-Identifier: GPL-2.0-only
#
# Generates a new LD script with every .text.* section described for FG-KASLR
# to avoid orphan/heuristic section placement and double-checks we don't have
# any symbols in plain .text section.
#
# Copyright (C) 2021-2022, Intel Corporation.
# Author: Alexander Lobakin <alexandr.lobakin@intel.com>
#

use strict;
use warnings;

## parameters
my $add_assert = 0;
my $expecting = 0;
my $shift = 0;
my $file;

foreach (@ARGV) {
	if ($_ eq '-a') {
		$add_assert = 1;
	} elsif ($_ eq '-s') {
		$expecting = 1;
	} elsif ($expecting) {
		$shift = $_ + 0;
		if ($shift < 0) {
			$shift = 0;
		} elsif ($shift > 16) {
			$shift = 16;
		}
		$expecting = 0;
	} elsif (!defined($file)) {
		$file = $_;
	} else {
		die "$0: usage: $0 [-a] [-s shift] binary < linker script";
	}
}

if (!defined($file)) {
	die "$0: usage: $0 [-a] [-s shift] binary < linker script";
}

## environment
my $readelf = $ENV{'READELF'} || die "$0: ERROR: READELF not set?";

## text sections array
my @sections = ();
my $has_ccf = 0;
my $vmlinux = 0;

## max alignment found to reserve some space. It would probably be
## better to start from 64, but CONFIG_DEBUG_FORCE_FUNCTION_ALIGN_64B
## (which aligns every function to 64b) would explode the $count then
my $max_align = 128;
my $count = 0;

sub read_sections {
	open(my $fh, "\"$readelf\" -SW \"$file\" 2>/dev/null |")
		or die "$0: ERROR: failed to execute \"$readelf\": $!";

	while (<$fh>) {
		my $name;
		my $align;
		chomp;

		($name, $align) = $_ =~ /^\s*\[[\s0-9]*\]\s*(\.\S*)\s*[A-Z]*\s*[0-9a-f]{16}\s*[0-9a-f]*\s*[0-9a-f]*\s*[0-9a-f]*\s*[0-9a-f]{2}\s*[A-Z]{2}\s*[0-9]\s*[0-9]\s*([0-9]*)$/;

		if (!defined($name)) {
			next;
		}

		## Clang 13 onwards emits __cfi_check_fail only on final
		## linking, so it won't appear in .o files and will be
		## missing in @sections. Add it manually to prevent
		## spawning orphans.
		if ($name eq ".text.__cfi_check_fail") {
			$has_ccf = 1;
		}

		## If we're processing a module, don't reserve any space
		## at the end as its sections are being allocated separately.
		if ($name eq ".sched.text") {
			$vmlinux = 1;
		}

		if (!($name =~ /^\.text(\.(?!hot\.|unknown\.|unlikely\.|.san\.)[0-9a-zA-Z_]*){1,2}((\.constprop|\.isra|\.part)\.[0-9]){0,2}(|\.[0-9cfi]*)$/)) {
			next;
		}

		if ($align > $max_align) {
			$max_align = $align;
			$count = 1;
		} elsif ($align == $max_align) {
			$count++;
		}

		push(@sections, $name);
	}

	close($fh);

	if (!$has_ccf) {
		push(@sections, ".text.__cfi_check_fail");
	}

	@sections = sort @sections;
}

sub print_sections {
	my $fps = 1 << $shift;
	my $counter = 1;

	print "\t.text.0 : ALIGN(16) {\n";
	print "\t\t*(.text)\n";
	print "\t}\n";

	## If we have asm function sections, we shouldn't have anything
	## in here.
	if ($add_assert) {
		print "\tASSERT(SIZEOF(.text.0) == 0, \"Plain .text is not empty!\")\n\n";
	}

	if (!@sections) {
		return;
	}

	while () {
		print "\t.text.$counter : ALIGN(16) {\n";

		my @a = (($counter - 1) * $fps .. ($counter * $fps) - 1);
		for (@a) {
			print "\t\t*($sections[$_])\n";

			if ($sections[$_] eq $sections[-1]) {
				print "\t}\n";
				return;
			}
		}

		print "\t}\n";
		$counter++;
	}
}

sub print_reserve {
	## If we have text sections aligned with 128 bytes or more, make
	## sure we reserve some space for them to not overlap _etext
	## while shuffling sections.
	if (!$vmlinux or !$count) {
		return;
	}

	print "\n\t. += $max_align * $count;\n";
}

sub print_lds {
	while (<STDIN>) {
		if ($_ =~ /^\s*__fg_kaslr_magic = \.;$/) {
			print_sections();
			print_reserve();
		} else {
			print $_;
		}
	}
}

## main

read_sections();
print_lds();
