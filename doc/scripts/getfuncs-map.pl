eval '(exit $?0)' && eval 'exec perl -wST "$0" ${1+"$@"}'
  & eval 'exec perl -wST "$0" $argv:q'
    if 0;

# Copyright (C) 2011-2012 Free Software Foundation, Inc.
# Copyright (C) 2013 Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

# This list contains exported values, but prototype isn't easy
# to obtain (e.g., it's a pointer to a function or not a function).
my %known_false_positives = (
);

# API functions that although documented as such, are simply
# macros that expand to another function.
my %known_false_negatives = (
);

sub function_print {
  my $func_name;
  my $prototype = shift @_;
  my $check;

#print STDERR $prototype;
  if ($prototype =~ m/^\s*([A-Za-z0-9_]+)\;$/) {
#  if ($prototype =~ m/^(.*)/) {
    $func_name = $1;
  } else { 
    $func_name = '';
  }

  $check = $known_false_positives{$func_name};
  return if (defined $check && $check == 1);

  if ($func_name ne '' && ($func_name =~ m/^rc_.*/)) {
    print $func_name . "\n";
  }
      
  return;
}

my $line;
my $lineno = 0;
while ($line=<STDIN>) {

  next if ($line eq '');
# print STDERR "line($lineno): $line";

  #skip comments
#  if ($line =~ m/^\s*/) {
     function_print($line);
#  }
   $lineno++;
}

for (keys %known_false_negatives) {
	print $_ . "\n";
}
