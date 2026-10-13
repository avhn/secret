use strict;
use warnings;
binmode STDOUT;
binmode STDERR;
$| = 1;
my $mode = shift @ARGV;
if ($mode eq 'streams') {
    print STDOUT "$ENV{KEY}|$ENV{KEY}|$ENV{TOKEN}|";
    print STDERR "partial:$ENV{TOKEN}!\n";
} elsif ($mode eq 'selection') {
    print STDOUT defined $ENV{TOKEN} ? "unexpected\n" : "$ENV{KEY}\n";
    open my $store, "<", shift @ARGV or die "synthetic fixture unavailable";
    while (my $line = <$store>) {
        if ($line =~ /^export KEY='(.*)'/) { print STDERR "$1\n"; last; }
    }
} elsif ($mode eq 'status') {
    print STDOUT "$ENV{KEY}";
    exit 37;
}
