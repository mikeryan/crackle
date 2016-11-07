#!/usr/bin/perl

use strict;
use Digest::SHA;

my $crackle = shift || die "Must provide full path to crackle\n";
my $verbose = shift || 0;

sub diff {
    my ($path) = @_;

    my @output = `diff -u $path/out/expected_output.txt $path/out/actual_output.txt`;
    return \@output;
}

sub file_sha256 {
    my ($filename) = @_;

    my $sha = Digest::SHA->new(256);
    $sha->addfile($filename);
    return $sha->hexdigest();
}

my ($total, $passed) = (0, 0);
foreach my $test (glob('*')) {
    next unless $test =~ /^\d\d_/;

    print "Running $test... ";
    ++$total;

    # find the input file
    my $input = (glob("$test/*.pcap $test/*.pcapng"))[0];
    if (!defined $input) {
        print "FAIL: no input file\n";
        next;
    }

    # setup basic args
    my $args = "-i $input -o $test/out/actual_output.pcap ";

    # grab any extra args
    my $has_extra = open my $args_file, '<', "$test/args.txt";
    if ($has_extra) {
        my $extra_args = <$args_file>;
        chomp $extra_args;
        $args .= " $extra_args";
    }
    close $args_file;

    # dump the whole thing into the out dir
    $args .= " > $test/out/actual_output.txt";

    # run the test with crackle
    my $retval = system("$crackle $args");
    if ($retval != 0) {
        print "FAIL: return value $retval\n";
        map { print $_ } @{diff($test)} if $verbose;
        next;
    }

    # check if the command output matches
    my $diff = diff($test);
    if (@$diff > 0) {
        print "FAIL: output does not match expected\n";
        map { print $_ } @$diff if $verbose;
        next;
    }

    # check that the output PCAP is generated properly
    if (-e "$test/out/expected_output.pcap") {
        my $expected_sha = file_sha256("$test/out/expected_output.pcap");
        my $actual_sha = file_sha256("$test/out/actual_output.pcap");
        if ($expected_sha ne $actual_sha) {
            print "FAIL: output PCAP does not match expected PCAP\n";
            if ($verbose) {
                print "  Expected: $expected_sha\n";
                print "  Actual:   $actual_sha\n";
            }
            next;
        }
    }

    print "PASS\n";
    ++$passed;
}

print "Ran $total tests, $passed passed\n";
if ($passed < $total) {
    print "Rerun with -v to get diff of output\n" if !$verbose;
    exit 1;
}
exit 0;
