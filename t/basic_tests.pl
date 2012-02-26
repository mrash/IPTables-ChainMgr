#!/usr/bin/perl -w

use lib (qw|../lib ../../IPTables-Parse/lib ../../IPTables-Parse.git/lib|);
use Data::Dumper;
use strict;

eval {
    require IPTables::ChainMgr;
};
die "[*] Adjust 'use lib' statement to include ",
    "directory where IPTables::Parse lives" if $@;

#==================== config =====================
my $iptables_bin  = '/sbin/iptables';
my $ip6tables_bin = '/sbin/ip6tables';

my $test_table = 'filter';
my $test_chain = 'CHAINMGRTEST';
my $test_jump_from_chain = 'INPUT';

my $logfile   = 'test.log';
my $PRINT_LEN = 68;
my $chain_past_end = 1000;
#================== end config ===================

my %targets = (
    'ACCEPT' => '',
    'DROP'   => '',
    'QUEUE'  => '',
    'RETURN' => '',
);

my %iptables_chains = (
    'mangle' => [qw/PREROUTING INPUT OUTPUT FORWARD POSTROUTING/],
    'raw'    => [qw/PREROUTING OUTPUT/],
    'filter' => [qw/INPUT OUTPUT FORWARD/],
    'nat'    => [qw/PREROUTING OUTPUT POSTROUTING/]
);

my %ip6tables_chains = (
    'mangle' => [qw/PREROUTING INPUT OUTPUT FORWARD POSTROUTING/],
    'raw'    => [qw/PREROUTING OUTPUT/],
    'filter' => [qw/INPUT OUTPUT FORWARD/],
);

my $passed = 0;
my $failed = 0;
my $executed = 0;

&init();

&iptables_tests();
&ip6tables_tests();

&logr("\n[+] passed/failed/executed: $passed/$failed/$executed tests\n\n");

exit 0;

sub iptables_tests() {

    &logr("\n[+] Running $iptables_bin tests...\n");
    my %opts = (
        'iptables' => $iptables_bin,
        'iptout'   => '/tmp/iptables.out',
        'ipterr'   => '/tmp/iptables.err',
        'debug'    => 0,
        'verbose'  => 0
    );

    my $ipt_obj = new IPTables::ChainMgr(%opts)
        or die "[*] Could not acquire IPTables::ChainMgr object";

    ### built-in chains
    &chain_exists_tests($ipt_obj, \%iptables_chains);

    &test_cycle($ipt_obj);

    return;
}

sub ip6tables_tests() {

    &logr("\n[+] Running $ip6tables_bin tests...\n");
    my %opts = (
        'iptables' => $ip6tables_bin,
        'iptout'   => '/tmp/ip6tables.out',
        'ipterr'   => '/tmp/ip6tables.err',
        'debug'    => 0,
        'verbose'  => 0
    );

    my $ipt_obj = new IPTables::ChainMgr(%opts)
        or die "[*] Could not acquire IPTables::ChainMgr object";

    ### built-in chains
    &chain_exists_tests($ipt_obj, \%ip6tables_chains);

    &test_cycle($ipt_obj);

    return;
}

sub test_cycle() {
    my $ipt_obj = shift;

    &custom_chain_init($ipt_obj, $test_table,
        $test_jump_from_chain, $test_chain);

    ### create/delete chain cycle
    &chain_does_not_exist_test($ipt_obj, $test_table, $test_chain);
    &create_chain_test($ipt_obj, $test_table, $test_chain);
    &flush_chain_test($ipt_obj, $test_table, $test_chain);
    &delete_chain_test($ipt_obj, $test_table, $test_jump_from_chain, $test_chain);

    ### create chain, add rules, delete chain cycle
    &chain_does_not_exist_test($ipt_obj, $test_table, $test_chain);
    &create_chain_test($ipt_obj, $test_table, $test_chain);
    &add_rules_tests($ipt_obj, $test_table, $test_chain);
    &flush_chain_test($ipt_obj, $test_table, $test_chain);
    &delete_chain_test($ipt_obj, $test_table, $test_jump_from_chain, $test_chain);

    ### create chain add rules, add jump rule, delete chain cycle
    &chain_does_not_exist_test($ipt_obj, $test_table, $test_chain);
    &create_chain_test($ipt_obj, $test_table, $test_chain);
    &add_rules_tests($ipt_obj, $test_table, $test_chain);
    &find_rules_tests($ipt_obj, $test_table, $test_chain);
    &add_jump_rule_test($ipt_obj, $test_table, $test_chain);
    &find_jump_rule_test($ipt_obj, $test_table, $test_chain);
    &flush_chain_test($ipt_obj, $test_table, $test_chain);
    &delete_chain_test($ipt_obj, $test_table, $test_jump_from_chain, $test_chain);

    return;
}

sub chain_exists_tests() {
    my ($ipt_obj, $tables_chains_hr) = @_;

    for my $table (keys %$tables_chains_hr) {
        for my $chain (@{$tables_chains_hr->{$table}}) {
            &dots_print("chain_exists(): $table $chain");

            my ($rv, $out_ar, $err_ar) = $ipt_obj->chain_exists($table, $chain);

            $executed++;

            if ($rv) {
                &logr("pass ($executed)\n");
                $passed++;
            } else {
                &logr("fail ($executed)\n");
                &logr("   $table chain $chain does not exist.\n");
                $failed++;
            }
        }
    }

    return;
}

sub flush_chain_test() {
    my ($ipt_obj, $test_table, $test_chain) = @_;

    &dots_print("flush_chain(): $test_table $test_chain");

    my ($rv, $out_ar, $err_ar) = $ipt_obj->flush_chain($test_table, $test_chain);

    $executed++;

    if ($rv) {
        &logr("pass ($executed)\n");
        $passed++;
    } else {
        &logr("fail ($executed)\n");
        &logr("   Could not flush $test_table $test_chain chain\n");
        $failed++;
    }

    return;
}

sub add_jump_rule_test() {
    my ($ipt_obj, $test_table, $test_chain) = @_;

    &dots_print("add_jump_rule(): $test_table $test_jump_from_chain -> $test_chain ");
    my ($rv, $out_ar, $err_ar) = $ipt_obj->add_jump_rule($test_table,
        $test_jump_from_chain, 1, $test_chain);

    $executed++;

    if ($rv) {
        &logr("pass ($executed)\n");
        $passed++;
    } else {
        &logr("fail ($executed)\n");
        &logr("   Could not add jump rule\n");
        $failed++;
    }

    return;
}

sub find_jump_rule_test() {
    my ($ipt_obj, $test_table, $test_chain) = @_;

    my $ip_any_net = '0.0.0.0/0';
    $ip_any_net = '::/0' if $ipt_obj->{'_ipt_bin_name'} eq 'ip6tables';

    &dots_print("find jump rule: $test_table $test_jump_from_chain -> $test_chain ");

    my ($rule_position, $num_chain_rules) = $ipt_obj->find_ip_rule($ip_any_net,
            $ip_any_net, $test_table, $test_jump_from_chain, $test_chain, {});

    $executed++;

    if ($rule_position > 0) {
        &logr("pass ($executed)\n");
        $passed++;
    } else {
        &logr("fail ($executed)\n");
        &logr("   Could not find jump rule\n");
        $failed++;
    }

    return;
}


sub add_rules_tests() {
    my ($ipt_obj, $test_table, $test_chain) = @_;

    my $src_ip = '10.1.2.3/24';
    my $dst_ip = '192.168.1.2';

    if ($ipt_obj->{'_ipt_bin_name'} eq 'ip6tables') {
        $src_ip = '0000:0000:0000:00FF:0000:0000:0000:0001/FFFF:FFFF:FFFF:FFFF:0000:0000:0000:0000';
        $dst_ip = '0000:0000:00AA:0000:0000:AA00:0000:0001/64';
    }

    for my $target (qw/LOG ACCEPT RETURN/) {
        &dots_print("add_rules(): $test_table $test_chain $src_ip -> $dst_ip $target ");
        my ($rv, $out_ar, $err_ar) = $ipt_obj->add_ip_rule($src_ip,
                $dst_ip, $chain_past_end, $test_table, $test_chain, $target, {});

        $executed++;

        if ($rv) {
            &logr("pass ($executed)\n");
            $passed++;
        } else {
            &logr("fail ($executed)\n");
            &logr("   Could not add $src_ip -> $dst_ip $target rule\n");
            $failed++;
        }
    }

    return;
}

sub find_rules_tests() {
    my ($ipt_obj, $test_table, $test_chain) = @_;

    my $src_ip = '10.1.2.3/24';
    my $dst_ip = '192.168.1.2';

    if ($ipt_obj->{'_ipt_bin_name'} eq 'ip6tables') {
        $src_ip = '0000:0000:0000:00FF:0000:0000:0000:0001/FFFF:FFFF:FFFF:FFFF:0000:0000:0000:0000';
        $dst_ip = '0000:0000:00AA:0000:0000:AA00:0000:0001/64';
    }

    for my $target (qw/LOG ACCEPT RETURN/) {
        &dots_print("find rule: $test_table $test_chain $src_ip -> $dst_ip $target ");
        my ($rule_position, $num_chain_rules) = $ipt_obj->find_ip_rule($src_ip,
                $dst_ip, $test_table, $test_chain, $target, {'normalize' => 1});

        $executed++;

        if ($rule_position > 0) {
            &logr("pass ($executed)\n");
            $passed++;
        } else {
            &logr("fail ($executed)\n");
            &logr("   Could not find $src_ip -> $dst_ip $target rule\n");
            $failed++;
        }
    }

    return;
}

sub create_chain_test() {
    my ($ipt_obj, $test_table, $test_chain) = @_;

    &dots_print("create_chain(): $test_table $test_chain");

    my ($rv, $out_ar, $err_ar) = $ipt_obj->create_chain($test_table, $test_chain);

    $executed++;

    if ($rv) {
        &logr("pass ($executed)\n");
        $passed++;
    } else {
        &logr("fail ($executed)\n");
        &logr("   Could not create $test_table $test_chain chain\n");
        die "[*] FATAL";
        $failed++;
    }

    return;
}

sub chain_does_not_exist_test() {
    my ($ipt_obj, $test_table, $test_chain) = @_;

    &dots_print("!chain_exists(): $test_table $test_chain");

    my ($rv, $out_ar, $err_ar) = $ipt_obj->chain_exists($test_table, $test_chain);

    $executed++;

    if ($rv) {
        &logr("fail ($executed)\n");
        &logr("   Chain exists.\n");
        die "[*] FATAL";
        $failed++;
    } else {
        &logr("pass ($executed)\n");
        $passed++;
    }
    return;
}

sub custom_chain_init() {
    my ($ipt_obj, $test_table, $test_jump_from_chain, $test_chain) = @_;

    my ($rv, $out_ar, $err_ar) = $ipt_obj->chain_exists($test_table,
            $test_chain);
    if ($rv) {
        $ipt_obj->delete_chain($test_table, $test_jump_from_chain, $test_chain);
    }
    return;
}

sub delete_chain_test() {
    my ($ipt_obj, $test_table, $test_jump_from_chain, $test_chain) = @_;

    &dots_print("delete_chain(): $test_table $test_chain");

    my ($rv, $out_ar, $err_ar) = $ipt_obj->delete_chain($test_table,
        $test_jump_from_chain, $test_chain);

    $executed++;

    if ($rv) {
        &logr("pass ($executed)\n");
        $passed++;
    } else {
        &logr("fail ($executed)\n");
        &logr("   Could not delete chain.\n");
        die "[*] FATAL";
        $failed++;
    }
    return;
}

sub dots_print() {
    my $msg = shift;
    &logr($msg);
    my $dots = '';
    for (my $i=length($msg); $i < $PRINT_LEN; $i++) {
        $dots .= '.';
    }
    &logr($dots);
    return;
}

sub logr() {
    my $msg = shift;
    print STDOUT $msg;
    open F, ">> $logfile" or die $!;
    print F $msg;
    close F;
    return;
}

sub init() {

    $|++; ### turn off buffering

    $< == 0 && $> == 0 or
        die "[*] $0: You must be root (or equivalent ",
            "UID 0 account) to effectively test fwknop";

    unlink $logfile if -e $logfile;
    for my $bin ($iptables_bin, $ip6tables_bin) {
        die "[*] $bin does not exist" unless -e $bin;
        die "[*] $bin not executable" unless -x $bin;
    }

    return;
}
