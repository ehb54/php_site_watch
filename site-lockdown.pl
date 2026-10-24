#!/usr/bin/perl
# site-lockdown: an emergency switch that blocks web traffic to this server, and MySQL on request,
# from everywhere except the admin addresses in /etc/site-lockdown.conf. It is for a vulnerability
# that is being exploited while no fix is installed yet. SSH is never blocked.
# https://github.com/ehb54/php_site_watch
#
# Usage: site-lockdown on [--mysql] [--reason TEXT]
#        site-lockdown off
#        site-lockdown status
#        site-lockdown enforce
#   on        block the web ports (80 and 443, TCP and UDP) and, with --mysql, the MySQL port
#             (3306). Running it again while the block is on picks up changes to the config,
#             and --mysql adds MySQL.
#   off       remove the block. Only a person, as root: fleet control hosts can turn the block
#             on but never off.
#   status    whether the block is on, since when, who turned it on and why, and how many
#             packets it has stopped
#   enforce   put the block back if it is on but its rules are gone. While the block is on,
#             site-lockdown.service runs this at boot, before the network comes up, and after
#             every firewalld restart, and site-lockdown.timer runs it every minute.
#
# The block is its own nftables table (inet site_lockdown). It runs before firewalld's and
# Docker's rules and before address translation, so it also covers ports Docker publishes for
# containers, and it cuts connections already open on those ports. Traffic from this server
# itself, from its container and VM networks, and from the allowed addresses gets through.
# The state is kept in /var/lib/site-lockdown/state; every change is logged to
# /var/log/site-lockdown.log and to syslog. Exit status: 0 done, 2 usage or setup error.

use strict;
use warnings;

our $VERSION = '1.10.0';

$ENV{PATH}   = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
$ENV{LC_ALL} = 'C';

my $conf_file  = '/etc/site-lockdown.conf';
my $state_dir  = '/var/lib/site-lockdown';
my $state_file = "$state_dir/state";
my $log_file   = '/var/log/site-lockdown.log';
my $table      = 'site_lockdown';
my $unit_dir   = '/etc/systemd/system';
# traffic arriving from these interfaces comes from this server's own containers and VMs
my @local_ifaces = ('lo', 'docker*', 'br-*', 'veth*', 'cni*', 'podman*', 'virbr*');

sub fail { print STDERR "site-lockdown: $_[0]\n"; exit 2 }

sub usage {
    my ($status, $msg) = @_;
    print STDERR "site-lockdown: $msg\n" if $msg;
    if (open my $self, '<', $0) {
        while (<$self>) {
            last if /^use /;
            print STDERR substr($_, 2) if /^# (?:Usage|  |       )/;
        }
    }
    exit $status;
}

my $cmd = shift @ARGV // '';
usage(0) if $cmd eq '--help' || $cmd eq '-h';
if ($cmd eq '--version') { print "site-lockdown $VERSION\n"; exit 0 }
usage(2, $cmd eq '' ? 'what should it do? on, off, status or enforce' : "unknown command: $cmd")
    unless $cmd =~ /^(?:on|off|status|enforce)$/;

my %o;
while (@ARGV) {
    my $arg = shift @ARGV;
    if ($cmd eq 'on' && $arg eq '--mysql') { $o{mysql} = 1; next }
    if ($cmd eq 'on' && $arg =~ /^--(reason|by)(?:=(.*))?$/s) {
        my ($k, $v) = ($1, $2);
        $v = shift @ARGV unless defined $v;
        usage(2, "--$k needs a value") unless defined $v;
        $o{$k} = one_line($v);
        usage(2, "--$k is empty") unless length $o{$k};
        next;
    }
    usage(2, "unknown argument for $cmd: $arg");
}
fail("run as root: sudo $0 $cmd") if $> != 0;

my $by = $o{by} // ($ENV{SUDO_USER} ? "$ENV{SUDO_USER} (sudo)" : scalar(getpwuid $<) // 'root');

if ($cmd eq 'on') {
    my %c   = read_conf();
    my $old = read_state();
    my $s   = $old ? {%$old} : { since => stamp(), by => $by, reason => $o{reason} // 'no reason given', mysql => 0 };
    $s->{mysql} = 1 if $o{mysql};
    apply(\%c, $s);
    my $units = units(1);
    if (!$old) {
        event("on by $by" . ($s->{mysql} ? ', MySQL too' : '') . ": $s->{reason}");
    } else {
        event("refreshed by $by" . ($o{mysql} && !$old->{mysql} ? ', MySQL added' : '') . (defined $o{reason} ? ": $o{reason}" : ''));
    }
    print_status();
    print "$units\n" if $units;
} elsif ($cmd eq 'off') {
    # a control host can only ever run "on" through fleet-agent; refuse anyone else sudo lets in as it
    fail('a fleet control host cannot turn the block off; a person has to, as root') if ($ENV{SUDO_USER} // '') eq 'fleet';
    my $s = read_state();
    my ($present) = table_info();
    if ($present) {
        system('nft', 'delete', 'table', 'inet', $table) == 0 or fail('nft could not remove the block');
    }
    unlink $state_file if $s;
    units(0);
    event("off by $by" . ($s ? " (on since $s->{since} by $s->{by})" : '')) if $s || $present;
    print_status();
} elsif ($cmd eq 'status') {
    print_status();
} else {    # enforce
    my $s = read_state() or exit 0;
    my ($present) = table_info();
    exit 0 if $present;
    my %c = read_conf();
    apply(\%c, $s);
    event('restored the block, whose rules were gone');
    print_status();
}
exit 0;

# --- the block ------------------------------------------------------------------------------------

# Build the nftables table from the config and apply it in one transaction, replacing an older one,
# then record what it blocks in the state file. Nothing is recorded if nft rejects the rules.
sub apply {
    my ($c, $s) = @_;
    my @tcp = uniq_ports(@{ $c->{ports} }, $s->{mysql} ? @{ $c->{'mysql-ports'} } : ());
    my @udp = uniq_ports(@{ $c->{ports} });    # HTTP/3 runs over UDP
    my @v4  = grep { !/:/ } @{ $c->{allow} };
    my @v6  = grep { /:/ } @{ $c->{allow} };
    my $set = sub {
        my ($name, $type, @e) = @_;
        return "\tset $name {\n\t\ttype $type\n\t\tflags interval\n\t\tauto-merge\n"
             . (@e ? "\t\telements = { " . join(', ', @e) . " }\n" : '') . "\t}\n";
    };
    my $rules = join '',
        "add table inet $table\n",
        "delete table inet $table\n",
        "table inet $table {\n",
        $set->('allow4', 'ipv4_addr', @v4),
        $set->('allow6', 'ipv6_addr', @v6),
        "\tchain prerouting {\n",
        "\t\ttype filter hook prerouting priority -300; policy accept;\n",
        (map { "\t\tiifname \"$_\" accept\n" } @local_ifaces),
        "\t\tip saddr \@allow4 accept\n",
        "\t\tip6 saddr \@allow6 accept\n",
        "\t\tfib daddr type local tcp dport { " . join(', ', @tcp) . " } counter drop\n",
        "\t\tfib daddr type local udp dport { " . join(', ', @udp) . " } counter drop\n",
        "\t}\n}\n";
    have('nft') or fail('nft not found; install nftables (dnf install nftables, or apt-get install nftables)');
    open my $nft, '|-', 'nft', '-f', '-' or fail("cannot run nft: $!");
    print $nft $rules;
    close $nft or fail('nft did not accept the rules (see its message above); the block is not on');
    $s->{tcp}   = "@tcp";
    $s->{udp}   = "@udp";
    $s->{allow} = @{ $c->{allow} } ? join(' ', @{ $c->{allow} }) : 'none';
    write_state($s);
}

# Whether the table is in place, and how many packets it has dropped.
sub table_info {
    return (0, 0) unless have('nft');
    open my $saved, '>&', \*STDERR;
    open STDERR, '>', '/dev/null';
    my $ok = open my $fh, '-|', 'nft', 'list', 'table', 'inet', $table;
    open STDERR, '>&', $saved;
    return (0, 0) unless $ok;
    my ($lines, $dropped) = (0, 0);
    while (<$fh>) {
        $lines++;
        $dropped += $1 if /counter packets (\d+) bytes \d+ drop/;
    }
    close $fh or return (0, 0);
    return ($lines > 0, $dropped);
}

sub print_status {
    my $s = read_state();
    my ($present, $dropped) = table_info();
    if (!$s) {
        print $present ? "lockdown: off, but a block from an earlier run is still in place (site-lockdown off removes it)\n" : "lockdown: off\n";
        return;
    }
    print $present ? "lockdown: on\n" : "lockdown: on, but its rules are missing (site-lockdown enforce puts them back)\n";
    print "since $s->{since}, turned on by $s->{by}\n";
    print "reason: $s->{reason}\n";
    print 'blocked: TCP ', join(', ', split ' ', $s->{tcp} // '?'), '; UDP ', join(', ', split ' ', $s->{udp} // '?'),
          $s->{mysql} ? ' (MySQL included)' : ' (MySQL not included)', "\n";
    print 'still allowed: this server, its container networks', ($s->{allow} && $s->{allow} ne 'none' ? ', ' . join(', ', split ' ', $s->{allow}) : ''), ", and SSH from anywhere\n";
    print "packets dropped so far: $dropped\n" if $present;
}

# While the block is on, site-lockdown.service puts it back at boot before the network comes up
# and after firewalld restarts, and the timer checks every minute (an "nft flush ruleset", such as
# a restart of nftables.service does, removes it).
sub units {
    my ($on) = @_;
    return 'no systemd here: the block will not come back by itself after a reboot or a firewall reload; run site-lockdown enforce then'
        unless -d '/run/systemd/system' && have('systemctl');
    return "the site-lockdown units are not installed in $unit_dir (setup.sh install puts them there)"
        unless -e "$unit_dir/site-lockdown.timer";
    # started as well as enabled, so a firewalld restart now also restarts it
    my @do = $on ? (['enable', '--now', '--quiet', 'site-lockdown.service', 'site-lockdown.timer'])
                 : (['disable', '--now', '--quiet', 'site-lockdown.timer', 'site-lockdown.service']);
    for (@do) {
        system('systemctl', @$_) == 0 or return "systemctl @$_ failed; the block may not come back by itself after a reboot";
    }
    return '';
}

# --- config, state and log ----------------------------------------------------------------------

sub read_conf {
    my %c = (allow => [], ports => [80, 443], 'mysql-ports' => [3306]);
    return %c unless -e $conf_file;
    open my $fh, '<', $conf_file or fail("cannot read $conf_file: $!");
    while (my $l = <$fh>) {
        $l =~ s/#.*//;
        $l =~ s/^\s+|\s+$//g;
        next unless length $l;
        my ($k, $v) = $l =~ /^([a-z_-]+)\s*=\s*(.*)$/ or fail("$conf_file line $.: expected key = value");
        $k =~ tr/_/-/;
        if ($k eq 'allow') {
            for (split /[\s,]+/, $v) {
                my $a = address($_) // fail("$conf_file line $.: not an address or network: $_");
                push @{ $c{allow} }, $a unless grep { $_ eq $a } @{ $c{allow} };
            }
        } elsif ($k eq 'ports' || $k eq 'mysql-ports') {
            my @p = split /[\s,]+/, $v;
            fail("$conf_file line $.: $k needs port numbers") if !@p || grep { !/^\d{1,5}$/ || $_ < 1 || $_ > 65535 } @p;
            $c{$k} = [@p];
        } else {
            fail("$conf_file line $.: unknown key '$k'");
        }
    }
    return %c;
}

# An IPv4 or IPv6 address or network, written the way nft wants it (host bits cleared), or undef.
sub address {
    my ($a) = @_;
    if ($a =~ m{^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:/(\d{1,2}))?$}) {
        my @o   = ($1, $2, $3, $4);
        my $len = $5 // 32;
        return if (grep { $_ > 255 } @o) || $len > 32;
        my $mask = $len ? (0xffffffff << (32 - $len)) & 0xffffffff : 0;
        my $net  = join '.', unpack 'C4', pack 'N', (unpack 'N', pack 'C4', @o) & $mask;
        return $len == 32 ? $net : "$net/$len";
    }
    if ($a =~ m{^([0-9A-Fa-f:]*:[0-9A-Fa-f:]*)(?:/(\d{1,3}))?$}) {
        my ($addr, $len) = ($1, $2 // 128);
        my @w = ipv6_words($addr) or return;
        return if $len > 128;
        for my $i (0 .. 7) {
            my $bits = $len - 16 * $i;
            $w[$i] &= $bits >= 16 ? 0xffff : $bits <= 0 ? 0 : (0xffff << (16 - $bits)) & 0xffff;
        }
        my $net = join ':', map { sprintf '%x', $_ } @w;
        return $len == 128 ? $net : "$net/$len";
    }
    return;
}

# The eight 16-bit words of an IPv6 address written with :: or in full, or () if it isn't one.
sub ipv6_words {
    my ($a) = @_;
    my @parts = split /::/, $a, -1;
    return if @parts > 2;
    my @l = length $parts[0] ? split(/:/, $parts[0], -1) : ();
    my @r = @parts == 2 && length $parts[1] ? split(/:/, $parts[1], -1) : ();
    return if grep { !/^[0-9A-Fa-f]{1,4}$/ } @l, @r;
    my $fill = 8 - @l - @r;
    return if @parts == 2 ? $fill < 1 : $fill != 0;
    return map { hex } @l, ('0') x $fill, @r;
}

sub read_state {
    open my $fh, '<', $state_file or return;
    my %s;
    while (<$fh>) {
        $s{$1} = $2 if /^([a-z]+) = (.*?)\s*$/;
    }
    return \%s;
}

sub write_state {
    my ($s) = @_;
    mkdir $state_dir, 0755 unless -d $state_dir;
    open my $fh, '>', "$state_file.new" or fail("cannot write $state_file.new: $!");
    print $fh "# site-lockdown: the block is on while this file exists; remove it with site-lockdown off\n";
    print $fh "$_ = $s->{$_}\n" for grep { defined $s->{$_} } qw(since by reason mysql tcp udp allow);
    close $fh or fail("cannot write $state_file.new: $!");
    rename "$state_file.new", $state_file or fail("cannot replace $state_file: $!");
}

sub event {
    my ($text) = @_;
    if (open my $fh, '>>', $log_file) {
        print $fh stamp(), "  $text\n";
        close $fh;
    } else {
        print STDERR "site-lockdown: cannot write $log_file: $!\n";
    }
    if (have('logger')) {
        open my $saved, '>&', \*STDERR;
        open STDERR, '>', '/dev/null';
        system('logger', '-p', 'authpriv.notice', '-t', 'site-lockdown', '--', $text);
        open STDERR, '>&', $saved;
    }
}

# --- helpers ----------------------------------------------------------------------------------------

sub stamp {
    my @t = localtime;
    return sprintf '%04d-%02d-%02d %02d:%02d:%02d', $t[5] + 1900, $t[4] + 1, @t[3, 2, 1, 0];
}

sub have { my ($cmd) = @_; return scalar grep { -f "$_/$cmd" && -x _ } split /:/, $ENV{PATH} }

sub uniq_ports {
    my %seen;
    return sort { $a <=> $b } grep { !$seen{$_}++ } map { $_ + 0 } @_;
}

# Text from the command line or a control host goes into the state file, logs and mail: one line
# of printable characters, not too long.
sub one_line {
    my ($t) = @_;
    $t =~ s/\s+/ /g;
    $t =~ tr/\x20-\x7e//cd;
    $t =~ s/^ | $//g;
    return substr($t, 0, 200);
}
