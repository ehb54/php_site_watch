#!/usr/bin/perl -T
# fleet-agent: the only command a fleet control host can run on this server. Each control host's
# key in ~fleet/.ssh/authorized_keys forces it, whatever the control host asks for, and the request
# arrives in SSH_ORIGINAL_COMMAND. setup.sh controller add writes these lines:
#   restrict,from="ADDRESSES",command="/usr/local/sbin/fleet-agent --controller NAME" ssh-ed25519 ...
# It accepts only these requests, and runs all but ping as root through sudo:
#   ping                               this server's name and versions
#   report                             the latest saved php-site-watch reports and runs (--last)
#   packages                           installed packages and the security updates waiting for them
#                                      (from the package manager's cache; nothing is downloaded)
#   lockdown status                    site-lockdown status
#   lockdown on [--mysql] [REASON...]  turn site-lockdown on, recorded as done by this control host
# Turning the lockdown off, installing software and changing settings are not possible through it;
# people do those as root. Every request, allowed or not, goes to syslog (authpriv).
# https://github.com/ehb54/php_site_watch

use strict;
use warnings;

our $VERSION = '1.10.0';

# taint mode: nothing from the environment or the request is used before it has been checked
$ENV{PATH} = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
$ENV{LC_ALL} = 'C';

my $self     = '/usr/local/sbin/fleet-agent';
my $psw      = '/usr/local/sbin/php-site-watch';
my $lockdown = '/usr/local/sbin/site-lockdown';
my $reason_chars = 'letters, digits, spaces and . , : ( ) / + # @ _ -';

my ($controller, $from, $as_root);
my @args = @ARGV;
while (@args && $args[0] =~ /^--/) {
    my $opt = shift @args;
    if    ($opt eq '--version')    { print "fleet-agent $VERSION\n"; exit 0 }
    elsif ($opt eq '--controller') { $controller = name(shift @args) }
    elsif ($opt eq '--from')       { $from = address(shift @args) }
    elsif ($opt eq '--root')       { $as_root = 1 }
    else                           { refuse('unknown option') }
}
refuse('no valid --controller NAME; fix this key line in ~fleet/.ssh/authorized_keys') unless defined $controller;

if (!$as_root) {
    # Straight from sshd, as the fleet user. Words are never handed to a shell, but are still checked.
    $from = address((split ' ', $ENV{SSH_CONNECTION} // '')[0]) // 'unknown';
    my $request = $ENV{SSH_ORIGINAL_COMMAND} // '';
    my @req = parse(split ' ', $request);
    note("controller $controller from $from: " . printable($request));
    if ($req[0] eq 'ping') {
        my $v = sub { my $l = `$_[0] --version 2>/dev/null` // ''; chomp $l; return length $l ? $l : "$_[0] not installed" };
        print "fleet-agent $VERSION on ", hostname(), "\n", $v->($psw), "\n", $v->($lockdown), "\n";
        exit 0;
    }
    exec('sudo', '-n', $self, '--root', '--controller', $controller, '--from', $from, @req)
        or refuse("cannot run sudo: $!");
}

# As root, through sudo: check again, since the arguments came through another program.
($< == 0 && $> == 0) or refuse('--root is only for fleet-agent itself, through sudo');
defined $from or refuse('--root needs --from');
my @req = canonical(@args);
if ($req[0] eq 'report') {
    exec($psw, '--last')
        or refuse("cannot run $psw: $!");
} elsif ($req[0] eq 'packages') {
    packages();
} elsif ($req[0] eq 'lockdown-status') {
    exec($lockdown, 'status')
        or refuse("cannot run $lockdown: $!");
} elsif ($req[0] eq 'lockdown-on') {
    note("controller $controller from $from turns the lockdown on");
    exec($lockdown, 'on', @req[1 .. $#req], '--by', "controller $controller from $from")
        or refuse("cannot run $lockdown: $!");
}
exit 0;

# --- requests -------------------------------------------------------------------------------------

# A control host's request, as words, into the canonical form the root half accepts.
sub parse {
    my @all  = @_;
    my @w    = @_;
    my $verb = shift(@w) // '';
    return ($1) if $verb =~ /^(ping|report|packages)$/ && !@w;
    if ($verb eq 'lockdown' && @w) {
        my $what = shift @w;
        return ('lockdown-status') if $what eq 'status' && !@w;
        if ($what eq 'on') {
            my @r = ('lockdown-on');
            if (@w && $w[0] eq '--mysql') { shift @w; push @r, '--mysql' }
            push @r, '--reason', reason(join ' ', @w) if @w;
            return @r;
        }
    }
    note("controller $controller from " . ($from // 'unknown') . ' refused: ' . printable(join ' ', @all));
    refuse('not allowed; the requests are: ping, report, packages, lockdown status, lockdown on [--mysql] [REASON]');
}

sub canonical {
    my @w = @_;
    return ($1) if @w == 1 && $w[0] =~ /^(report|packages|lockdown-status)$/;
    if (@w && $w[0] eq 'lockdown-on') {
        my @r = ('lockdown-on');
        shift @w;
        if (@w && $w[0] eq '--mysql') { shift @w; push @r, '--mysql' }
        if (@w == 2 && $w[0] eq '--reason') { push @r, '--reason', reason($w[1]); @w = () }
        return @r unless @w;
    }
    refuse('not a request fleet-agent makes');
}

sub reason {
    my ($r) = @_;
    $r =~ /^([\w .,:()\/+#@-]{1,200})$/a or refuse("the reason may only use $reason_chars, up to 200 characters");
    return $1;
}

# Installed packages, then the security updates the package manager already knows about.
sub packages {
    print "== installed packages\n";
    if (have('rpm')) {
        run('rpm', '-qa', '--qf', '%{NAME} %|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}.%{ARCH}\n');
    } elsif (have('dpkg-query')) {
        run('dpkg-query', '-W', '-f', '${db:Status-Abbrev} ${Package} ${Version} ${Architecture}\n');
    } else {
        print "(no rpm or dpkg here)\n";
    }
    print "== security updates waiting (from the package manager's cache)\n";
    if (have('dnf')) {
        run('dnf', '-q', '-C', 'updateinfo', 'list', '--security');
    } elsif (have('yum')) {
        run('yum', '-q', '-C', 'updateinfo', 'list', 'security');
    } elsif (have('apt-get')) {
        # what a simulated upgrade would take from a security pocket
        run('sh', '-c', q{apt-get -s -q -o Debug::NoLocking=1 upgrade 2>&1 | sed -n 's/^Inst \([^ ]*\) \[\([^]]*\)\] (\([^ ]*\) \([^)]*\)).*/\1 \2 -> \3 \4/p' | grep -i security || true});
    } else {
        print "(no dnf, yum or apt-get here)\n";
    }
}

sub run {
    my @cmd = @_;
    system(@cmd) == 0 or print "(@cmd[0, 1] did not finish cleanly: exit ", $? >> 8, ")\n";
}

# --- checks and messages --------------------------------------------------------------------------

sub name {
    my ($n) = @_;
    return defined $n && $n =~ /^([A-Za-z0-9][A-Za-z0-9._-]{0,39})$/ ? $1 : undef;
}

sub address {
    my ($a) = @_;
    return defined $a && $a =~ /^([0-9A-Fa-f.:]{2,45})$/ ? $1 : undef;
}

sub printable {
    my ($t) = @_;
    $t =~ tr/\x20-\x7e/?/c;
    return length $t > 300 ? substr($t, 0, 300) . '...' : $t;
}

sub hostname {
    open my $fh, '<', '/proc/sys/kernel/hostname' or return 'unknown-host';
    chomp(my $h = <$fh> // '');
    return length $h ? $h : 'unknown-host';
}

sub have { my ($cmd) = @_; return scalar grep { -f "$_/$cmd" && -x _ } split /:/, $ENV{PATH} }

sub note {
    my ($text) = printable($_[0]) =~ /^(.*)$/s;    # printable now, so fine to hand to logger
    return unless have('logger');
    open my $saved, '>&', \*STDERR;
    open STDERR, '>', '/dev/null';
    system('logger', '-p', 'authpriv.notice', '-t', 'fleet-agent', '--', $text);
    open STDERR, '>&', $saved;
}

sub refuse {
    print STDERR "fleet-agent: $_[0]\n";
    exit 1;
}
