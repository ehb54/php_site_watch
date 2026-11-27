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
#   exposure                           the running kernel and whether a reboot is needed, the
#                                      processes still running files an update replaced, and the
#                                      listening sockets with their programs, packages and units
#   lockdown status                    site-lockdown status
#   lockdown on [--mysql] [REASON...]  turn site-lockdown on, recorded as done by this control host
# Turning the lockdown off, installing software and changing settings are not possible through it;
# people do those as root. Every request, allowed or not, goes to syslog (authpriv).
# https://github.com/ehb54/php_site_watch

use strict;
use warnings;

our $VERSION = '1.14.0';

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
} elsif ($req[0] eq 'exposure') {
    exposure();
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
    return ($1) if $verb =~ /^(ping|report|packages|exposure)$/ && !@w;
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
    refuse('not allowed; the requests are: ping, report, packages, exposure, lockdown status, lockdown on [--mysql] [REASON]');
}

sub canonical {
    my @w = @_;
    return ($1) if @w == 1 && $w[0] =~ /^(report|packages|exposure|lockdown-status)$/;
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

# What a control host needs to judge whether an advisory matters here, next to the package list:
# the kernel that runs (an installed fix does nothing until the reboot), the processes still running
# code an update replaced (until they restart), and what listens on the network, with the program,
# package and systemd unit behind each socket. Read-only, like packages.
sub exposure {
    print "== system\n";
    my %os = os_release();
    my $pretty = $os{PRETTY_NAME} // join(' ', grep { defined } @os{qw(NAME VERSION)});
    print 'host: ', hostname(), "\n";
    print 'os: ', (length $pretty ? $pretty : 'unknown'), "\n";
    print 'os id: ', join(' ', map { $os{$_} // '-' } qw(ID VERSION_ID)), "\n";
    my ($btime) = map { /^btime (\d+)$/ ? $1 : () } file_lines('/proc/stat');
    print 'booted: ', (defined $btime ? utc($btime) : 'unknown'), "\n";
    my $running = first_line('/proc/sys/kernel/osrelease') // 'unknown';
    print "kernel running: $running\n";
    my $default;
    if (have('grubby')) {
        my ($out) = capture('grubby', '--default-kernel');
        $default = $1 if $out =~ m{\A/boot/vmlinuz-(\S+)\n?\z};
    }
    print 'kernel default boot: ', $default // 'unknown', "\n";
    my @boot;
    if (opendir my $d, '/boot') {
        @boot = sort { vercmp($a, $b) } map { /^vmlinuz-(?!0-rescue-)(\S+)$/ ? printable($1) : () } readdir $d;
        closedir $d;
    }
    print 'kernels in /boot: ', (@boot ? join(', ', @boot) : 'none'), "\n";

    # a reason is enough for yes; no needs a check that covers the whole system
    print "== reboot\n";
    my (@why, @note, $sure);
    if (defined $default) {
        push @why, "the default boot kernel is $default, not the running one" if $default ne $running;
    } elsif (@boot && $running ne 'unknown' && vercmp($boot[-1], $running) > 0) {
        push @why, "a newer kernel is installed: $boot[-1]";
    }
    if (have('dnf')) {
        # -C: only what is installed and cached, nothing downloaded
        my ($out) = capture('dnf', '-C', '-q', 'needs-restarting', '-r');
        if ($out =~ /Reboot is required/) {
            my @p = map { printable($_) } $out =~ /^\s*\*\s*(\S+)/mg;
            push @why, 'updated since boot: ' . (@p ? join(', ', @p) : 'core libraries or services') . ' (dnf needs-restarting)';
            $sure = 1;
        } elsif ($out =~ /Reboot should not be necessary/) {
            $sure = 1;
        } else {
            my ($first) = $out =~ /^\s*(\S.*)$/m;
            push @note, 'dnf needs-restarting gave no answer' . (defined $first ? ': ' . printable($first) : '');
        }
    }
    if (-e '/var/run/reboot-required') {
        my %p = map { (printable($_) => 1) } file_lines('/var/run/reboot-required.pkgs');
        push @why, '/var/run/reboot-required exists' . (%p ? ' (' . join(', ', sort keys %p) . ')' : '');
        $sure = 1;
    } elsif (-x '/usr/share/update-notifier/notify-reboot-required') {
        $sure = 1;    # Debian and Ubuntu: what writes /var/run/reboot-required is installed
    }
    print 'reboot needed: ', (@why ? 'yes' : $sure ? 'no' : 'unknown'), "\n";
    print "  why: $_\n" for @why;
    print "  note: $_\n" for @note;

    # code an update replaced stays in memory, mapped as "(deleted)", until the process restarts
    print "== processes running files an update replaced (unit or process: names (pids): files)\n";
    my %group;
    opendir my $proc, '/proc' or refuse("cannot read /proc: $!");
    for my $pid (sort { $a <=> $b } map { /^(\d+)$/ ? $1 : () } readdir $proc) {
        open my $fh, '<', "/proc/$pid/maps" or next;
        my %files;
        while (<$fh>) {
            my ($perms, $path) = m{^\S+\s+(\S+)\s+\S+\s+\S+\s+\d+\s+(/.*) \(deleted\)$} or next;
            $files{ printable($path) } = 1 if $perms =~ /x/ && $path =~ m{^/(?:usr|lib|lib64|bin|sbin|opt)/};
        }
        close $fh;
        next unless %files;
        my $comm = printable(first_line("/proc/$pid/comm") // '?');
        my $unit = unit_of($pid);
        my $g = $group{ $unit ne '-' ? $unit : $comm } //= { names => {}, pids => [], files => {} };
        $g->{names}{$comm} = 1;
        push @{ $g->{pids} }, $pid;
        $g->{files}{$_} = 1 for keys %files;
    }
    closedir $proc;
    for my $k (sort keys %group) {
        my $g = $group{$k};
        print "$k: ", join(', ', sort keys %{ $g->{names} }), ' (', some(@{ $g->{pids} }), '): ',
              some(sort keys %{ $g->{files} }), "\n";
    }
    print "(none)\n" unless %group;

    print "== listening (protocol address:port process program package unit; - where unknown)\n";
    unless (have('ss')) { print "(no ss here)\n"; return }
    my ($out, $rc) = capture('ss', '-l', '-n', '-p', '-t', '-u');
    print "(ss did not finish cleanly: exit $rc)\n" if $rc;
    my (%row, %pkg_of, $hidden);
    for (split /\n/, $out) {
        my ($proto, $local, $users) = /^(tcp|udp)\s+\S+\s+\d+\s+\d+\s+(\S+)\s+\S+\s*(.*)$/ or next;
        $local = printable($local);
        my ($port) = $local =~ /:(\d+)$/;
        my $sort = sprintf '%05d %s %s', $port // 0, $proto, $local;
        my %pid_of;
        while ($users =~ /\("([^"]*)",pid=(\d+),/g) {
            $pid_of{$1} = $2 if !defined $pid_of{$1} || $2 < $pid_of{$1};    # the parent, usually
        }
        unless (%pid_of) { $row{"$sort -"} = "$proto $local - - - -"; $hidden = 1; next }
        for my $name (sort keys %pid_of) {
            my $pid = $pid_of{$name};
            my $exe = readlink("/proc/$pid/exe") // '';
            $exe =~ s/ \(deleted\)$//;
            $exe = $exe =~ m{^(/[\w.+\@:/-]+)$} ? $1 : '-';
            $pkg_of{$exe} //= package_of($exe);
            my $proc = printable($name) =~ s/\s/_/gr;
            $row{"$sort $proc"} = join ' ', $proto, $local, $proc, $exe, $pkg_of{$exe}, unit_of($pid);
        }
    }
    print "$row{$_}\n" for sort keys %row;
    print "(none)\n" unless %row;
    print "(- as the process: no process holds it, as for nfsd, or root can't see the process here)\n" if $hidden;
}

sub run {
    my @cmd = @_;
    system(@cmd) == 0 or print "(@cmd[0, 1] did not finish cleanly: exit ", $? >> 8, ")\n";
}

# A command's output, stderr included, and its exit status, without a shell; nothing on stdin.
sub capture {
    my @cmd = @_;
    my $pid = open(my $fh, '-|') // return ('', -1);
    if (!$pid) {
        open STDIN, '<', '/dev/null';
        open STDERR, '>&', \*STDOUT;
        exec(@cmd) or exit 127;
    }
    my $out = do { local $/; <$fh> } // '';
    close $fh;
    return ($out, $? >> 8);
}

# The package an installed program came from, by its path.
sub package_of {
    my ($exe) = @_;
    return '-' if $exe eq '-';
    if (have('rpm')) {
        my ($out, $rc) = capture('rpm', '-qf', '--qf', '%{NAME}\n', $exe);
        return $rc == 0 && $out =~ /\A([\w.+-]+)\n/ ? $1 : '-';
    }
    if (have('dpkg-query')) {
        # with a merged /usr, dpkg may know the file by its other name
        my $other = $exe =~ m{^/usr(/.+)$} ? $1 : "/usr$exe";
        for my $p ($exe, $other) {
            my ($out, $rc) = capture('dpkg-query', '-S', $p);
            return $1 if $rc == 0 && $out =~ /\A([a-z0-9][a-z0-9.+-]*)[:,]/;
        }
    }
    return '-';
}

# The systemd unit (service or scope) a process runs in, from its cgroup; container scopes shortened.
sub unit_of {
    my ($pid) = @_;
    my $unit = '-';
    for (file_lines("/proc/$pid/cgroup")) {
        my (undef, $ctl, $path) = split /:/, $_, 3;
        next unless defined $path && ($ctl eq '' || $ctl eq 'name=systemd');
        my @u = $path =~ m{([^/]+\.(?:service|scope))(?=/|$)}g;
        $unit = $u[-1] if @u;
    }
    $unit =~ s/^((?:docker|libpod|crio)-[0-9a-f]{12})[0-9a-f]+\.scope$/$1.scope/;
    return printable($unit) =~ s/\s/_/gr;
}

sub os_release {
    for my $f ('/etc/os-release', '/usr/lib/os-release') {
        my @l = file_lines($f) or next;
        my %os;
        for (@l) {
            my ($k, @v) = /^([A-Z_]+)=(?:"([^"]*)"|'([^']*)'|(\S*))\s*$/ or next;
            $os{$k} = printable((grep { defined } @v)[0]);
        }
        return %os;
    }
    return ();
}

# Version strings compared piece by piece, numbers as numbers: 5.15.0-326 is newer than 5.15.0-36.
sub vercmp {
    my @a = $_[0] =~ /(\d+|[a-z]+)/gi;
    my @b = $_[1] =~ /(\d+|[a-z]+)/gi;
    while (@a && @b) {
        my ($x, $y) = (shift @a, shift @b);
        my $c = $x =~ /^\d/ && $y =~ /^\d/ ? $x <=> $y : $x cmp $y;
        return $c if $c;
    }
    return @a <=> @b;
}

# The first five of a list, and how many more.
sub some {
    my @l = @_;
    return join(', ', @l) if @l <= 5;
    return join(', ', @l[0 .. 4]) . ', ' . (@l - 5) . ' more';
}

sub utc {
    my @t = gmtime $_[0];
    return sprintf '%04d-%02d-%02d %02d:%02d:%02d UTC', $t[5] + 1900, $t[4] + 1, @t[3, 2, 1, 0];
}

sub file_lines {
    open my $fh, '<', $_[0] or return ();
    chomp(my @l = <$fh>);
    return @l;
}

sub first_line { my @l = file_lines($_[0]); return $l[0] }

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
