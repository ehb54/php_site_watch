#!/usr/bin/perl
# php-site-watch: look for signs of PHP exploitation or trouble on an Apache or nginx + PHP
# server. Written after PHP2Shell (CVE-2026-109618/109619): it reports crashed or out-of-memory
# PHP workers, FastCGI failures, 5xx responses, busy POST senders, and recent files, processes
# and network sockets of the account PHP runs as. It can mail alerts about new findings and a
# daily status report that also covers basic server health.
#
# Needs only perl itself (no extra modules) plus ps, ss and find; mail goes through sendmail,
# which postfix provides. Run it as root so it can read the logs and see every process and socket.
# https://github.com/ehb54/php_site_watch
#
# Usage: php-site-watch [options]
#   --date DAY           day to check: YYYY-MM-DD, today or yesterday, in the server's local
#                        time (default: today)
#   --hours N            how far back to look for changed files (default: 24)
#   --user NAME          account PHP runs as (default: detected from running workers)
#   --fpm-logs PATH      php-fpm log directory or file (repeatable)
#   --web-logs PATH      Apache or nginx log directory or file (repeatable)
#   --scan DIR           where to look for files changed by the PHP account (repeatable)
#   --exclude REGEX      changed files to ignore (repeatable)
#   --allow-proc REGEX   other expected processes of the PHP account (repeatable)
#   --allow-peer REGEX   expected network peers as host:port, e.g. a remote database (repeatable)
#   --config FILE        read options from FILE, one "key = value" per line, # for comments
#                        (default: /etc/php-site-watch.conf if it exists)
#   --quiet              print only sections with findings, and nothing if all is clean
#   --alert              report only findings not reported before, from today and yesterday
#                        (for an hourly cron job)
#   --status             full report plus server health (for a daily cron job)
#   --mail-to ADDRESSES  with --alert or --status, mail the report instead of printing it
#                        (comma-separated; alerts are mailed only when there is something new)
#   --mail-from ADDRESS  sender address for mail (default: the system's)
#   --version            print the version and exit
# Exit status: 0 nothing suspicious, 1 findings, 2 usage or setup error.

use strict;
use warnings;

our $VERSION = '1.2.0';

# Cron and sudo can hand us a short PATH; ps date formats depend on the locale.
$ENV{PATH}   = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
$ENV{LC_ALL} = 'C';

my %single = map { $_ => 1 } qw(date hours user config mail-to mail-from sendmail state-dir);
my %multi  = map { $_ => 1 } qw(fpm-logs web-logs scan exclude allow-proc allow-peer);
my %flag   = map { $_ => 1 } qw(quiet alert status);

my @mon = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
my %mon = map { $mon[$_] => $_ + 1 } 0 .. 11;

my $re_crash  = qr/exited on signal (?:6|7|11)\b|SIG(?:SEGV|BUS|ABRT)|exited with code [1-9]|exit signal (?:Segmentation fault|Bus error|Aborted)/;
my $re_limits = qr/Allowed memory size|Maximum execution time|Out of memory|reached (?:pm\.)?max_children/;
my $re_fcgi   = qr/proxy_fcgi:error|proxy:error|AH01067|AH01075|reset by peer|upstream prematurely closed|while reading response header from upstream/;
my $re_stderr = qr/AH01071|FastCGI sent in stderr/;    # PHP's own messages passed on by Apache or nginx, not failures
my $re_fatal  = qr/PHP Fatal error:\s+(.*?)(?:\\n|',\s*referer:|"\s*while reading|'?\s*$)/;
my $re_loop   = qr/^(?:127\.|::1$|::ffff:127\.|localhost$)/;

my @default_exclude    = (qr{^/var/lib/php/(?:session|opcache)/}, qr{/sess_[\w,-]+$});
my @default_allow_proc = (qr{^(?:\S*/)?(?:httpd|apache2)\b}, qr{^nginx: }, qr{^php-fpm: }, qr{^(?:\S*/)?(?:php-cgi|lsphp)\b});
my $remember_days      = 14;    # how long --alert remembers what it already reported

sub fail { print STDERR "php-site-watch: $_[0]\n"; exit 2 }

sub usage {
    my ($status, $msg) = @_;
    print STDERR "php-site-watch: $msg\n" if $msg;
    if (open my $self, '<', $0) {
        while (<$self>) {
            last if /^use /;
            print STDERR substr($_, 2) if /^# (?:Usage|  |Exit)/;
        }
    }
    exit $status;
}

# --- options: config file first, then the command line on top -------------------------------

my (%cli, %cli_list, %opt, %list);
$cli_list{$_} = [] for keys %multi;
$list{$_}     = [] for keys %multi;
my @args = @ARGV;
while (@args) {
    my $arg = shift @args;
    usage(0) if $arg eq '--help' || $arg eq '-h';
    if ($arg eq '--version') { print "php-site-watch $VERSION\n"; exit 0 }
    $arg = '--quiet' if $arg eq '-q';
    my ($k, $v) = $arg =~ /^--([a-z-]+)(?:=(.*))?$/ or usage(2, "unknown argument: $arg");
    if ($flag{$k}) {
        usage(2, "--$k takes no value") if defined $v;
        $cli{$k} = 1;
        next;
    }
    usage(2, "unknown option: --$k") unless $single{$k} || $multi{$k};
    $v = shift @args unless defined $v;
    usage(2, "--$k needs a value") unless defined $v;
    if ($multi{$k}) { push @{ $cli_list{$k} }, $v } else { $cli{$k} = $v }
}

my $config = $cli{config};
$config = '/etc/php-site-watch.conf' if !defined $config && -e '/etc/php-site-watch.conf';
if (defined $config) {
    open my $fh, '<', $config or fail("cannot read $config: $!");
    while (my $l = <$fh>) {
        $l =~ s/#.*//;
        $l =~ s/^\s+|\s+$//g;
        next unless length $l;
        my ($k, $v) = $l =~ /^([a-z_-]+)\s*=\s*(.*)$/ or fail("$config line $.: expected key = value");
        $k =~ tr/_/-/;
        if    ($multi{$k})                    { push @{ $list{$k} }, $v }
        elsif ($single{$k} && $k ne 'config') { $opt{$k} = $v }
        else                                  { fail("$config line $.: unknown key '$k'") }
    }
}
$opt{$_} = $cli{$_} for grep { !$flag{$_} } keys %cli;
push @{ $list{$_} }, @{ $cli_list{$_} } for keys %multi;

usage(2, '--alert and --status cannot be combined') if $cli{alert} && $cli{status};
my $mode  = $cli{alert} ? 'alert' : $cli{status} ? 'status' : 'report';
my $quiet = $cli{quiet} ? 1 : 0;

my $today     = local_ymd(time);
my $yesterday = local_ymd(time - 86400);
usage(2, '--alert always checks today and yesterday; leave out --date') if $mode eq 'alert' && defined $opt{date};
my $date = $opt{date} // 'today';
$date = $today     if $date eq 'today';
$date = $yesterday if $date eq 'yesterday';
fail('--date must be YYYY-MM-DD, today or yesterday') unless $date =~ /^\d{4}-\d\d-\d\d$/;
my @days = $mode eq 'alert' ? ($yesterday, $today) : ($date);
my %want = map { $_ => 1 } @days;

my $hours = $opt{hours} // 24;
fail('--hours must be a number') unless $hours =~ /^\d+(?:\.\d+)?$/;
if (defined $opt{'mail-to'}) {
    fail('--mail-to must be a comma-separated list of addresses') unless $opt{'mail-to'} =~ /^[\w.%+@-]+(?:\s*,\s*[\w.%+@-]+)*$/;
}
if (defined $opt{'mail-from'}) {
    fail('--mail-from must be a single address') unless $opt{'mail-from'} =~ /^[\w.%+@-]+$/;
}

my $host = hostname();
my @warn;
push @warn, 'not running as root: some logs, processes and sockets may be invisible' if $> != 0;

my $user = $opt{user} // detect_user() // fail('could not tell which account PHP runs as; pass --user');
my ($uid, $home) = (getpwnam $user)[2, 7];
fail("unknown user '$user'") unless defined $uid;

my @exclude    = (@default_exclude,    map { qr/$_/ } @{ $list{exclude} });
my @allow_proc = (@default_allow_proc, map { qr/$_/ } @{ $list{'allow-proc'} });
my @allow_peer = map { qr/$_/ } @{ $list{'allow-peer'} };

# RHEL/Rocky/OL, Remi's parallel php74/php80/... packages, and Debian/Ubuntu layouts
my @fpm_paths = @{ $list{'fpm-logs'} } ? @{ $list{'fpm-logs'} }
              : grep { -e } ('/var/log/php-fpm', glob('/var/opt/remi/php*/log/php-fpm'), glob('/var/log/php*-fpm.log*'));
my @web_paths = @{ $list{'web-logs'} } ? @{ $list{'web-logs'} }
              : grep { -d } qw(/var/log/httpd /var/log/httpd24 /var/log/apache2 /var/log/nginx);
my @scan = @{ $list{scan} } ? @{ $list{scan} }
         : grep { -d } ('/srv', '/var/www', '/tmp', '/var/tmp', '/dev/shm', (defined $home && $home ne '/' ? $home : ()));

# --- logs ---------------------------------------------------------------------------------------

my %seen_file;
my @logs = grep { !$seen_file{$_}++ } (log_files(\@fpm_paths, qr/\.log/), log_files(\@web_paths, qr/access|error/));
my ($first_day) = sort @days;
my $oldest = (days_from_civil(split /-/, $first_day) - 2) * 86400;    # older files can't hold these days
my (%hits, %e5, %posts, %fatal, $read);
$hits{$_} = [] for qw(crash limits fcgi);

for my $f (@logs) {
    next if (stat $f)[9] < $oldest;
    my $fh = open_log($f) or do { push @warn, "cannot read $f"; next };
    $read++;
    while (my $l = <$fh>) {
        my $ld = line_day($l);
        next unless defined $ld && $want{$ld};
        chomp $l;
        $l = clean($l);
        if ($l =~ m{^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) }) {
            my ($ip, $method, $url, $status) = ($1, $2, $3, $4);
            $posts{$ip}++ if $method eq 'POST';
            $e5{"$ip $method $url $status"}++ if $status =~ /^5/;
            next;
        }
        if    ($l =~ $re_crash)                         { push @{ $hits{crash} },  $l }
        elsif ($l =~ $re_limits)                        { push @{ $hits{limits} }, $l }
        elsif ($l =~ $re_fatal)                         { $fatal{$1}++ }
        elsif ($l =~ $re_fcgi && $l !~ $re_stderr)      { push @{ $hits{fcgi} },   $l }
    }
    close $fh;
}
push @warn, 'no log files found for ' . join(' or ', @days) unless $read;

# --- files, processes, sockets of the PHP account ---------------------------------------------

my @changed;
if (@scan) {
    my $fh = quiet_open('find', @scan, '-xdev', '-type', 'f', '-user', $user, '-mmin', '-' . int($hours * 60), '-print0');
    if ($fh) {
        local $/ = "\0";
        while (my $f = <$fh>) {
            chomp $f;
            push @changed, $f unless grep { $f =~ $_ } @exclude;
        }
        close $fh;
    } else {
        push @warn, "cannot run find: $!";
    }
}
@changed = map { clean(scalar(localtime((stat $_)[9] // 0)) . "  $_") }
           sort { ((stat $b)[9] // 0) <=> ((stat $a)[9] // 0) } @changed;

my (%userpid, @procs);
if (my $fh = quiet_open('ps', '-u', $user, '-o', 'pid=,lstart=,args=')) {
    while (my $l = <$fh>) {
        chomp $l;
        my ($pid, $start, $cmd) = $l =~ /^\s*(\d+)\s+(\w{3} \w{3} +\d+ [\d:]+ \d{4})\s+(.*)$/ or next;
        $userpid{$pid} = 1;
        push @procs, clean("$pid  $start  $cmd") unless grep { $cmd =~ $_ } @allow_proc;
    }
    close $fh;
} else {
    push @warn, "cannot run ps: $!";
}

my @socks;
my ($sockets, $owned) = (0, 0);
if (my $fh = quiet_open('ss', '-tanp')) {
    while (my $l = <$fh>) {
        next if $l =~ /^State/;
        my @c = split ' ', $l;
        $sockets++;
        next unless @c >= 6;
        $owned++;
        my ($state, $local, $peer) = @c[0, 3, 4];
        my $who = join ' ', @c[5 .. $#c];
        next unless grep { $userpid{$_} } $who =~ /pid=(\d+)/g;
        my ($lhost, $lport) = split_hostport($local);
        my ($phost, $pport) = split_hostport($peer);
        next if $lport =~ /^(?:80|443)$/;    # visitors talking to the web server
        if ($state eq 'LISTEN') {
            next if $lhost =~ $re_loop;
        } else {
            next if $phost =~ $re_loop || grep { "$phost:$pport" =~ $_ } @allow_peer;
        }
        push @socks, clean("$state  $local -> $peer  $who");
    }
    close $fh;
    push @warn, 'ss could not show which processes own sockets (needs root with CAP_SYS_PTRACE), so the sockets section is incomplete'
        if $sockets && !$owned;
} else {
    push @warn, "cannot run ss: $!";
}

# --- report -------------------------------------------------------------------------------------

my $day_label = join ' and ', @days;
my @sections = (
    { title => 'PHP workers that crashed or died while starting a request', alert => 1, tail => 20, lines => $hits{crash} },
    { title => 'PHP out of memory or time, or worker limit reached', alert => 1, tail => 20, lines => $hits{limits} },
    { title => "FastCGI failures between web server and PHP (PHP's own notices, warnings and scanner noise left out)",
      alert => 1, tail => 20, lines => $hits{fcgi} },
    { title => 'PHP fatal errors in applications, for context: count, error', alert => 0, lines => [ counted(\%fatal, 10) ] },
    { title => '5xx responses: count, client, method, URL, status', alert => 0, lines => [ counted(\%e5, 15) ] },
    { title => 'Most active POST senders', alert => 0, lines => [ counted(\%posts, 5) ] },
    { title => "Files $user changed in the last $hours h", alert => 1, head => 30, lines => \@changed },
    { title => "$user processes other than web server and PHP workers (now)", alert => 1, lines => \@procs },
    { title => "$user network sockets other than web visitors and local ones (now)", alert => 1, lines => \@socks,
      key => sub { (my $k = shift) =~ s/^\S+\s+//; $k } },    # a socket changing state is not news
);
my $findings = 0;
$findings += @{ $_->{lines} } for grep { $_->{alert} } @sections;
my $header = "php-site-watch $VERSION: $day_label on $host, PHP account $user, " . ($read // 0) . " log files read\n"
           . join('', map { "warning: $_\n" } @warn);

if ($mode eq 'alert') {
    my $dir   = $opt{'state-dir'} // '/var/lib/php-site-watch';
    my $state = "$dir/alerted";
    my $since = local_ymd(time - $remember_days * 86400);
    my (%known, @keep);
    if (open my $fh, '<', $state) {
        while (my $l = <$fh>) {
            chomp $l;
            my ($d, $k) = split /\t/, $l, 2;
            next unless defined $k && $d ge $since;
            $known{$k} = 1;
            push @keep, $l;
        }
        close $fh;
    }
    my (@new_sections, @new_keys);
    for my $s (grep { $_->{alert} } @sections) {
        my @new = grep { !$known{ key_of($s, $_) } } @{ $s->{lines} };
        next unless @new;
        push @new_keys, map { key_of($s, $_) } @new;
        push @new_sections, { %$s, lines => \@new, tail => 50, head => undef };
    }
    if (@new_keys) {
        my $n = @new_keys;
        deliver("[php-site-watch] ALERT $host: $n new finding" . ($n == 1 ? '' : 's'),
            $header . render(\@new_sections, 0)
            . "\n$n new item(s) to look at. Each is reported once; run php-site-watch on $host for the full report.\n");
        mkdir $dir, 0700 unless -d $dir;
        open my $fh, '>', "$state.new" or fail("cannot write $state.new: $!");
        print $fh "$_\n" for @keep, map { "$today\t$_" } @new_keys;
        close $fh or fail("cannot write $state.new: $!");
        rename "$state.new", $state or fail("cannot replace $state: $!");
    }
    exit($findings ? 1 : 0);
}

my ($health, @problems) = $quiet ? () : health();
my @all = (@sections, ($health ? $health : ()));
my $summary = $findings ? "$findings item(s) to look at" : @problems ? 'nothing suspicious found, but: ' . join('; ', @problems)
            : 'nothing suspicious found';

if ($mode eq 'status') {
    my $what = $findings ? "$findings finding" . ($findings == 1 ? '' : 's') : @problems ? 'check ' . join('; ', @problems) : 'OK';
    deliver("[php-site-watch] $host $date: $what", $header . render(\@all, 0) . "\n$summary\n");
} elsif (!$quiet || $findings) {
    print $header, render(\@all, $quiet), ($quiet ? '' : "\n$summary\n");
}
exit($findings ? 1 : 0);

# --- helpers ------------------------------------------------------------------------------------

sub render {
    my ($sections, $only_findings) = @_;
    my $out = '';
    for my $s (@$sections) {
        my @l = @{ $s->{lines} };
        next if $only_findings && !($s->{alert} && @l);
        if ($s->{tail} && @l > $s->{tail}) {
            @l = ('... ' . (@l - $s->{tail}) . ' earlier lines not shown', @l[-$s->{tail} .. -1]);
        } elsif ($s->{head} && @l > $s->{head}) {
            @l = (@l[0 .. $s->{head} - 1], '... ' . (@l - $s->{head}) . ' more');
        }
        $out .= "\n== $s->{title}\n" . (@l ? join('', map { "$_\n" } @l) : "(none)\n");
    }
    return $out;
}

sub key_of { my ($s, $line) = @_; return $s->{key} ? $s->{key}->($line) : $line }

sub counted {
    my ($h, $max) = @_;
    my @k = sort { $h->{$b} <=> $h->{$a} || $a cmp $b } keys %$h;
    splice @k, $max if @k > $max;
    return map { sprintf '%6d  %s', $h->{$_}, $_ } @k;
}

# Mail a report through sendmail, or print it when no recipients are configured.
sub deliver {
    my ($subject, $body) = @_;
    unless (defined $opt{'mail-to'}) {
        print "$subject\n\n$body";
        return;
    }
    my $sendmail = $opt{sendmail} // '/usr/sbin/sendmail';
    my @to = split /\s*,\s*/, $opt{'mail-to'};
    my @args = ('-oi', '-t', (defined $opt{'mail-from'} ? ('-f', $opt{'mail-from'}) : ()));
    open my $mh, '|-', $sendmail, @args or fail("cannot run $sendmail: $!");
    print $mh 'To: ', join(', ', @to), "\n";
    print $mh "From: $opt{'mail-from'}\n" if defined $opt{'mail-from'};
    print $mh "Subject: $subject\n", "MIME-Version: 1.0\n", "Content-Type: text/plain; charset=UTF-8\n",
              "Content-Transfer-Encoding: 8bit\n", "Auto-Submitted: auto-generated\n\n", $body;
    close $mh or fail("$sendmail failed (exit status " . ($? >> 8) . "); nothing was mailed");
}

# Basic server health for --status and normal reports: returns the section and the problems found.
sub health {
    my (@lines, @problems);
    my $cpus = 0;
    if (open my $fh, '<', '/proc/cpuinfo') { $cpus = grep { /^processor\s*:/ } <$fh> }
    my ($up)  = split ' ', (first_line('/proc/uptime') // '0');
    my @load  = split ' ', (first_line('/proc/loadavg') // '');
    push @lines, sprintf('up %d days %d h, load %s %s %s, %d CPUs', $up / 86400, ($up % 86400) / 3600, @load[0 .. 2], $cpus)
        if @load >= 3;

    my $systemd = cmd_out('systemctl', 'is-system-running') // '';
    if ($systemd =~ /^(?:running|degraded|starting|maintenance)$/) {
        for my $u (sort map { (split ' ')[0] } cmd_lines('systemctl', 'list-unit-files', '--type=service', '--no-legend', '--no-pager')) {
            next unless $u =~ /^(?:php[\w.-]*fpm|httpd|apache2|nginx)\.service$/;
            my $enabled = cmd_out('systemctl', 'is-enabled', $u) // '?';
            my $active  = cmd_out('systemctl', 'is-active',  $u) // '?';
            next if $enabled ne 'enabled' && $active ne 'active';
            push @lines, "$u: $active ($enabled)";
            push @problems, "$u is $active" if $enabled eq 'enabled' && $active ne 'active';
        }
    }

    my @use;
    for (cmd_lines('df', '-lP', map { ('-x', $_) } qw(tmpfs devtmpfs squashfs overlay efivarfs))) {
        my @f = split ' ';
        next unless @f >= 6 && $f[4] =~ /^(\d+)%$/;
        my ($pct, $mount) = ($1, join(' ', @f[5 .. $#f]));
        push @use, "$mount $pct%";
        push @problems, "disk $mount $pct% full" if $pct >= 90;
    }
    push @lines, 'disk use: ' . join(', ', @use) if @use;

    # the PHP that serves requests: the php-fpm master's binary, or the php command for mod_php setups
    my ($master) = grep { /php-fpm: master process/ } cmd_lines('ps', '-eo', 'pid=,args=');
    my $exe = $master && $master =~ /^\s*(\d+)/ ? readlink("/proc/$1/exe") : undef;
    $exe //= (grep { -x } qw(/usr/bin/php /usr/local/bin/php))[0];
    if ($exe) {
        if ($exe =~ s/ \(deleted\)$//) {
            push @problems, 'php-fpm still runs a binary an update replaced; restart it';
        }
        my $v = cmd_out($exe, '-v') // '';
        push @lines, 'PHP: ' . ($v =~ /^(PHP \S+)/ ? $1 : 'version unknown') . " ($exe)";
        if (grep { -x } qw(/usr/bin/rpm /bin/rpm)) {
            my $pkg = cmd_out('rpm', '-qf', $exe);
            if ($pkg && $pkg !~ /not owned|^error/) {
                my $fixed = grep { /CVE-2026-109618/ } cmd_lines('rpm', '-q', '--changelog', $pkg);
                push @lines, "PHP2Shell fix (CVE-2026-109618/109619) in $pkg: " . ($fixed ? 'yes' : 'NO');
                push @problems, "$pkg lacks the PHP2Shell fix" unless $fixed;
            }
        }
    }
    return ({ title => 'Server health (now)', alert => 0, lines => [ (map { "!! $_" } @problems), @lines ] }, @problems);
}

sub detect_user {
    my (%fpm, %web);
    for my $l (cmd_lines('ps', '-eo', 'user:32=,comm=')) {
        my ($u, $c) = $l =~ /^\s*(\S+)\s+(.*?)\s*$/ or next;
        next if $u eq 'root';
        if    ($c =~ /^php-fpm/)                         { $fpm{$u}++ }
        elsif ($c =~ /^(?:httpd|apache2|lsphp|php-cgi)/) { $web{$u}++ }
    }
    for my $h (\%fpm, \%web) {
        my ($u) = sort { $h->{$b} <=> $h->{$a} || $a cmp $b } keys %$h;
        return $u if defined $u;
    }
    return;
}

sub log_files {
    my ($paths, $pick) = @_;
    my @files;
    for my $p (@$paths) {
        if (-d $p) {
            opendir my $dh, $p or do { push @warn, "cannot read $p"; next };
            push @files, map { "$p/$_" } grep { $_ =~ $pick && -f "$p/$_" } sort readdir $dh;
            closedir $dh;
        } elsif (-f $p) {
            push @files, $p;
        } else {
            push @warn, "no such log path $p";
        }
    }
    return @files;
}

sub open_log {
    my ($f) = @_;
    return quiet_open('gzip', '-dc', '--', $f) if $f =~ /\.gz$/;
    open my $fh, '<', $f or return;
    return $fh;
}

# Run a command for reading, with its error messages discarded.
sub quiet_open {
    open my $saved, '>&', \*STDERR or return;
    open STDERR, '>', '/dev/null';
    my $ok = open my $fh, '-|', @_;
    open STDERR, '>&', $saved;
    return $ok ? $fh : undef;
}

sub cmd_lines {
    my $fh = quiet_open(@_) or return;
    chomp(my @l = <$fh>);
    close $fh;
    return @l;
}

sub cmd_out { my @l = cmd_lines(@_); return @l ? $l[0] : undef }

sub first_line {
    open my $fh, '<', $_[0] or return;
    chomp(my $l = <$fh> // '');
    return $l;
}

# Log text is attacker-controlled: keep control characters out of terminals and mail, and lines short.
sub clean {
    my ($s) = @_;
    $s =~ s/[\x00-\x08\x0b-\x1f\x7f]/?/g;
    $s = substr($s, 0, 497) . '...' if length $s > 500;
    return $s;
}

# The day a log line belongs to, as YYYY-MM-DD, for the formats Apache, nginx, php-fpm and PHP write.
sub line_day {
    my ($l) = @_;
    return ymd($3, $mon{$2}, $1) if $l =~ m{^\S+ \S+ \S+ \[(\d\d)/(\w{3})/(\d{4}):};        # access log
    return ymd($3, $mon{$1}, $2) if $l =~ m{^\[\w{3} (\w{3}) +(\d{1,2}) [\d:.]+ (\d{4})\]};  # Apache error log
    return ymd($3, $mon{$2}, $1) if $l =~ m{^\[(\d\d)-(\w{3})-(\d{4}) };                     # php-fpm, PHP error log
    return ymd($1, $2, $3)       if $l =~ m{^(\d{4})/(\d\d)/(\d\d) [\d:]+ \[};               # nginx error log
    return undef;
}

sub ymd { my ($y, $m, $d) = @_; return defined $m ? sprintf('%04d-%02d-%02d', $y, $m, $d) : undef }

sub local_ymd { my @t = localtime(shift); return sprintf '%04d-%02d-%02d', $t[5] + 1900, $t[4] + 1, $t[3] }

sub days_from_civil {    # days since 1970-01-01 (Howard Hinnant's algorithm)
    my ($y, $m, $d) = @_;
    $y-- if $m <= 2;
    my $era = int($y / 400);
    my $yoe = $y - $era * 400;
    my $doy = int((153 * ($m > 2 ? $m - 3 : $m + 9) + 2) / 5) + $d - 1;
    my $doe = $yoe * 365 + int($yoe / 4) - int($yoe / 100) + $doy;
    return $era * 146097 + $doe - 719468;
}

sub split_hostport {
    my ($s) = @_;
    return ($1, $2) if $s =~ /^\[(.*)\]:(\S+)$/;
    return ($1, $2) if $s =~ /^(.*):(\S+)$/;
    return ($s, '');
}

sub hostname {
    my $h = first_line('/proc/sys/kernel/hostname');
    return defined $h && length $h ? $h : 'unknown-host';
}
