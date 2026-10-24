#!/usr/bin/perl
# fleet: the inventory of servers that php-site-watch watches, and setting servers up from it. A
# person runs it from their own machine, with their own SSH login and sudo on the servers. Fleet
# control hosts can only read reports and turn site-lockdown on (see fleet-agent), so adding,
# changing and removing servers is done this way, by people.
#
#   fleet [--inventory FILE] list [--group NAME] [--names]
#   fleet [--inventory FILE] check
#   fleet [--inventory FILE] add NAME [--ssh DEST] [--profile lims|vhost|genapp] [--group NAME]...
#                                [--mail-to ADDRESSES] [--mail-from ADDRESS] [--site URL]...
#                                [--no-sites] [--mail-test] [--repo URL] [--dry-run] [--yes]
#   fleet [--inventory FILE] sync [NAME...] [--dry-run] [--yes]
#   fleet [--inventory FILE] remove NAME [--uninstall] [--forget] [--dry-run] [--yes]
#
# list    the servers in the inventory, or those of one profile or group; --names prints only
#         their names
# check   checks the inventory: its sections and settings, addresses and keys
# add     sets up server NAME over SSH (to DEST, default NAME) and writes its section in the
#         inventory. For a server already there, it brings the server back in line with it.
#         - clones php_site_watch (--repo, default GitHub) into the login's ~/php_site_watch, or
#           updates that clone
#         - for a server without settings yet, puts the profile's config in place (lims:
#           examples/us3lims.conf; vhost and genapp are set up by hand after the first report)
#         - runs setup.sh install --cron, and makes the report recipients those of the inventory
#         - adds each control host of the inventory, and removes those no longer in it
#         - adds the lockdown-allow addresses to /etc/site-lockdown.conf
#         - finds the sites in Apache's or nginx's config and asks which to keep, for the outside
#           checks (--site names them instead, --no-sites keeps none)
#         - runs a first check; --mail-test also mails a status report (a first install always does)
# sync    does add's control host, recipient and lockdown-allow steps on servers already in the
#         inventory (all of them, or those named), without updating the software
# remove  takes the control hosts' keys off server NAME and its section out of the inventory;
#         --uninstall also runs setup.sh uninstall there; --forget only edits the inventory, for a
#         server that is gone
#
# add, sync and remove say what they will do and ask first; --dry-run only says it, and --yes
# doesn't ask. The inventory is FILE, or $FLEET_INVENTORY, or inventory.conf in the current
# directory (start from inventory.conf.example). Keep it in a private git repository: fleet
# edits it but never commits.
# https://github.com/ehb54/php_site_watch

use strict;
use warnings;

our $VERSION = '1.11.0';

my $repo_default = 'https://github.com/ehb54/php_site_watch';
my @profiles     = qw(lims vhost genapp);
my %profile_conf = (lims => 'examples/us3lims.conf');    # the others are set up by hand
my $clone        = 'php_site_watch';                     # in the login's home on the server

# the same rules as setup.sh and fleet-agent use
my $re_host = qr/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
my $re_ctl  = qr/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/;
my $re_mail = qr/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$/;
my $re_rcpt = qr/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$|^[A-Za-z0-9._-]+$/;    # or a local name, like root
my $re_key  = qr/^(?:ssh-ed25519|sk-ssh-ed25519\@openssh\.com|ecdsa-sha2-nistp(?:256|384|521)|sk-ecdsa-sha2-nistp256\@openssh\.com|ssh-rsa) [A-Za-z0-9+\/]+=*(?: \S.*)?$/;

# the settings each kind of section may have: one value, or a line per value (many)
my %keys = (
    defaults   => { map({ $_ => 'one' } qw(profile groups mail-to mail-from lockdown-allow repo contact)), notes => 'many' },
    server     => { map({ $_ => 'one' } qw(ssh address profile groups mail-to mail-from lockdown-allow repo contact cloud added)),
                    site => 'many', notes => 'many' },
    controller => { from => 'one', key => 'one', notes => 'many' },
);

$| = 1;
my $self = $0;
for (1 .. 10) {    # through symlinks, such as ~/bin/fleet, to the clone
    my $t = readlink $self;
    last unless defined $t;
    $self = $t =~ m{^/} ? $t : ($self =~ m{^(.*/)} ? $1 : '') . $t;
}
my $here = $self =~ m{^(.*)/[^/]*$} ? $1 : '.';

my $inventory;
my @args = @ARGV;
while (@args && $args[0] =~ /^--/) {
    my $o = shift @args;
    if    ($o eq '--version')         { print "fleet $VERSION\n"; exit 0 }
    elsif ($o eq '--help')            { usage(0) }
    elsif ($o eq '--inventory')       { $inventory = shift @args // usage() }
    elsif ($o =~ /^--inventory=(.+)/) { $inventory = $1 }
    else                              { usage() }
}
$inventory //= $ENV{FLEET_INVENTORY} // 'inventory.conf';
my $cmd = shift(@args) // usage();
my %run = (list => \&cmd_list, check => \&cmd_check, add => \&cmd_add, sync => \&cmd_sync, remove => \&cmd_remove);
my $code = $run{$cmd} or usage();
my $rc = eval { $code->(@args) // 0 };
if (!defined $rc) { print STDERR $@; exit 1 }
exit $rc;

# --- the inventory -----------------------------------------------------------------------------------

# Reads the inventory into sections, each { type, name, line, set => { key => [[value, line], ...] } },
# collecting what is wrong with it in problems.
sub load {
    my ($file, $text) = @_;
    my $inv = { file => $file, lines => [], server => {}, controller => {}, defaults => undef, problems => [] };
    if (!defined $text) {
        -e $file or fail("no inventory at $file; start one from $here/inventory.conf.example, or name it with --inventory FILE or FLEET_INVENTORY");
        open my $fh, '<', $file or fail("cannot read $file: $!");
        local $/;
        $text = <$fh> // '';
        close $fh;
    }
    $inv->{lines} = [ $text =~ /([^\n]*\n|[^\n]+\z)/g ];
    my $cur;
    my $n = 0;
    for my $raw (@{ $inv->{lines} }) {
        $n++;
        (my $l = $raw) =~ s/\r?\n\z//;
        next if $l =~ /^\s*(?:#|$)/;
        if ($l =~ /^\s*\[\s*(.*?)\s*\]\s*$/) {
            my $h = $1;
            my ($type, $name) = header($h);
            $cur = { type => $type // 'unknown', name => $name // $h, line => $n, set => {} };    # takes in its settings
            if (!defined $type) {
                problem($inv, $n, "[$h]: a section is [defaults], [controller NAME] or [the server's host name]");
            } elsif ($type eq 'controller' && $name !~ $re_ctl) {
                problem($inv, $n, "[$h]: a control host's name has letters, digits, . _ and -, up to 40");
            } elsif ($type eq 'server' && ($name !~ $re_host || $name !~ /\./)) {
                problem($inv, $n, "[$h]: not a host name with its domain, like uslims.example.org");
            } elsif (my $seen = $type eq 'defaults' ? $inv->{defaults} : $inv->{$type}{$name}) {
                problem($inv, $n, "[$h] again (first on line $seen->{line})");
            } elsif ($type eq 'defaults') {
                $inv->{defaults} = $cur;
            } else {
                $inv->{$type}{$name} = $cur;
            }
            next;
        }
        if ($l =~ /^\s*([A-Za-z][\w-]*)\s*=\s*(.*?)\s*$/) {
            my ($k, $v) = (lc $1, $2);
            $k =~ tr/_/-/;
            if (!$cur) { problem($inv, $n, "$k = ... comes before any [section]"); next }
            next if $cur->{type} eq 'unknown';
            my $kind = $keys{ $cur->{type} }{$k};
            if (!$kind) {
                problem($inv, $n, "$k: not a setting of " . what($cur) . '; those are ' . join(', ', sort keys %{ $keys{ $cur->{type} } }));
            } elsif ($kind eq 'one' && $cur->{set}{$k}) {
                problem($inv, $n, "$k again in " . what($cur) . " (first on line $cur->{set}{$k}[0][1])");
            } elsif (my $why = invalid($k, $v)) {
                problem($inv, $n, "$k = $v: $why");
            } else {
                push @{ $cur->{set}{$k} }, [ $v, $n ];
            }
            next;
        }
        problem($inv, $n, 'not a [section], a key = value setting or a # comment');
    }
    for my $c (values %{ $inv->{controller} }) {
        $c->{set}{$_} or problem($inv, $c->{line}, "[controller $c->{name}] needs $_ = ...") for qw(from key);
    }
    @{ $inv->{problems} } = sort { $a->[0] <=> $b->[0] } @{ $inv->{problems} };
    return $inv;
}

sub header {
    my ($h) = @_;
    return ('defaults', 'defaults') if $h eq 'defaults';
    return ('controller', $1) if $h =~ /^controller\s+(\S+)$/;
    return ('server', lc $h) if $h =~ /^\S+$/;
    return;
}

sub what { my ($s) = @_; return $s->{type} eq 'defaults' ? '[defaults]' : $s->{type} eq 'controller' ? "[controller $s->{name}]" : "[$s->{name}]" }

sub problem { my ($inv, $line, $text) = @_; push @{ $inv->{problems} }, [ $line, $text ] }

# Why a setting's value won't do, or nothing if it will.
sub invalid {
    my ($k, $v) = @_;
    return 'it is empty' unless length $v;
    return 'it has control characters' if $v =~ /[\x00-\x1f\x7f]/;
    my @list = split /\s*,\s*/, $v;
    if ($k eq 'ssh') {
        return $v =~ /^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9._-]*$/ ? undef : 'not an SSH destination: a name from ~/.ssh/config, a host, or user@host';
    } elsif ($k eq 'address') {
        return $v =~ $re_host || ipv4($v) || ipv6($v) ? undef : 'not a host name or an address';
    } elsif ($k eq 'profile') {
        return (grep { $_ eq $v } @profiles) ? undef : 'the profiles are ' . join(', ', @profiles);
    } elsif ($k eq 'groups') {
        /^[A-Za-z][\w-]*$/ or return "'$_' is not a group name (a letter, then letters, digits, _ and -)" for @list;
    } elsif ($k eq 'mail-to') {
        /$re_rcpt/ or return "'$_' is not a mail address" for @list;
    } elsif ($k eq 'mail-from') {
        return $v =~ $re_mail ? undef : 'not a mail address';
    } elsif ($k eq 'site') {
        return $v =~ m{^https?://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/\S*)?$} ? undef : 'not a URL: http:// or https://, a host name, then a path';
    } elsif ($k eq 'lockdown-allow' || $k eq 'from') {
        ipv4($_) || ipv6($_) or return "'$_' is not an address or network" for @list;
    } elsif ($k eq 'repo') {
        return $v =~ m{^(?:https://|ssh://|git@|/)[^\s']+$} ? undef : 'not a git URL (https://...) or a path';
    } elsif ($k eq 'key') {
        return $v =~ $re_key ? undef : 'not an SSH public key (one line, such as ssh-ed25519 AAAA...)';
    }
    return;    # contact, cloud, notes and added are free text
}

sub ipv4 {
    my ($s) = @_;
    my ($o, $len) = $s =~ m{^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$} or return 0;
    return !(grep { $_ > 255 } split /\./, $o) && (!defined $len || $len <= 32);
}

sub ipv6 {
    my ($s) = @_;
    my ($h, $len) = $s =~ m{^([0-9A-Fa-f:]*:[0-9A-Fa-f:]*)(?:/(\d{1,3}))?$} or return 0;
    return $h =~ /^(?:[0-9A-Fa-f]{0,4}:){1,7}[0-9A-Fa-f]{0,4}$/ && (!defined $len || $len <= 128);
}

# A setting of a section; for servers, [defaults] fills in what the server doesn't set.
sub one { my ($s, $k) = @_; my $v = $s && $s->{set}{$k}; return $v ? $v->[0][0] : undef }
sub many { my ($s, $k) = @_; return map { $_->[0] } @{ ($s && $s->{set}{$k}) // [] } }
sub setting { my ($inv, $s, $k) = @_; return one($s, $k) // one($inv->{defaults}, $k) }
sub setting_list { my @v = split /\s*,\s*/, setting(@_) // ''; return grep { length } @v }

sub must_be_clean {
    my ($inv) = @_;
    return unless @{ $inv->{problems} };
    print STDERR "$inv->{file}:$_->[0]: $_->[1]\n" for @{ $inv->{problems} };
    fail("fix the inventory first (fleet check lists what is wrong)");
}

# Edits the inventory as it is on disk now, through EDIT(lines), so changes made meanwhile are
# kept, and saves it only if it still reads cleanly. Returns whether anything changed.
sub edit_inventory {
    my ($edit) = @_;
    my $inv   = load($inventory);
    my @lines = @{ $inv->{lines} };
    $lines[-1] .= "\n" if @lines && $lines[-1] !~ /\n\z/;
    $edit->(\@lines);
    my $text = join '', @lines;
    return 0 if $text eq join('', @{ $inv->{lines} });
    my $check = load($inventory, $text);
    if (@{ $check->{problems} } > @{ $inv->{problems} }) {
        print STDERR "fleet: (bug) the edit would leave the inventory with: $_->[1] (line $_->[0])\n" for @{ $check->{problems} };
        fail("left $inventory as it was");
    }
    my $tmp  = "$inventory.fleet-$$";
    my $mode = (stat $inventory)[2];
    open my $fh, '>', $tmp or fail("cannot write $tmp: $!");
    print {$fh} $text;
    close $fh or fail("cannot write $tmp: $!");
    chmod $mode & 07777, $tmp if defined $mode;
    rename $tmp, $inventory or fail("cannot replace $inventory: $!");
    return 1;
}

# The lines of a section: its header up to its last setting or comment before the next header
# (the comments and blank lines just before a header belong to that header).
sub span {
    my ($lines, $type, $name) = @_;
    my ($start, $end);
    for my $i (0 .. $#$lines) {
        next unless $lines->[$i] =~ /^\s*\[\s*(.*?)\s*\]\s*$/;
        if (defined $start) { $end = $i; last }
        my ($t, $n) = header($1);
        $start = $i if defined $t && $t eq $type && $n eq $name;
    }
    return unless defined $start;
    $end //= @$lines;
    $end-- while $end > $start + 1 && $lines->[ $end - 1 ] =~ /^\s*(?:#|$)/;
    return ($start, $end);
}

# Puts key = value lines for VALUES where that key's lines are now (or after the section's last
# line); no values removes them.
sub set_key {
    my ($lines, $type, $name, $k, @values) = @_;
    my ($start, $end) = span($lines, $type, $name) or return;
    (my $kp = quotemeta $k) =~ s/\\-/[-_]/g;
    my @at  = grep { $lines->[$_] =~ /^\s*$kp\s*=/i } $start + 1 .. $end - 1;
    my @new = map { "$k = $_\n" } @values;
    my $at  = @at ? $at[0] : $end;
    splice(@$lines, $_, 1) for reverse @at;
    splice(@$lines, $at, 0, @new);
}

sub add_section {
    my ($lines, $header, @settings) = @_;
    push @$lines, "\n" if @$lines && $lines->[-1] !~ /^\s*$/;
    push @$lines, "[$header]\n", map { "$_->[0] = $_->[1]\n" } @settings;
}

# A section, with the comments right above it and the blank lines after it.
sub remove_section {
    my ($lines, $type, $name) = @_;
    my ($start, $end) = span($lines, $type, $name) or return;
    $start-- while $start > 0 && $lines->[ $start - 1 ] =~ /^\s*#/;
    $end++ while $end < @$lines && $lines->[$end] =~ /^\s*$/;
    splice(@$lines, $start, $end - $start);
}

# --- list and check ------------------------------------------------------------------------------------

sub cmd_list {
    my ($o, @rest) = options({ group => 'value', names => 'flag' }, @_);
    usage() if @rest;
    my $inv = load($inventory);
    print STDERR "$inventory:$_->[0]: $_->[1]\n" for @{ $inv->{problems} };
    my @rows;
    for my $s (map { $inv->{server}{$_} } sort keys %{ $inv->{server} }) {
        my $profile = setting($inv, $s, 'profile') // '-';
        my @groups  = setting_list($inv, $s, 'groups');
        next if defined $o->{group} && !grep { $_ eq $o->{group} } $profile, @groups;
        push @rows, [ $s->{name}, one($s, 'ssh') // $s->{name}, $profile, join(',', @groups) || '-', scalar(many($s, 'site')) ];
    }
    if ($o->{names}) { print "$_->[0]\n" for @rows; return 0 }
    table([qw(SERVER SSH PROFILE GROUPS SITES)], @rows) if @rows;
    my @ctl = sort keys %{ $inv->{controller} };
    print @rows ? "\n" : '', scalar(@rows), ' server(s)', (defined $o->{group} ? " in $o->{group}" : ''),
        '; control hosts: ', (@ctl ? join(', ', @ctl) : 'none yet'), "\n";
    return 0;
}

sub cmd_check {
    my ($o, @rest) = options({}, @_);
    usage() if @rest;
    my $inv = load($inventory);
    # ssh-keygen knows keys better than a pattern does
    if (have('ssh-keygen')) {
        for my $c (map { $inv->{controller}{$_} } sort keys %{ $inv->{controller} }) {
            my $k = $c->{set}{key} or next;
            my ($rc) = run_cmd([ 'ssh-keygen', '-l', '-f', '/dev/stdin' ], "$k->[0][0]\n");
            problem($inv, $k->[0][1], "[controller $c->{name}]: ssh-keygen does not accept this key") if $rc;
        }
        @{ $inv->{problems} } = sort { $a->[0] <=> $b->[0] } @{ $inv->{problems} };
    }
    my %key_of;
    for my $c (map { $inv->{controller}{$_} } sort keys %{ $inv->{controller} }) {
        my ($t, $d) = split ' ', one($c, 'key') // next;
        problem($inv, $c->{line}, "[controller $c->{name}] has the same key as [controller $key_of{$d}]") if $key_of{$d};
        $key_of{$d} //= $c->{name};
    }
    print "$inventory:$_->[0]: $_->[1]\n" for @{ $inv->{problems} };
    my @notes;
    my $nctl = keys %{ $inv->{controller} };
    push @notes, "$nctl control host(s); two or more, in different places, keep the servers watched when one is down or stolen" if $nctl < 2;
    for my $s (map { $inv->{server}{$_} } sort keys %{ $inv->{server} }) {
        push @notes, "[$s->{name}] has no profile (nor does [defaults]); fleet add needs one" unless setting($inv, $s, 'profile');
        push @notes, "[$s->{name}] has no mail-to (nor does [defaults]), so its reports go to root there" unless setting($inv, $s, 'mail-to');
        push @notes, "[$s->{name}] has no site to check from outside" unless $s->{set}{site};
    }
    print "note: $_\n" for @notes;
    my $n = keys %{ $inv->{server} };
    if (@{ $inv->{problems} }) {
        print "$inventory: ", scalar(@{ $inv->{problems} }), " problem(s)\n";
        return 1;
    }
    print "$inventory is fine: $n server(s), $nctl control host(s)\n";
    return 0;
}

# --- add, sync and remove ----------------------------------------------------------------------------

sub cmd_add {
    my ($o, @rest) = options({ ssh => 'value', profile => 'value', group => 'multi', 'mail-to' => 'value', 'mail-from' => 'value',
                               site => 'multi', 'no-sites' => 'flag', 'mail-test' => 'flag', repo => 'value', 'dry-run' => 'flag', yes => 'flag' }, @_);
    @rest == 1 or usage("add needs one NAME: the server's host name");
    my $name = lc $rest[0];
    $name =~ $re_host && $name =~ /\./ or fail("$rest[0]: not a host name with its domain, like uslims.example.org");
    for my $k (qw(ssh profile mail-to mail-from repo)) {
        defined $o->{$k} or next;
        my $why = invalid($k, $o->{$k}) or next;
        fail("--$k $o->{$k}: $why");
    }
    for my $u (@{ $o->{site} // [] }) { my $why = invalid('site', $u); fail("--site $u: $why") if $why }
    my $groups = $o->{group} ? join(', ', map { split /\s*,\s*/ } @{ $o->{group} }) : undef;
    if (defined $groups) { my $why = invalid('groups', $groups); fail("--group: $why") if $why }
    fail('--site and --no-sites do not go together') if $o->{site} && $o->{'no-sites'};

    my $inv = load($inventory);
    must_be_clean($inv);
    my $srv = $inv->{server}{$name};
    # what this run sets, over what the inventory says
    my %new = (ssh => $o->{ssh}, profile => $o->{profile}, groups => $groups, 'mail-to' => $o->{'mail-to'}, 'mail-from' => $o->{'mail-from'}, repo => $o->{repo});
    my $want = wanted($inv, $srv, $name, \%new);
    $want->{profile} or fail("which profile does $name have? --profile " . join(', ', @profiles));

    print $srv ? "$name is in the inventory; checking it against that over SSH ($want->{ssh})\n"
               : "looking at $name over SSH ($want->{ssh})\n";
    my $f    = facts($want->{ssh});
    my $plan = plan($inv, $want, $f, 1);
    $plan->{mail_test} = 1 if $o->{'mail-test'} || !$f->{psw};
    if ($plan->{mail_test}) {
        @{ $want->{'mail-to'} } ? push(@{ $plan->{todo} }, 'mail a status report to ' . join(', ', @{ $want->{'mail-to'} }) . ', to see that mail gets through')
                                : push(@{ $plan->{hand} }, "no mail-to for $name, so its reports go to root there; set mail-to in the inventory");
    }

    # the sites, for the outside checks
    my ($found, $aliases) = sites($f);
    my @found = @$found;
    my @have  = many($srv, 'site');
    my @sites;
    my $host = sub { $_[0] =~ m{^\w+://([^/:]+)} ? lc $1 : '' };
    if ($o->{'no-sites'}) {
        @sites = ();
    } elsif ($o->{site}) {
        @sites = @{ $o->{site} };
    } elsif (@have) {
        @sites = @have;
        my %h   = map { $host->($_) => 1 } @have;
        my @not = grep { !$h{ $host->($_) } } @found;
        push @{ $plan->{notes} }, "also served there, but not in the inventory: " . join(', ', @not) . ' (add them with --site)' if @not;
    } elsif (@found) {
        @sites = $o->{yes} || $o->{'dry-run'} || !-t STDIN ? @found : choose(@found);
    }
    if (@$aliases && !@have && !$o->{site} && !$o->{'no-sites'}) {
        my @eg = @$aliases[ 0 .. ($#$aliases < 2 ? $#$aliases : 2) ];
        push @{ $plan->{notes} }, scalar(@$aliases) . ' other name(s) of these sites left out, such as ' . join(', ', @eg) . ' (name them with --site to check them too)';
    }
    my $sites_change = !$srv || $o->{site} || $o->{'no-sites'} || (!@have && @sites);
    my @set;    # the settings to write into the server's section
    if (!$srv) {
        push @set, [ ssh => $want->{ssh} ] if $want->{ssh} ne $name;
        push @set, [ profile => $want->{profile} ];
        push @set, [ $_ => $new{$_} ] for grep { defined $new{$_} } qw(groups mail-to mail-from repo);
        push @set, map { [ site => $_ ] } @sites;
        push @set, [ added => sprintf('%s by %s with fleet %s', today(), whoami(), $VERSION) ];
        push @{ $plan->{todo} }, "add [$name] to $inventory" . (@sites ? ', with ' . scalar(@sites) . ' site(s) to check from outside' : '');
    } else {
        push @set, [ $_ => $new{$_} ] for grep { defined $new{$_} && ($new{$_} ne (one($srv, $_) // '')) } qw(ssh profile groups mail-to mail-from repo);
        push @set, [ site => \@sites ] if $sites_change;
        push @{ $plan->{todo} }, "update [$name] in $inventory: " . join(', ', map { $_->[0] } @set) if @set;
    }
    show($name, $f, $plan, \@sites);
    return 0 if $o->{'dry-run'};
    confirm($o);

    apply($want, $f, $plan) or fail("$name is not set up completely; fix what is above, then run fleet add $name again");
    if (@set && edit_inventory(sub {
            my ($lines) = @_;
            if (!$srv) { add_section($lines, $name, @set); return }
            set_key($lines, 'server', $name, $_->[0], ref $_->[1] ? @{ $_->[1] } : $_->[1]) for @set;
        })) {
        my $dir = $inventory =~ m{^(.*)/} ? $1 : '.';
        print "\n", ($srv ? 'updated' : 'added'), " [$name] in $inventory; look it over and commit it (git -C $dir diff)\n";
    }
    return 0;
}

sub cmd_sync {
    my ($o, @names) = options({ 'dry-run' => 'flag', yes => 'flag' }, @_);
    my $inv = load($inventory);
    must_be_clean($inv);
    @names = sort keys %{ $inv->{server} } unless @names;
    @names or fail("no servers in $inventory yet; add one with fleet add NAME");
    my @bad;
    for my $n (map { lc } @names) {
        $inv->{server}{$n} or fail("$n is not in $inventory");
    }
    for my $n (map { lc } @names) {
        my $want = wanted($inv, $inv->{server}{$n}, $n, {});
        print "\n" if $n ne lc $names[0];
        print "==== $n (ssh $want->{ssh})\n";
        my $f = eval { facts($want->{ssh}) };
        if (!$f) { print $@; push @bad, $n; next }
        if (!$f->{psw} || !$f->{clone}) {
            print "php-site-watch is not set up there from ~/$clone; run fleet add $n first\n";
            push @bad, $n;
            next;
        }
        my $plan = eval { plan($inv, $want, $f, 0) };
        if (!$plan) { print $@; push @bad, $n; next }
        if (!@{ $plan->{todo} }) {
            print "in line with the inventory\n";
            print "by hand: $_\n" for @{ $plan->{hand} };
            next;
        }
        show($n, $f, $plan);
        next if $o->{'dry-run'};
        if (!$o->{yes}) {
            -t STDIN or fail('cannot ask: standard input is not a terminal; pass --yes to go ahead, or --dry-run to look');
            if (ask('Go ahead? [y/N] ', 'n', qr/^[yn]/i) !~ /^y/i) { print "skipped $n\n"; next }
        }
        apply($want, $f, $plan) or push @bad, $n;
    }
    if (@bad) { print "\nnot done: ", join(', ', @bad), "\n"; return 1 }
    return 0;
}

sub cmd_remove {
    my ($o, @rest) = options({ uninstall => 'flag', forget => 'flag', 'dry-run' => 'flag', yes => 'flag' }, @_);
    @rest == 1 or usage('remove needs one NAME');
    fail('--forget leaves the server as it is, so --uninstall does not go with it') if $o->{forget} && $o->{uninstall};
    my $name = lc $rest[0];
    my $inv  = load($inventory);
    must_be_clean($inv);
    my $srv = $inv->{server}{$name} or fail("$name is not in $inventory");
    my $want = wanted($inv, $srv, $name, {});
    my (@todo, $script);
    if (!$o->{forget}) {
        print "looking at $name over SSH ($want->{ssh})\n";
        my $f = facts($want->{ssh});
        $f->{clone} or fail("there is no ~/$clone on $name to run setup.sh from; take it off by hand, or use --forget");
        my @ctl = sort keys %{ controllers_on($f) };
        $script = "cd ~/$clone || fail 'no ~/$clone'\n";
        for my $c (@ctl) {
            push @todo, "remove control host $c";
            $script .= "step 'remove control host $c'\n\$S ./setup.sh controller remove " . shq($c) . " || fail 'setup.sh controller remove $c did not work'\n";
        }
        if ($o->{uninstall}) {
            fail("site-lockdown is on there; turn it off first (ssh $want->{ssh} sudo site-lockdown off)") if ($f->{lockdown} // '') =~ /^lockdown: on/;
            push @todo, 'setup.sh uninstall (keeps /etc/php-site-watch.conf; uninstall --purge by hand removes the rest)';
            $script .= "step 'setup.sh uninstall'\n\$S ./setup.sh uninstall || fail 'setup.sh uninstall did not work'\n";
        }
    }
    push @todo, "take [$name] out of $inventory";
    print "\n$name:\n";
    print "  - $_\n" for @todo;
    return 0 if $o->{'dry-run'};
    confirm($o);
    if (defined $script) {
        my ($rc, $out) = remote($want->{ssh}, remote_script($script), \&shown);
        $out =~ /^\@\@done$/m or fail("$name: stopped" . ($out =~ /^\@\@fail (.*)$/m ? ": $1" : ''));
    }
    edit_inventory(sub { remove_section($_[0], 'server', $name) });
    my $dir = $inventory =~ m{^(.*)/} ? $1 : '.';
    print "\ntook [$name] out of $inventory; commit that (git -C $dir diff)\n";
    return 0;
}

# What the inventory (with this run's settings NEW) wants for a server.
sub wanted {
    my ($inv, $srv, $name, $new) = @_;
    my $get  = sub { $new->{ $_[0] } // setting($inv, $srv, $_[0]) };
    my $list = sub { my $v = $get->(@_) // ''; [ grep { length } split /\s*,\s*/, $v ] };
    return {
        name      => $name,
        ssh       => $new->{ssh} // one($srv, 'ssh') // $name,
        profile   => $get->('profile'),
        repo      => $get->('repo') // $repo_default,
        'mail-to' => $list->('mail-to'),
        'mail-from' => $get->('mail-from'),
        allow     => $list->('lockdown-allow'),
        address   => one($srv, 'address'),
        controllers => [ map { { name => $_, from => join(',', setting_list($inv, $inv->{controller}{$_}, 'from')),
                                 key => join(' ', (split ' ', one($inv->{controller}{$_}, 'key'))[ 0, 1 ]) } }
                         sort keys %{ $inv->{controller} } ],
    };
}

# What the server needs, from what it has (FACTS). With SOFTWARE, also the clone, the profile's
# config, setup.sh install and a first check; without, only the control hosts, the recipients and
# the lockdown-allow addresses.
sub plan {
    my ($inv, $want, $f, $software) = @_;
    my $p = { todo => [], hand => [], notes => [], script => '' };
    my $name = $want->{name};
    $f->{sudo} eq 'yes' or fail("$f->{login} on $name cannot use sudo without a password; fleet needs that (or SSH as root)");
    if ($software) {
        for my $t ([ perl => 'perl', 'perl-interpreter', 'perl' ], [ git => 'git', 'git', 'git' ], [ cron_daemon => 'cron', 'cronie', 'cron' ]) {
            my ($fact, $what, $dnf, $apt) = @$t;
            $f->{$fact} or fail("$name has no $what; install it first (dnf install $dnf, or apt-get install $apt)");
        }
    }
    push @{ $p->{notes} }, "it calls itself $f->{hostname}" if $f->{hostname} && lc $f->{hostname} ne $name;
    push @{ $p->{notes} }, "$name doesn't resolve here, so control hosts may not reach it by that name; set address = in its section"
        if !$want->{address} && !gethostbyname($name);
    my $s = '';
    if ($software) {
        if ($f->{clone}) {
            fail("~/$clone on $name is not on a branch, so git pull cannot update it; put it back on main first: git -C ~/$clone checkout main")
                if ($f->{clone_branch} // '') eq 'HEAD';
            push @{ $p->{notes} }, "~/$clone is on branch $f->{clone_branch}, not main" if $f->{clone_branch} && $f->{clone_branch} ne 'main';
            push @{ $p->{notes} }, "~/$clone comes from $f->{clone_origin}, not $want->{repo}" if repo_id($f->{clone_origin}) ne repo_id($want->{repo});
            push @{ $p->{hand} }, "~/$clone has $f->{clone_changes} changed file(s), so git pull may refuse; look at them (git -C ~/$clone status)" if $f->{clone_changes};
            push @{ $p->{todo} }, "update ~/$clone (git pull)" . ($f->{psw} ? ", now at $f->{clone_head}" : '');
            $s .= "step 'update ~/$clone'\ngit -C ~/$clone pull -q --ff-only || fail 'git pull in ~/$clone did not work'\n";
        } else {
            push @{ $p->{todo} }, "clone $want->{repo} into ~/$clone";
            $s .= "step 'clone $want->{repo}'\ngit clone -q " . shq($want->{repo}) . " ~/$clone || fail 'git clone $want->{repo} did not work'\n";
        }
        $s .= "cd ~/$clone || fail 'no ~/$clone'\necho \"~/$clone is at \$(git log --oneline -1)\"\n";
        my @conf = settings_of($f->{config});
        my $tmpl = $profile_conf{ $want->{profile} };
        if (!@conf && $tmpl) {
            push @{ $p->{todo} }, "put $tmpl in place as /etc/php-site-watch.conf (the $want->{profile} profile)";
            $s .= "if [ ! -s /etc/php-site-watch.conf ] || ! \$S grep -qvE '^[[:space:]]*(#|\$)' /etc/php-site-watch.conf; then\n"
                . "    \$S install -m 644 $tmpl /etc/php-site-watch.conf || fail 'could not install $tmpl'\n"
                . "    echo 'installed $tmpl as /etc/php-site-watch.conf'\nfi\n";
        } elsif (!@conf) {
            push @{ $p->{hand} }, "/etc/php-site-watch.conf has no settings yet: after the first report, set the user and the excludes for this site (the $want->{profile} profile has no ready config)";
        } elsif ($tmpl && open my $fh, '<', "$here/$tmpl") {
            my %has  = map { $_ => 1 } @conf;
            my @miss = grep { !$has{$_} } settings_of([<$fh>]);
            push @{ $p->{notes} }, scalar(@miss) . " setting(s) of $tmpl are not in its /etc/php-site-watch.conf:\n" . join('', map { "      $_\n" } @miss) if @miss;
        }
        my @opt = ('--cron');
        push @opt, '--mailfrom', $want->{'mail-from'} if $want->{'mail-from'};
        push @{ $p->{todo} }, ($f->{psw} ? "reinstall ($f->{psw} now)" : 'install') . ': setup.sh install ' . join(' ', @opt) . ', for hourly alerts and a daily status report';
        $s .= "step 'setup.sh install'\n\$S ./setup.sh install " . join(' ', map { shq($_) } @opt) . " || fail 'setup.sh install did not work'\n";
    } else {
        $s .= "cd ~/$clone || fail 'no ~/$clone'\n";
    }

    # report recipients: those of the inventory, and no others
    my %rcpt = map { lc $_ => $_ } recipients($f->{config});
    my %want = map { lc $_ => $_ } @{ $want->{'mail-to'} };
    my @add  = grep { !$rcpt{ lc $_ } } @{ $want->{'mail-to'} };
    my @drop = map { $rcpt{$_} } grep { !$want{$_} } sort keys %rcpt;
    @drop = () unless @{ $want->{'mail-to'} };    # the inventory names none: leave the server's as they are
    if (@add) {
        push @{ $p->{todo} }, 'send the reports to ' . join(', ', @add);
        $s .= "step 'report recipients'\n\$S ./setup.sh mail add " . join(' ', map { shq($_) } @add) . " || fail 'setup.sh mail add did not work'\n";
    }
    if (@drop) {
        push @{ $p->{todo} }, 'stop sending the reports to ' . join(', ', @drop) . ' (not in the inventory)';
        $s .= "step 'report recipients'\n\$S ./setup.sh mail remove " . join(' ', map { shq($_) } @drop) . " || fail 'setup.sh mail remove did not work'\n";
    }

    # control hosts: those of the inventory, as it has them, and no others
    my $on = controllers_on($f);
    my %in = map { $_->{name} => 1 } @{ $want->{controllers} };
    for my $c (@{ $want->{controllers} }) {
        my $h = $on->{ $c->{name} };
        next if $h && $h->{from} eq $c->{from} && $h->{key} eq $c->{key};
        push @{ $p->{todo} }, ($h ? 'update' : 'add') . " control host $c->{name} (from $c->{from})";
        $s .= "step 'control host $c->{name}'\n\$S ./setup.sh controller add " . join(' ', map { shq($_) } $c->{name}, '--from', $c->{from}, '--key', $c->{key})
            . " || fail 'setup.sh controller add $c->{name} did not work'\n";
    }
    for my $c (grep { !$in{$_} } sort keys %$on) {
        push @{ $p->{todo} }, "remove control host $c (not in the inventory)";
        $s .= "step 'remove control host $c'\n\$S ./setup.sh controller remove " . shq($c) . " || fail 'setup.sh controller remove $c did not work'\n";
    }
    push @{ $p->{notes} }, "$f->{odd_keys} key line(s) of the fleet user were not written by setup.sh; php-site-watch reports them" if $f->{odd_keys};
    my @limits = @{ $f->{sshd} // [] };
    if (@{ $want->{controllers} } && @limits && !grep { /^allowusers\s+fleet(?:@\S+)?$/i } @limits) {
        my @at = map { "fleet\@$_" } map { split /,/, $_->{from} } @{ $want->{controllers} };
        push @{ $p->{hand} }, 'sshd there only lets listed ' . (grep({ /^allowgroups/i } @limits) ? 'users or groups' : 'users')
            . " in: add AllowUsers @at to /etc/ssh/sshd_config, check it with sshd -t, then systemctl reload sshd";
    }

    # addresses that get through a lockdown: add those of the inventory (the server may have more)
    my %allowed = map { lc $_ => 1 } allowed($f->{lockdown_conf});
    my @allow   = grep { !$allowed{ lc $_ } } @{ $want->{allow} };
    if (@allow) {
        push @{ $p->{todo} }, 'let ' . join(', ', @allow) . ' through a lockdown (/etc/site-lockdown.conf)';
        $s .= "step 'lockdown-allow'\n";
        $s .= "echo " . shq("allow = $_") . " | \$S tee -a /etc/site-lockdown.conf > /dev/null || fail 'could not add to /etc/site-lockdown.conf'\n" for @allow;
        push @{ $p->{hand} }, 'site-lockdown is on there: run site-lockdown on again so the new allow lines take effect' if ($f->{lockdown} // '') =~ /^lockdown: on/;
    }
    if ($software) {
        push @{ $p->{todo} }, 'run a first check (php-site-watch --quiet)';
        $s .= "step 'first check'\nrc=0; \$S /usr/local/sbin/php-site-watch --quiet || rc=\$?\necho \"\@\@check \$rc\"\n";
    }
    $p->{script} = $s;
    $p->{software} = $software;
    return $p;
}

sub show {
    my ($name, $f, $p, $sites) = @_;
    print "\n$name: $f->{os}; $f->{login}", ($f->{login} eq 'root' ? '' : ' with sudo'), "\n";
    print "  php-site-watch: ", $f->{psw} // 'not installed', ($f->{lockdown} ? "; $f->{lockdown}" : ''), "\n";
    if ($sites) {
        print "  sites to check from outside: ", (@$sites ? '' : 'none'), "\n";
        print "    $_\n" for @$sites;
    }
    print "  note: $_\n" for @{ $p->{notes} };
    print "To do:\n";
    print "  - $_\n" for @{ $p->{todo} };
    if (@{ $p->{hand} }) {
        print "By hand, afterwards:\n";
        print "  - $_\n" for @{ $p->{hand} };
    }
}

# Runs the plan's script on the server, showing its output, and says how it went.
sub apply {
    my ($want, $f, $p) = @_;
    my $s = $p->{script};
    # only once php-site-watch runs: without a PHP account set or running, it can't yet
    $s .= "if [ \"\${rc:-0}\" -le 1 ]; then\n    step 'mail test'\n    \$S ./setup.sh mail test || fail 'setup.sh mail test did not work'\nelse\n    echo '\@\@nomail'\nfi\n"
        if $p->{mail_test} && @{ $want->{'mail-to'} };
    print "\n";
    my ($rc, $out) = remote($want->{ssh}, remote_script($s), \&shown);
    if ($out !~ /^\@\@done$/m) {
        print "\nfleet: $want->{name}: stopped", ($out =~ /^\@\@fail (.*)$/m ? ": $1" : " (ssh exit $rc)"), "\n";
        return 0;
    }
    if ($out =~ /^\@\@check (\d+)$/m) {
        print "\nfirst check: ", ($1 == 0 ? 'nothing suspicious found'
            : $1 == 1 ? "findings, above; for each that is normal on this server, add an exclude or allow line to its /etc/php-site-watch.conf"
            : "php-site-watch could not run (exit $1); see above"), "\n";
    }
    push @{ $p->{hand} }, "no test mail was sent, since php-site-watch cannot run yet; once it does: ssh $want->{ssh} sudo ~/$clone/setup.sh mail test"
        if $out =~ /^\@\@nomail$/m;
    if (@{ $p->{hand} }) {
        print "\nstill to do by hand on $want->{name}:\n";
        print "  - $_\n" for @{ $p->{hand} };
    }
    return 1;
}

# How remote output is shown: steps as headings, everything else indented.
sub shown {
    my ($l) = @_;
    return "-- $1\n" if $l =~ /^\@\@step (.*)$/;
    return '' if $l =~ /^\@\@/;
    return "   $l";
}

# --- the server's side --------------------------------------------------------------------------------

# What a server has, read over SSH without changing anything.
sub facts {
    my ($dest) = @_;
    my ($rc, $out) = remote($dest, remote_script(<<'EOF'));
f() { printf '@@ %s=%s\n' "$1" "$2"; }
block() { echo "@@begin $1"; shift; "$@" 2> /dev/null; echo '@@end'; }
f login "$(id -un)"
if [ -z "$S" ] || sudo -n true 2> /dev/null; then f sudo yes; else f sudo no; S=false; fi
f os "$( (. /etc/os-release && echo "$PRETTY_NAME") 2> /dev/null || uname -sr)"
f hostname "$(hostname -f 2> /dev/null || hostname)"
command -v perl > /dev/null && f perl yes
command -v git > /dev/null && f git yes
[ -d /etc/cron.d ] && { command -v crond || command -v cron; } > /dev/null && f cron_daemon yes
[ -x /usr/local/sbin/php-site-watch ] && f psw "$(/usr/local/sbin/php-site-watch --version 2>&1 | head -1)"
c=~/php_site_watch
if [ -d "$c/.git" ]; then
    f clone "$c"
    f clone_head "$(git -C "$c" log --oneline -1 2>&1)"
    f clone_branch "$(git -C "$c" rev-parse --abbrev-ref HEAD 2>&1)"
    f clone_origin "$(git -C "$c" config --get remote.origin.url)"
    f clone_changes "$(git -C "$c" status --porcelain 2> /dev/null | grep -c .)"
fi
[ "$S" = false ] && { echo '@@done'; exit 0; }
block config $S cat /etc/php-site-watch.conf
h=$(getent passwd fleet | cut -d: -f6)
[ -n "$h" ] && block keys $S cat "$h/.ssh/authorized_keys"
[ -x /usr/local/sbin/site-lockdown ] && f lockdown "$($S /usr/local/sbin/site-lockdown status 2>&1 | head -1)"
block lockdown_conf $S cat /etc/site-lockdown.conf
echo '@@begin sshd'; $S sshd -T 2> /dev/null | grep -iE '^(allowusers|allowgroups) '; echo '@@end'
for a in httpd apache2ctl; do    # Rocky's apachectl doesn't pass -S on; Debian's apache2 needs apache2ctl's settings
    if command -v $a > /dev/null; then block apache $S $a -S; break; fi
done
command -v nginx > /dev/null && block nginx $S nginx -T
EOF
    my (%f, $block);
    for (split /\n/, $out) {
        if (/^\@\@begin (\w+)$/) { $block = $1; $f{$block} = []; next }
        if (/^\@\@end$/)         { undef $block; next }
        if (defined $block)      { push @{ $f{$block} }, $_; next }
        $f{$1} = $2 if /^\@\@ (\w+)=(.*)$/;
    }
    defined $f{login} && $out =~ /^\@\@done$/m or fail("cannot look at $dest over SSH (exit $rc)" . (length $out ? ":\n" . join('', map { "  $_\n" } split /\n/, $out) : ''));
    return \%f;
}

# The remote side of a script: bash reads it all first, so nothing in it can eat the rest of the
# script from standard input.
sub remote_script {
    my ($body) = @_;
    return <<EOF;
main() {
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\$PATH
export LC_ALL=C
S='sudo -n'; [ "\$(id -u)" = 0 ] && S=
step() { echo "\@\@step \$*"; }
fail() { echo "\@\@fail \$*"; exit 1; }
$body
echo '\@\@done'
}
main < /dev/null
EOF
}

# The control hosts setup.sh has given keys to, by name, and the count of other key lines.
sub controllers_on {
    my ($f) = @_;
    my %on;
    $f->{odd_keys} = 0;
    for (@{ $f->{keys} // [] }) {
        if (/^restrict,from="([^"]+)",command="\S+ --controller (\S+)" (\S+ \S+) fleet:\2$/) {
            $on{$2} = { from => $1, key => $3 };
        } elsif (/\S/ && !/^\s*#/) {
            $f->{odd_keys}++;
        }
    }
    return \%on;
}

# The settings of a php-site-watch config, written one way: key = value
sub settings_of {
    my ($lines) = @_;
    my @s;
    for (@{ $lines // [] }) {
        next if /^\s*(?:#|$)/;
        push @s, /^\s*([\w-]+)\s*=\s*(.*?)\s*$/ ? lc($1) . " = $2" : do { (my $l = $_) =~ s/^\s+|\s+$//g; $l };
    }
    return @s;
}

sub recipients {
    my ($lines) = @_;
    return map { /^mail[-_]to = (.*)$/ ? split(/\s*,\s*/, $1) : () } settings_of($lines);
}

sub allowed {
    my ($lines) = @_;
    my @a;
    for (@{ $lines // [] }) {
        (my $l = $_) =~ s/#.*//;
        push @a, split /[\s,]+/, $1 if $l =~ /^\s*allow\s*=\s*(.*?)\s*$/;
    }
    return @a;
}

# The sites a server's web server is set up for, by their main names (ServerName, or the first of
# server_name), https for those on 443, else http; and its other names (the aliases, like www.).
sub sites {
    my ($f) = @_;
    my (%ports, %main);
    my $cur;
    # a name's ports, with an s where it is served over TLS (Apache's -S doesn't say: 443 is)
    my $port = sub { my ($n, $p, $is_main) = @_; $ports{ lc $n }{$p} = 1; $main{ lc $n } = 1 if $is_main };
    my $usable = sub {
        my ($n) = @_;
        return $n =~ /\./ && $n !~ /[*~]/ && $n !~ /^[\d.]+$/ && $n !~ /\.(?:local|localdomain)$/i && $n =~ $re_host;
    };
    for (@{ $f->{apache} // [] }) {
        if    (/^\s+port (\d+) namevhost (\S+)/)  { $cur = $1 == 443 ? '443s' : $1; $port->($2, $cur, 1) }
        elsif (/^\s+alias (\S+)/ && defined $cur) { $port->($1, $cur) }
        elsif (/^\S*:(\d+)\s+(?!is a )(\S+) \(/)  { $cur = $1 == 443 ? '443s' : $1; $port->($2, $cur, 1) }
        elsif (/^\S/)                             { undef $cur }
    }
    # nginx -T, statement by statement: the listen and server_name of each server { } in http { },
    # or at the top of a file, since nginx -T prints each included file (like conf.d/*.conf,
    # included in http { }) by itself
    my @files = ('');
    for (@{ $f->{nginx} // [] }) {
        if (/^# configuration file .*:$/) { push @files, ''; next }
        (my $l = $_) =~ s/#.*//;
        $files[-1] .= "$l\n";
    }
    for my $text (@files) {
        my (@blocks, $srv);
        while ($text =~ /\G\s*([^{};]*?)\s*([{};])/gc) {
            my ($stmt, $tok) = ($1, $2);
            if ($tok eq '{') {
                push @blocks, $stmt;
                $srv = { depth => scalar @blocks, listen => [], names => [] } if !$srv && $stmt eq 'server' && (@blocks == 1 || $blocks[-2] eq 'http');
            } elsif ($tok eq ';') {
                next unless $srv && @blocks == $srv->{depth};
                if ($stmt =~ /^listen\s+(.+)$/s) {
                    my $spec = $1;
                    my $p = $spec =~ /(?:^|:)(\d+)(?:\s|$)/ ? $1 : 80;    # listen 127.0.0.1; means port 80
                    push @{ $srv->{listen} }, $p . ($spec =~ /\bssl\b/ || $p == 443 ? 's' : '');
                } elsif ($stmt =~ /^server_name\s+(.+)$/s) {
                    push @{ $srv->{names} }, split ' ', $1;
                }
            } else {
                if ($srv && @blocks == $srv->{depth}) {
                    my ($first) = grep { $usable->($_) } @{ $srv->{names} };
                    for my $n (@{ $srv->{names} }) {
                        $port->($n, $_, defined $first && $n eq $first) for (@{ $srv->{listen} } ? @{ $srv->{listen} } : 80);
                    }
                    undef $srv;
                }
                pop @blocks;
            }
        }
    }
    my (@urls, @aliases);
    for my $n (sort keys %ports) {
        next unless $usable->($n);
        # an alias, or the www. twin of a site
        if (!$main{$n} || ($n =~ /^www\.(.+)$/ && $main{$1})) { push @aliases, $n; next }
        my %p = %{ $ports{$n} };
        if    ($p{'443s'}) { push @urls, "https://$n/" }
        elsif ($p{80})     { push @urls, "http://$n/" }
        else {
            my ($q) = sort keys %p;
            push @urls, $q =~ /^(\d+)s$/ ? "https://$n:$1/" : "http://$n:$q/";
        }
    }
    return (\@urls, \@aliases);
}

# --- running things -------------------------------------------------------------------------------------

my %masters;

sub ssh_command {
    my ($dest) = @_;
    my @o = ('-o', 'ConnectTimeout=20', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=4');
    push @o, '-o', 'BatchMode=yes' unless -t STDIN;
    # one connection per server for the whole run, so a key that wants a touch asks once
    if (defined $ENV{HOME} && -d "$ENV{HOME}/.ssh" && -O _) {
        push @o, '-o', 'ControlMaster=auto', '-o', "ControlPath=$ENV{HOME}/.ssh/fleet-%C", '-o', 'ControlPersist=60';
        $masters{$dest} = 1;
    }
    return ('ssh', @o, $dest);
}

END {
    local $?;    # fleet's own exit status, which run_cmd would overwrite
    for my $d (keys %masters) {
        run_cmd([ 'ssh', '-o', "ControlPath=$ENV{HOME}/.ssh/fleet-%C", '-O', 'exit', $d ], '');
    }
}

sub remote {
    my ($dest, $script, $show) = @_;
    return run_cmd([ ssh_command($dest), 'bash -s' ], $script, $show);
}

# Runs CMD with INPUT on its standard input; returns its exit status and its output (with
# standard error), shown line by line as it comes through SHOW when given.
sub run_cmd {
    my ($cmd, $input, $show) = @_;
    pipe(my $r, my $w) or fail("pipe: $!");
    my $pid = open(my $out, '-|');
    defined $pid or fail("cannot fork: $!");
    if (!$pid) {
        %masters = ();    # the END block is the parent's
        close $w;
        open STDIN, '<&', $r or exit 127;
        open STDERR, '>&', \*STDOUT or exit 127;
        exec { $cmd->[0] } @$cmd or do { print "cannot run $cmd->[0]: $!\n"; exit 127 };
    }
    close $r;
    {
        local $SIG{PIPE} = 'IGNORE';    # the command may be gone before it read it all
        print {$w} $input // '';
        close $w;
    }
    my $text = '';
    while (my $l = <$out>) {
        $text .= $l;
        print $show->($l) if $show;
    }
    close $out;
    return ($? >> 8, $text);
}

sub have { my ($c) = @_; return scalar grep { -f "$_/$c" && -x _ } split /:/, $ENV{PATH} // '' }

# A repository URL without the parts that don't change where it leads
sub repo_id { my ($u) = @_; $u = lc($u // ''); $u =~ s{(?:\.git)?/*$}{}; return $u }

sub shq { my ($s) = @_; $s =~ s/'/'\\''/g; return "'$s'" }

# --- talking to the person ------------------------------------------------------------------------------

sub confirm {
    my ($o) = @_;
    return if $o->{yes};
    -t STDIN or fail('cannot ask: standard input is not a terminal; pass --yes to go ahead, or --dry-run to look');
    ask('Go ahead? [y/N] ', 'n', qr/^[yn]/i) =~ /^y/i or fail('nothing done');
}

sub ask {
    my ($q, $default, $ok) = @_;
    while (1) {
        print $q;
        my $reply = <STDIN>;
        defined $reply or fail('no answer');
        $reply =~ s/^\s+|\s+$//g;
        $reply = $default unless length $reply;
        return $reply if $reply =~ $ok;
    }
}

sub choose {
    my (@found) = @_;
    print "\nSites in the web server's config:\n";
    printf "  %2d  %s\n", $_ + 1, $found[$_] for 0 .. $#found;
    my $answer = ask('Which go in the inventory, for the outside checks? [all], none, or numbers like 1 3 5-7: ', 'all',
                qr/^(?:all|none|(?:\d+(?:-\d+)?[\s,]*)+)$/i);
    return @found if lc $answer eq 'all';
    return () if lc $answer eq 'none';
    my %pick;
    for (split /[\s,]+/, $answer) {
        my ($x, $y) = /^(\d+)(?:-(\d+))?$/;
        $pick{$_} = 1 for grep { $_ >= 1 && $_ <= @found } $x .. ($y // $x);
    }
    return map { $found[ $_ - 1 ] } sort { $a <=> $b } keys %pick;
}

sub table {
    my ($head, @rows) = @_;
    my @w = map { length } @$head;
    for my $r (@rows) { $w[$_] = length $r->[$_] > $w[$_] ? length $r->[$_] : $w[$_] for 0 .. $#$r }
    my $fmt = join('  ', map { "%-${_}s" } @w[ 0 .. $#w - 1 ]) . "  %s\n";
    printf $fmt, @$_ for $head, @rows;
}

# Options of a command, by SPEC: flag, value, or multi (may be given more than once).
sub options {
    my ($spec, @a) = @_;
    my (%o, @rest);
    while (@a) {
        my $x = shift @a;
        if ($x !~ /^--([a-z-]+)(?:=(.*))?$/s) { push @rest, $x; next }
        my ($k, $v) = ($1, $2);
        my $t = $spec->{$k} or usage("unknown option --$k");
        if ($t eq 'flag') {
            usage("--$k takes no value") if defined $v;
            $o{$k} = 1;
            next;
        }
        $v //= shift @a;
        defined $v or usage("--$k needs a value");
        if ($t eq 'multi') { push @{ $o{$k} }, $v } else { $o{$k} = $v }
    }
    return (\%o, @rest);
}

sub today { my @t = localtime; return sprintf '%04d-%02d-%02d', $t[5] + 1900, $t[4] + 1, $t[3] }

sub whoami { return $ENV{USER} // scalar(getpwuid $<) // 'unknown' }

sub usage {
    my ($why) = @_;
    my $ok = defined $why && $why eq '0';
    print STDERR "fleet: $why\n" if defined $why && !$ok;
    open my $fh, '<', $self or exit 2;
    my $text = '';
    while (<$fh>) {
        next if $. == 1;
        last unless /^#/;
        s/^# ?//;
        $text .= $_;
    }
    print { $ok ? \*STDOUT : \*STDERR } $text;
    exit($ok ? 0 : 2);
}

sub fail { die "fleet: $_[0]\n" }
