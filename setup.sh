#!/bin/bash
# Install, update or remove php-site-watch, and manage who gets its reports. Run as root from a
# clone of https://github.com/ehb54/php_site_watch
#
#   ./setup.sh install [--cron] [--mailto ADDRESSES] [--mailfrom ADDRESS]
#   ./setup.sh update
#   ./setup.sh uninstall [--purge]
#   ./setup.sh mail list | add ADDRESS... | remove ADDRESS... | from ADDRESS|none | test
#   ./setup.sh controller list | add NAME --from ADDRESSES --key KEY | remove NAME
#
# install   puts the script at /usr/local/sbin/php-site-watch and, only if it doesn't exist yet,
#           a fully commented /etc/php-site-watch.conf. --cron also writes /etc/cron.d/php-site-watch
#           with two jobs that mail through the local sendmail (postfix): an hourly alert about
#           anything new, and a status report every morning at 07:00 on the previous day plus
#           server health. --mailto adds recipients (comma-separated), --mailfrom sets the sender.
#           Without --cron, an existing cron job is kept. It also installs site-lockdown, the
#           emergency block for the web ports, with its systemd units and a commented
#           /etc/site-lockdown.conf, and fleet-agent, the one command fleet control hosts may run.
# update    pulls the latest version into this clone and reinstalls it, keeping the config
#           and cron job.
# uninstall removes the scripts, the cron job, the logrotate entry, the site-lockdown units and the
#           control hosts' sudo rule (not while site-lockdown is on); --purge also removes
#           /etc/php-site-watch.conf, the alert history and saved reports in /var/lib/php-site-watch,
#           the run log /var/log/php-site-watch.log, site-lockdown's config, state and log, and the
#           fleet user with its keys.
# mail      lists, adds or removes report recipients (the mail-to lines of the config), sets
#           or clears the sender address, or mails a status report to every recipient now.
#           With no recipients, cron mails the reports to root instead.
# controller lists, adds or removes fleet control hosts. add lets one log in as the fleet user from
#           ADDRESSES (comma-separated addresses or networks) with the public KEY (or --key-file
#           FILE); its key can only run fleet-agent, which reads reports and package lists and can
#           turn site-lockdown on, never off. remove takes that back.
set -euo pipefail

here=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
bin=/usr/local/sbin/php-site-watch
conf=/etc/php-site-watch.conf
cron=/etc/cron.d/php-site-watch
state=/var/lib/php-site-watch
logrotate=/etc/logrotate.d/php-site-watch
runlog=/var/log/php-site-watch.log
lockdown_bin=/usr/local/sbin/site-lockdown
lockdown_conf=/etc/site-lockdown.conf
lockdown_state=/var/lib/site-lockdown
lockdown_log=/var/log/site-lockdown.log
agent_bin=/usr/local/sbin/fleet-agent
unit_dir=/etc/systemd/system
units=(site-lockdown.service site-lockdown.timer)
sudoers=/etc/sudoers.d/fleet-agent
fleet=fleet
address='^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$|^[A-Za-z0-9._-]+$'    # user@host, or a local name like root

die() { echo "setup: $*" >&2; exit 1; }

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
    exit 1
}

check_tools() {
    local t missing=()
    for t in perl ps ss find; do
        command -v "$t" > /dev/null || missing+=("$t")
    done
    ((${#missing[@]})) || return 0
    if command -v apt-get > /dev/null; then
        echo "setup: warning: missing ${missing[*]}; on Debian or Ubuntu: apt-get install procps iproute2" >&2
    else
        echo "setup: warning: missing ${missing[*]}; on RHEL, Rocky or Oracle Linux: dnf install perl-interpreter procps-ng iproute findutils" >&2
    fi
}

ensure_conf() {
    [[ -e $conf ]] && return
    install -m 644 "$here/php-site-watch.conf.example" "$conf"
    echo "installed $conf (all settings commented out; edit it to suit this site)"
}

# --- recipients: the mail-to lines of the config ------------------------------------------------

recipients() {
    [[ -r $conf ]] || return 0
    perl -ne 'next if /^\s*#/; print "$_\n" for /^\s*mail[-_]to\s*=\s*(.*?)\s*$/ ? split(/\s*,\s*/, $1) : ()' "$conf"
}

# cron mails errors (and the reports, when there are no recipients) to its MAILTO
sync_cron_mailto() {
    [[ -e $cron ]] || return 0
    local to
    to=$(recipients | paste -sd, -)
    to=${to:-root}
    if grep -q '^MAILTO=' "$cron"; then
        sed -i "s/^MAILTO=.*/MAILTO=$to/" "$cron"
    else
        sed -i "0,/^PATH=/s//MAILTO=$to\n&/" "$cron"
    fi
}

mail_add() {
    local a
    ensure_conf
    for a in "$@"; do
        [[ $a =~ $address ]] || die "not a mail address: $a"
        if recipients | grep -qixF -- "$a"; then
            echo "$a already gets the reports"
        else
            echo "mail-to = $a" >> "$conf"
            echo "added $a"
        fi
    done
    sync_cron_mailto
}

mail_remove() {
    local a
    [[ -e $conf ]] || die "$conf does not exist"
    for a in "$@"; do
        if recipients | grep -qixF -- "$a"; then
            A=$a perl -i -ne '
                if (!/^\s*#/ && /^(\s*mail[-_]to\s*=\s*)(.*?)\s*$/) {
                    my ($key, $list) = ($1, $2);
                    my @left = grep { lc $_ ne lc $ENV{A} } split /\s*,\s*/, $list;
                    print $key, join(", ", @left), "\n" if @left;
                    next;
                }
                print;' "$conf"
            echo "removed $a"
        else
            echo "$a does not get the reports"
        fi
    done
    sync_cron_mailto
}

mail_from() {
    local a=$1
    ensure_conf
    [[ $a == none || $a =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] || die "not a mail address: $a"
    perl -i -ne 'print unless !/^\s*#/ && /^\s*mail[-_]from\s*=/' "$conf"
    if [[ $a == none ]]; then
        echo "reports are sent from the system's default address"
    else
        echo "mail-from = $a" >> "$conf"
        echo "reports are sent from $a"
    fi
}

do_mail() {
    local sub=${1:-}
    (($#)) && shift
    case $sub in
        list)
            local list
            list=$(recipients)
            if [[ -n $list ]]; then echo "$list"; else echo "no recipients; cron mails the reports to root"; fi
            ;;
        add | remove)
            (($#)) || die "mail $sub needs at least one address"
            ((EUID == 0)) || die "run as root: sudo $0 mail $sub $*"
            "mail_$sub" "$@"
            ;;
        from)
            (($# == 1)) || die "mail from needs one address, or none"
            ((EUID == 0)) || die "run as root: sudo $0 mail from $1"
            mail_from "$1"
            ;;
        test)
            ((EUID == 0)) || die "run as root: sudo $0 mail test"
            [[ -x $bin ]] || die "$bin is not installed; run $0 install first"
            [[ -n $(recipients) ]] || die "no recipients yet; add one with: $0 mail add ADDRESS"
            "$bin" --status || (($? == 1))    # 1 just means there are findings
            echo "status report mailed to: $(recipients | paste -sd, - | sed 's/,/, /g')"
            ;;
        *) usage ;;
    esac
}

# Before 1.4.0 the cron jobs carried --mail-to and --mail-from; move those into the config.
migrate_cron() {
    [[ -e $cron ]] && grep -q -- '--mail-\(to\|from\) ' "$cron" || return 0
    local to from
    # sed rather than grep: a missing option must not fail the pipeline under pipefail
    to=$(sed -n 's/.* --mail-to \([^ ]*\).*/\1/p' "$cron" | head -1)
    from=$(sed -n 's/.* --mail-from \([^ ]*\).*/\1/p' "$cron" | head -1)
    [[ -n $to ]] && mail_add ${to//,/ } > /dev/null
    [[ -n $from ]] && mail_from "$from" > /dev/null
    sed -i -E 's/ --mail-(to|from) [^ ]+//g' "$cron"
    sync_cron_mailto
    echo "moved the report addresses from $cron into $conf"
}

# --- fleet control hosts: the fleet user, its keys and its sudo rule ----------------------------

fleet_home() { getent passwd "$fleet" | cut -d: -f6; }

controller_list() {
    local home
    home=$(fleet_home || true)
    if [[ -z $home || ! -s $home/.ssh/authorized_keys ]]; then
        echo "no control hosts; add one with: $0 controller add NAME --from ADDRESSES --key KEY"
        return 0
    fi
    perl -ne '
        if (/^restrict,from="([^"]+)",command="\S+ --controller (\S+)" (\S+) /) { print "$2  from $1  ($3)\n" }
        elsif (/\S/ && !/^\s*#/) { print "a key line not written by setup.sh, which php-site-watch reports: line $.\n" }' \
        "$home/.ssh/authorized_keys"
}

controller_add() {
    local name=${1:-} from='' key=''
    [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$ ]] || die "controller add NAME: letters, digits, . _ and -, up to 40"
    shift
    while (($#)); do
        case $1 in
            --from) (($# >= 2)) || die '--from needs addresses'; from=$2; shift ;;
            --key) (($# >= 2)) || die '--key needs a public key'; key=$2; shift ;;
            --key-file) (($# >= 2)) || die '--key-file needs a file'; [[ -r $2 ]] || die "cannot read $2"; key=$(head -1 "$2"); shift ;;
            *) die "unknown controller add option: $1" ;;
        esac
        shift
    done
    [[ -n $from ]] || die 'controller add needs --from ADDRESSES: where the control host connects from'
    local a addrs=()
    IFS=', ' read -ra addrs <<< "$from"
    for a in "${addrs[@]}"; do
        [[ $a =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ || $a =~ ^[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(/[0-9]{1,3})?$ ]] \
            || die "--from: not an address or network: $a"
    done
    from=$(IFS=,; echo "${addrs[*]}")
    local ktype kdata rest
    read -r ktype kdata rest <<< "$key"
    [[ $ktype =~ ^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa)$ \
        && $kdata =~ ^[A-Za-z0-9+/]+=*$ ]] || die '--key: not an SSH public key (one line, such as ssh-ed25519 AAAA...)'
    local tmp
    tmp=$(mktemp)
    echo "$ktype $kdata" > "$tmp"
    ssh-keygen -lf "$tmp" > /dev/null 2>&1 || { rm -f "$tmp"; die '--key: ssh-keygen does not accept this key'; }
    rm -f "$tmp"
    [[ -x $agent_bin && -x $lockdown_bin ]] || die "fleet-agent and site-lockdown are not installed; run $0 install first"
    command -v sudo > /dev/null || die 'sudo is not installed; fleet-agent needs it (dnf install sudo, or apt-get install sudo)'

    if ! getent passwd "$fleet" > /dev/null; then
        useradd --system --create-home --home-dir "/home/$fleet" --shell /bin/sh --comment 'fleet control hosts (fleet-agent)' "$fleet"
        echo "created the $fleet user"
    fi
    usermod -p '*' "$fleet"    # no password, but not locked: key logins work with or without PAM
    local home file
    home=$(fleet_home)
    file=$home/.ssh/authorized_keys
    # root's, so the fleet user can never add keys of its own
    install -d -m 755 -o root -g root "$home/.ssh"
    [[ -e $file ]] || install -m 644 -o root -g root /dev/null "$file"
    tmp=$(mktemp)
    grep -v " fleet:$name\$" "$file" > "$tmp" || true
    echo "restrict,from=\"$from\",command=\"$agent_bin --controller $name\" $ktype $kdata fleet:$name" >> "$tmp"
    install -m 644 -o root -g root "$tmp" "$file"
    rm -f "$tmp"

    tmp=$(mktemp)
    cat > "$tmp" <<EOF
# fleet control hosts (installed by setup.sh): fleet-agent re-runs itself as root through this
# for the few requests it allows, and checks them again there.
Defaults:$fleet !requiretty
$fleet ALL=(root) NOPASSWD: $agent_bin --root *
EOF
    visudo -cf "$tmp" > /dev/null || { rm -f "$tmp"; die 'visudo does not accept the sudo rule'; }
    install -m 440 -o root -g root "$tmp" "$sudoers"
    rm -f "$tmp"
    grep -qE '^[#@]includedir /etc/sudoers.d' /etc/sudoers \
        || echo "setup: warning: /etc/sudoers does not include /etc/sudoers.d, so $sudoers has no effect" >&2

    echo "control host $name may connect as $fleet@$(uname -n) from $from"
    echo "it can run: ping, report, packages, lockdown status, lockdown on [--mysql] [REASON]"
    # sshd may only let listed users in
    local limits
    limits=$(sshd -T 2> /dev/null | grep -iE '^(allowusers|allowgroups) ' || true)
    if [[ -n $limits ]] && ! grep -qiE "^allowusers $fleet(@\S+)?$" <<< "$limits"; then
        echo "setup: note: sshd here only lets listed users log in. For this control host, add to /etc/ssh/sshd_config:" >&2
        echo "  AllowUsers ${addrs[*]/#/$fleet@}" >&2
        echo "then check it with sshd -t and reload sshd (systemctl reload sshd)" >&2
    fi
}

controller_remove() {
    local name=${1:-} home file tmp
    (($# == 1)) || die 'controller remove needs one NAME'
    home=$(fleet_home || true)
    file=$home/.ssh/authorized_keys
    [[ -n $home && -e $file ]] && grep -q " fleet:$name\$" "$file" || die "no control host named $name"
    tmp=$(mktemp)
    grep -v " fleet:$name\$" "$file" > "$tmp" || true
    install -m 644 -o root -g root "$tmp" "$file"
    rm -f "$tmp"
    echo "removed control host $name"
    if ! grep -q ' fleet:' "$file"; then
        rm -f "$sudoers"
        echo "removed $sudoers (no control hosts left)"
    fi
}

do_controller() {
    local sub=${1:-}
    (($#)) && shift
    case $sub in
        list) controller_list ;;
        add | remove)
            ((EUID == 0)) || die "run as root: sudo $0 controller $sub $*"
            "controller_$sub" "$@"
            ;;
        *) usage ;;
    esac
}

install_fleet_tools() {
    perl -c "$here/site-lockdown.pl" > /dev/null 2>&1 \
        || die "site-lockdown.pl does not run with this perl: $(perl -c "$here/site-lockdown.pl" 2>&1 | head -3)"
    perl -cT "$here/fleet-agent.pl" > /dev/null 2>&1 \
        || die "fleet-agent.pl does not run with this perl: $(perl -cT "$here/fleet-agent.pl" 2>&1 | head -3)"
    install -m 755 "$here/site-lockdown.pl" "$lockdown_bin"
    install -m 755 "$here/fleet-agent.pl" "$agent_bin"
    echo "installed $lockdown_bin and $agent_bin"
    if [[ ! -e $lockdown_conf ]]; then
        install -m 644 "$here/site-lockdown.conf.example" "$lockdown_conf"
        echo "installed $lockdown_conf (no addresses get through a lockdown yet; add your own there)"
    fi
    if [[ -d $unit_dir ]]; then
        local u
        for u in "${units[@]}"; do
            install -m 644 "$here/systemd/$u" "$unit_dir/$u"
        done
        [[ -d /run/systemd/system ]] && systemctl daemon-reload
    fi
    command -v nft > /dev/null \
        || echo 'setup: warning: nft is missing, so site-lockdown cannot work here; install nftables (dnf install nftables, or apt-get install nftables)' >&2
    return 0
}

# --- install, update, uninstall ---------------------------------------------------------------------

do_install() {
    local want_cron=0 mailto='' mailfrom=''
    while (($#)); do
        case $1 in
            --cron) want_cron=1 ;;
            --mailto) (($# >= 2)) || die '--mailto needs an address'; mailto=$2; shift ;;
            --mailfrom) (($# >= 2)) || die '--mailfrom needs an address'; mailfrom=$2; shift ;;
            *) die "unknown install option: $1" ;;
        esac
        shift
    done
    local a
    for a in ${mailto//,/ }; do
        [[ $a =~ $address ]] || die "--mailto: not a mail address: $a"
    done
    [[ -z $mailfrom || $mailfrom =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] || die "--mailfrom: not a mail address: $mailfrom"
    if ((want_cron)); then
        # other packages can create /etc/cron.d without installing cron itself
        [[ -d /etc/cron.d ]] && { command -v crond || command -v cron; } > /dev/null \
            || die "cron is not installed; install cron first (dnf install cronie, or apt-get install cron)"
        [[ -x /usr/sbin/sendmail ]] || echo "setup: warning: /usr/sbin/sendmail is missing; install and configure postfix so the reports can be mailed" >&2
    fi
    check_tools
    perl -c "$here/php-site-watch.pl" > /dev/null 2>&1 \
        || die "php-site-watch.pl does not run with this perl: $(perl -c "$here/php-site-watch.pl" 2>&1 | head -3)"

    install -m 755 "$here/php-site-watch.pl" "$bin"
    echo "installed $bin ($("$bin" --version))"
    install_fleet_tools
    if [[ -d /etc/logrotate.d ]]; then
        [[ -e $logrotate ]] || echo "installed $logrotate (the run log $runlog is rotated monthly)"
        cat > "$logrotate" <<EOF
# php-site-watch run log (installed by setup.sh)
$runlog {
    monthly
    rotate 12
    compress
    missingok
    notifempty
}
EOF
        chmod 644 "$logrotate"
    fi
    if [[ -e $conf ]]; then echo "kept $conf"; else ensure_conf; fi
    [[ -n $mailto ]] && mail_add ${mailto//,/ } > /dev/null
    [[ -n $mailfrom ]] && mail_from "$mailfrom" > /dev/null
    migrate_cron

    if ((want_cron)); then
        cat > "$cron" <<EOF
# php-site-watch (installed by setup.sh): an hourly alert about new findings and a status report
# every morning at 07:00, mailed to the mail-to recipients in $conf
# (manage them with setup.sh mail). Cron itself mails only if the script fails, or the reports
# themselves when there are no recipients.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=root
5 * * * * root $bin --alert
0 7 * * * root $bin --status --date yesterday
EOF
        chmod 644 "$cron"
        sync_cron_mailto
        echo "installed $cron (hourly alerts and a daily status report)"
    elif [[ -e $cron ]]; then
        sync_cron_mailto
        echo "kept $cron"
    fi
    if [[ -e $cron ]]; then
        local list
        list=$(recipients | paste -sd, - | sed 's/,/, /g')
        echo "reports go to: ${list:-root (no recipients set; add them with: $0 mail add ADDRESS)}"
        [[ -n $list ]] && echo "to check that mail gets through: sudo $0 mail test"
        echo "to see the latest results: sudo $bin --last"
    fi
    return 0
}

do_update() {
    (($# == 0)) || die "update takes no options"
    [[ -d $here/.git ]] || die "$here is not a git clone; clone https://github.com/ehb54/php_site_watch and run update there"
    local owner old new
    owner=$(stat -c %U "$here")
    old=$("$bin" --version 2>/dev/null || echo 'not installed')
    # pull as the clone's owner, so root doesn't end up owning files in someone's checkout
    if [[ $owner == root ]]; then
        git -C "$here" pull --ff-only
    else
        runuser -u "$owner" -- git -C "$here" pull --ff-only
    fi
    # run the freshly pulled setup.sh, which may know about changes this one doesn't
    "$here/setup.sh" install
    new=$("$bin" --version)
    [[ $old == "$new" ]] && echo "version unchanged: $new" || echo "updated: $old -> $new"
}

do_uninstall() {
    local purge=0
    case ${1:-} in
        '') ;;
        --purge) purge=1 ;;
        *) die "unknown uninstall option: $1" ;;
    esac
    # without site-lockdown, nothing would be left to take its block away
    [[ ! -e $lockdown_state/state ]] || die "site-lockdown is on; turn it off first: sudo $lockdown_bin off"
    local f u
    if [[ -d /run/systemd/system ]]; then
        systemctl disable --now --quiet "${units[@]}" 2> /dev/null || true
    fi
    for u in "${units[@]}"; do
        [[ -e $unit_dir/$u ]] && rm -f "$unit_dir/$u" && echo "removed $unit_dir/$u"
    done
    [[ -d /run/systemd/system ]] && systemctl daemon-reload
    for f in "$bin" "$lockdown_bin" "$agent_bin" "$sudoers" "$cron" "$logrotate"; do
        [[ -e $f ]] && rm -f "$f" && echo "removed $f"
    done
    if ((purge)); then
        for f in "$conf" "$lockdown_conf" "$lockdown_log"; do
            [[ -e $f ]] && rm -f "$f" && echo "removed $f"
        done
        for f in "$state" "$lockdown_state"; do
            [[ -d $f ]] && rm -rf "$f" && echo "removed $f"
        done
        for f in "$runlog" "$runlog".*; do
            [[ -e $f ]] && rm -f "$f" && echo "removed $f"
        done
        if getent passwd "$fleet" > /dev/null; then
            userdel -r "$fleet" 2> /dev/null || userdel "$fleet"
            echo "removed the $fleet user and its keys"
        fi
    elif [[ -e $conf ]]; then
        echo "kept $conf (uninstall --purge removes it)"
    fi
    return 0
}

cmd=${1:-}
(($#)) && shift
case $cmd in
    install | update | uninstall)
        ((EUID == 0)) || die "run as root: sudo $0 $cmd${*:+ $*}"
        "do_$cmd" "$@"
        ;;
    mail) do_mail "$@" ;;
    controller) do_controller "$@" ;;
    *) usage ;;
esac
