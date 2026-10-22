#!/bin/bash
# Install, update or remove php-site-watch, and manage who gets its reports. Run as root from a
# clone of https://github.com/ehb54/php_site_watch
#
#   ./setup.sh install [--cron] [--mailto ADDRESSES] [--mailfrom ADDRESS]
#   ./setup.sh update
#   ./setup.sh uninstall [--purge]
#   ./setup.sh mail list | add ADDRESS... | remove ADDRESS... | from ADDRESS|none | test
#
# install   puts the script at /usr/local/sbin/php-site-watch and, only if it doesn't exist yet,
#           a fully commented /etc/php-site-watch.conf. --cron also writes /etc/cron.d/php-site-watch
#           with two jobs that mail through the local sendmail (postfix): an hourly alert about
#           anything new, and a status report every morning at 07:00 on the previous day plus
#           server health. --mailto adds recipients (comma-separated), --mailfrom sets the sender.
#           Without --cron, an existing cron job is kept.
# update    pulls the latest version into this clone and reinstalls it, keeping the config
#           and cron job.
# uninstall removes the script and the cron job; --purge also removes /etc/php-site-watch.conf
#           and the alert history in /var/lib/php-site-watch.
# mail      lists, adds or removes report recipients (the mail-to lines of the config), sets
#           or clears the sender address, or mails a status report to every recipient now.
#           With no recipients, cron mails the reports to root instead.
set -euo pipefail

here=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
bin=/usr/local/sbin/php-site-watch
conf=/etc/php-site-watch.conf
cron=/etc/cron.d/php-site-watch
state=/var/lib/php-site-watch
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
    if ((${#missing[@]})); then
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
    to=$(grep -o -- '--mail-to [^ ]*' "$cron" | head -1 | cut -d' ' -f2)
    from=$(grep -o -- '--mail-from [^ ]*' "$cron" | head -1 | cut -d' ' -f2)
    [[ -n $to ]] && mail_add ${to//,/ } > /dev/null
    [[ -n $from ]] && mail_from "$from" > /dev/null
    sed -i -E 's/ --mail-(to|from) [^ ]+//g' "$cron"
    sync_cron_mailto
    echo "moved the report addresses from $cron into $conf"
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
        [[ -d /etc/cron.d ]] || die "/etc/cron.d is missing; install cron first (dnf install cronie)"
        [[ -x /usr/sbin/sendmail ]] || echo "setup: warning: /usr/sbin/sendmail is missing; install and configure postfix so the reports can be mailed" >&2
    fi
    check_tools
    perl -c "$here/php-site-watch.pl" > /dev/null 2>&1 \
        || die "php-site-watch.pl does not run with this perl: $(perl -c "$here/php-site-watch.pl" 2>&1 | head -3)"

    install -m 755 "$here/php-site-watch.pl" "$bin"
    echo "installed $bin ($("$bin" --version))"
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
    local f
    for f in "$bin" "$cron"; do
        [[ -e $f ]] && rm -f "$f" && echo "removed $f"
    done
    if ((purge)); then
        [[ -e $conf ]] && rm -f "$conf" && echo "removed $conf"
        [[ -d $state ]] && rm -rf "$state" && echo "removed $state"
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
    *) usage ;;
esac
