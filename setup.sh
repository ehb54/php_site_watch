#!/bin/bash
# Install, update or remove php-site-watch. Run as root from a clone of
# https://github.com/ehb54/php_site_watch
#
#   ./setup.sh install [--cron] [--mailto ADDRESSES] [--mailfrom ADDRESS]
#   ./setup.sh update
#   ./setup.sh uninstall [--purge]
#
# install   puts the script at /usr/local/sbin/php-site-watch and, only if it doesn't exist yet,
#           a fully commented /etc/php-site-watch.conf; an existing config is never touched.
#           --cron also writes /etc/cron.d/php-site-watch with two jobs that mail through the
#           local sendmail (postfix): an hourly alert about anything new, and a status report
#           every morning at 07:00 on the previous day plus server health. Mail goes to
#           ADDRESSES (comma-separated, default: root). Without --cron, an existing cron job is kept.
# update    pulls the latest version into this clone and reinstalls it, keeping the config
#           and cron job.
# uninstall removes the script and the cron job; --purge also removes /etc/php-site-watch.conf
#           and the alert history in /var/lib/php-site-watch.
set -euo pipefail

here=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
bin=/usr/local/sbin/php-site-watch
conf=/etc/php-site-watch.conf
cron=/etc/cron.d/php-site-watch
state=/var/lib/php-site-watch
addresses='^[A-Za-z0-9._%+@-]+( *, *[A-Za-z0-9._%+@-]+)*$'

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

do_install() {
    local want_cron=0 mailto=root mailfrom=''
    while (($#)); do
        case $1 in
            --cron) want_cron=1 ;;
            --mailto) (($# >= 2)) || die '--mailto needs an address'; mailto=$2; shift ;;
            --mailfrom) (($# >= 2)) || die '--mailfrom needs an address'; mailfrom=$2; shift ;;
            *) die "unknown install option: $1" ;;
        esac
        shift
    done
    [[ $mailto =~ $addresses ]] || die "--mailto: not an address list: $mailto"
    [[ -z $mailfrom || $mailfrom =~ ^[A-Za-z0-9._%+@-]+$ ]] || die "--mailfrom: not an address: $mailfrom"
    if ((want_cron)); then
        [[ -d /etc/cron.d ]] || die "/etc/cron.d is missing; install cron first (dnf install cronie)"
        [[ -x /usr/sbin/sendmail ]] || echo "setup: warning: /usr/sbin/sendmail is missing; install and configure postfix so the reports can be mailed" >&2
    fi
    check_tools
    perl -c "$here/php-site-watch.pl" > /dev/null 2>&1 \
        || die "php-site-watch.pl does not run with this perl: $(perl -c "$here/php-site-watch.pl" 2>&1 | head -3)"

    install -m 755 "$here/php-site-watch.pl" "$bin"
    echo "installed $bin ($("$bin" --version))"

    if [[ -e $conf ]]; then
        echo "kept $conf"
    else
        install -m 644 "$here/php-site-watch.conf.example" "$conf"
        echo "installed $conf (all settings commented out; edit it to suit this site)"
    fi

    if ((want_cron)); then
        local mail="--mail-to ${mailto// /}${mailfrom:+ --mail-from $mailfrom}"
        cat > "$cron" <<EOF
# php-site-watch (installed by setup.sh): an hourly alert about new findings and a status
# report every morning at 07:00, both mailed to $mailto. Cron itself mails only if the
# script fails.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=${mailto// /}
5 * * * * root $bin --alert $mail
0 7 * * * root $bin --status --date yesterday $mail
EOF
        chmod 644 "$cron"
        echo "installed $cron (hourly alerts and a daily status report to $mailto)"
        echo "to check that mail gets through, send a status report now: sudo $bin --status $mail"
    elif [[ -e $cron ]]; then
        echo "kept $cron"
    fi
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
    do_install
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
    *) usage ;;
esac
