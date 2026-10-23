#!/bin/bash
# Static checks, run by CI on every pull request; from the repository directory: bash test/lint.sh
# Perl syntax (fleet-agent in taint mode); no modules beyond strict and warnings, since EL9 and
# EL10 package the others separately (perl-POSIX, perl-Socket, ...) and a minimal server may lack
# them; the same version in all three scripts and at the top of the README's Versions; shellcheck
# on the shell scripts; and systemd-analyze verify on the units. shellcheck and systemd-analyze
# are skipped, with a note, where they are not installed.
set -u
cd "$(dirname "$0")/.." || exit 9
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
scripts=(php-site-watch.pl site-lockdown.pl fleet-agent.pl)

for s in php-site-watch.pl site-lockdown.pl; do
    check "$s: perl syntax" 'perl -c "$s" 2> /dev/null'
done
check 'fleet-agent.pl: perl syntax in taint mode' 'perl -cT fleet-agent.pl 2> /dev/null'
modules=$(grep -nE '^\s*(use|require)\s+[A-Z]|^#!.*\s-M' "${scripts[@]}")
check 'no modules beyond strict and warnings' '[[ -z $modules ]] || { echo "$modules"; false; }'

versions=$(for s in "${scripts[@]}"; do sed -n "s/^our \$VERSION = '\(.*\)';/\1/p" "$s"; done | sort -u)
readme=$(sed -n '/^## Versions/,$s/^- \*\*\([0-9.]*\):\*\*.*/\1/p' README.md | head -1)
check "one version everywhere ($(echo $versions), README $readme)" '[[ $versions == "$readme" && -n $readme ]]'

shell=(setup.sh test/*.sh)
check 'shell syntax' '(for f in "${shell[@]}"; do bash -n "$f" || exit 1; done)'
if command -v shellcheck > /dev/null; then
    check 'shellcheck: setup.sh' 'shellcheck -S warning setup.sh'
    # the tests use their variables inside the strings check() evaluates, which shellcheck can't see
    check 'shellcheck: tests' 'shellcheck -S warning -e SC2034,SC1090 test/*.sh'
else
    echo "skip  shellcheck (not installed)"
fi

if command -v systemd-analyze > /dev/null; then
    # the units name /usr/local/sbin/site-lockdown; check them against this checkout's script
    t=$(mktemp -d)
    sed "s#/usr/local/sbin/site-lockdown#$PWD/site-lockdown.pl#" systemd/site-lockdown.service > "$t/site-lockdown.service"
    sed "s#/usr/local/sbin/site-lockdown#$PWD/site-lockdown.pl#" systemd/site-lockdown-check.service > "$t/site-lockdown-check.service"
    cp systemd/site-lockdown.timer "$t/"
    out=$(systemd-analyze verify "$t"/site-lockdown* 2>&1 | grep -F "$t/")
    rm -rf "$t"
    check 'systemd-analyze verify' '[[ -z $out ]] || { echo "$out"; false; }'
else
    echo "skip  systemd-analyze verify (not installed)"
fi

echo; ((fail)) && echo 'SOME CHECKS FAILED' || echo 'all lint checks passed'
exit $fail
