#!/bin/bash
# The README's Containers section, on a Docker host: copy php-site-watch into a running Ubuntu
# container, run --alert and --status there with docker exec as the host's cron would, and check
# a snapshot of the container in a read-only throwaway one. From the repository directory, on a
# machine with Docker (it creates and removes a container and an image named psw-test-*):
#   bash test/test-docker.sh                  (or: bash test/test-docker.sh ubuntu:20.04)
set -u
image=${1:-docker.io/library/ubuntu:22.04}
c=psw-test-$$
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
docker run -d --name "$c" "$image" sleep 900 > /dev/null || exit 9
trap 'docker rm -f "$c" > /dev/null; docker rmi "$c-snap" > /dev/null 2>&1' EXIT

docker cp php-site-watch.pl "$c:/usr/local/sbin/php-site-watch"
docker cp examples/genapp.conf "$c:/etc/php-site-watch.conf"
docker exec "$c" install -d -o www-data /var/www/html
docker exec -u www-data "$c" touch /var/www/html/shell.php

echo "######## docker exec, as the host's cron would run it"
alert1=$(docker exec "$c" /usr/local/sbin/php-site-watch --alert)
echo "$alert1"; echo
check 'first alert printed, with the new file' '[[ $alert1 == "[php-site-watch] ALERT "* ]] && grep -q "  /var/www/html/shell.php$" <<< "$alert1"'
alert2=$(docker exec "$c" /usr/local/sbin/php-site-watch --alert)
check 'second alert prints nothing, so cron mails nothing' '[[ -z $alert2 ]]'
status=$(docker exec "$c" /usr/local/sbin/php-site-watch --status --date yesterday)
check 'status printed, with health' 'grep -q "^\[php-site-watch\] " <<< "$status" && grep -q "^== Server health" <<< "$status"'
check 'status: no files mounted from the host as disks' 'grep -q "^disk use: " <<< "$status" && ! grep -q "/etc/hosts" <<< "$status"'
runlog=$(docker exec "$c" cat /var/log/php-site-watch.log)
check 'run log kept in the container' '(($(wc -l <<< "$runlog") == 3)) && grep -q "  alert   .*: 1 finding, 0 new; nothing new to send$" <<< "$runlog"'

echo; echo "######## a snapshot, checked in a read-only throwaway container"
docker commit "$c" "$c-snap" > /dev/null
snap=$(docker run --rm --read-only --network none \
           -v "$PWD/php-site-watch.pl:/usr/local/sbin/php-site-watch:ro" \
           -v "$PWD/examples/genapp.conf:/etc/php-site-watch.conf:ro" \
           --entrypoint /usr/local/sbin/php-site-watch "$c-snap" --user www-data --hours 2 2>&1); rc=$?
echo "$snap"; echo
check 'snapshot: finds the file, writes nothing' '((rc == 1)) && grep -q "  /var/www/html/shell.php$" <<< "$snap" && ! grep -qiE "read-only|cannot write" <<< "$snap"'

echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all Docker tests passed'
exit $fail
