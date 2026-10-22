# php_site_watch

`php-site-watch` checks an Apache or nginx + PHP server for signs of exploitation or trouble. It
can mail an alert as soon as something new shows up, and a status report every morning that also
covers basic server health.

It was written after the PHP2Shell vulnerabilities
([CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)),
whose attacks leave crashed or out-of-memory PHP workers behind, but it is a useful daily check
for any PHP site.

It reports:

- PHP workers that crashed (`SIGSEGV`, `SIGBUS`, `SIGABRT`) or died while starting a request,
  from php-fpm logs and from Apache when it runs PHP itself (mod_php)
- PHP running out of memory or time, and php-fpm reaching its worker limit
- FastCGI failures between the web server and PHP, such as reset connections or unreadable
  headers (PHP's own notices and warnings, which Apache logs as `AH01071`, and the "Primary
  script unknown" noise from scanners are left out)
- for context: PHP fatal errors in your applications, grouped by message; 5xx responses; and
  the clients sending the most POST requests
- files the PHP account changed recently, such as a dropped web shell
- processes the PHP account is running other than web server and PHP workers
- network sockets of the PHP account other than web visitors and local connections, such as a
  listening backdoor or an outbound connection
- server health: uptime and load, whether the web server and php-fpm services are running,
  local disks over 90% full, the PHP version and, on RPM systems, whether its package includes
  the PHP2Shell fix, whether php-fpm is still running a binary an update replaced, and zombie
  processes of the PHP account

Processes in containers (Docker, Podman, Kubernetes, LXC) are left out: they can run under the
same user ID as the host's PHP but belong to their own setups. The health section notes how many
containers are running.

## Requirements

- Linux, run as root (to read the logs and see every process and socket)
- `perl` with no extra modules (tested with Perl 5.26 and 5.32), plus `ps`, `ss` and `find`.
  On RHEL, Rocky or Oracle Linux: `dnf install perl-interpreter procps-ng iproute findutils git`
- For mail: a local `sendmail`, such as postfix configured to send outgoing mail, and cron

Tested on Rocky Linux 8.10 and 9.8, including a live Apache 2.4.37 + php-fpm 7.4.33 setup
delivering through postfix. It reads php-fpm, PHP, Apache and nginx log formats, including
rotated `.gz` files. Debian and Ubuntu log locations are recognized but haven't been tested.

## Install, update, uninstall

```bash
git clone https://github.com/ehb54/php_site_watch
cd php_site_watch
sudo ./setup.sh install --cron --mailto you@example.org
```

This installs `/usr/local/sbin/php-site-watch` (use the full path with `sudo`: on RHEL and similar systems its safe PATH leaves out `/usr/local/sbin`), a fully commented `/etc/php-site-watch.conf` (only
if there isn't one yet), and `/etc/cron.d/php-site-watch` with two jobs that mail to the given
addresses (comma-separated; root if `--mailto` is left out):

- **alerts**, hourly at 5 past: findings from today and yesterday that haven't been reported
  before. Nothing is sent when there is nothing new. Each finding is mailed once; the list of
  what was sent is kept in `/var/lib/php-site-watch` for 14 days.
- **status**, daily at 07:00: the full report on the previous day plus server health. The
  subject says `OK`, the number of findings, or which health check needs attention, so a
  missing report also tells you something is wrong.

`--mailfrom ADDRESS` sets the sender, if your mail relay needs a particular one. Leave out
`--cron` to install the script only. To check that mail gets through:

```bash
sudo /usr/local/sbin/php-site-watch --status --mail-to you@example.org
```

Later:

```bash
sudo ./setup.sh update             # pull the latest version and reinstall; config and cron job are kept
sudo ./setup.sh uninstall          # remove the script and cron job; config and alert history are kept
sudo ./setup.sh uninstall --purge  # also remove /etc/php-site-watch.conf and the alert history
```

To change the schedule, edit `/etc/cron.d/php-site-watch`; running `setup.sh install --cron`
again rewrites it.

## Use

```bash
sudo /usr/local/sbin/php-site-watch                      # today, printed
sudo /usr/local/sbin/php-site-watch --date yesterday     # or YYYY-MM-DD, in the server's local time
sudo /usr/local/sbin/php-site-watch --quiet              # print only findings, nothing if all is clean
sudo /usr/local/sbin/php-site-watch --status --mail-to you@example.org   # mail the daily report now
```

Exit status: 0 nothing suspicious, 1 findings, 2 usage or setup error.

Options (all but `--quiet`, `--alert`, `--status` and `--version` can also be set in
`/etc/php-site-watch.conf`; see [php-site-watch.conf.example](php-site-watch.conf.example), and
[examples/us3lims.conf](examples/us3lims.conf) for an UltraScan LIMS server):

| Option | Meaning |
|---|---|
| `--date DAY` | day to check: `YYYY-MM-DD`, `today` or `yesterday` (default: today) |
| `--hours N` | how far back to look for changed files (default: 24) |
| `--user NAME` | account PHP runs as (default: detected from running workers) |
| `--fpm-logs PATH` | php-fpm log directory or file (repeatable) |
| `--web-logs PATH` | Apache or nginx log directory or file (repeatable) |
| `--scan DIR` | where to look for changed files (repeatable) |
| `--exclude REGEX` | changed files to ignore (repeatable) |
| `--allow-proc REGEX` | other expected processes of the PHP account (repeatable) |
| `--allow-peer REGEX` | expected connections to other machines, as host:port (repeatable) |
| `--config FILE` | config file (default: `/etc/php-site-watch.conf` if it exists) |
| `--quiet` | print only sections with findings |
| `--alert` | report only findings not reported before, from today and yesterday |
| `--status` | full report plus server health |
| `--mail-to ADDRESSES` | with `--alert` or `--status`, mail instead of printing (comma-separated) |
| `--mail-from ADDRESS` | sender address for mail |
| `--version` | print the version |

The PHP fatal error, 5xx, POST and health sections are for context and don't count as findings. The files,
processes, sockets and health sections show the current state, whatever `--date` is.

## Reading the results

- **Usually harmless:** an occasional out-of-memory or time-limit error from a known page, 5xx
  responses to scanners, and files your applications normally write. Add those to `exclude` once
  you know them, so they stop being reported.
- **Worth a closer look:** crashed workers, especially several within seconds; FastCGI errors
  next to POSTs from the same client; new `.php` files in web directories or anything in `/tmp`
  or `/dev/shm`; processes or listening sockets of the PHP account you don't recognize; and
  connections from it to unfamiliar addresses.
- **Health lines marked `!!`:** a web server or php-fpm service that is enabled but not running,
  a disk over 90% full, a PHP package without the PHP2Shell fix, or a php-fpm that needs a
  restart to pick up an update.

## Tests

`test/` holds sample logs with planted problems and three test scripts, which print `ok` or
`FAIL` per check. Run them in throwaway Rocky containers from the repository directory (each
works with `:8` and `:9`):

```bash
# sample logs, planted files, processes and sockets, and mail through a stand-in sendmail
# (SYS_PTRACE lets container root see socket owners, as real root can)
podman run --rm -q --cap-add SYS_PTRACE -v "$PWD/test:/t:ro,z" -v "$PWD:/s:ro,z" \
    quay.io/rockylinux/rockylinux:9 bash /t/test-run.sh
# real Apache + php-fpm 7.4 and postfix: crashed workers, out-of-memory, PHP2Shell fix check
podman run --rm -q -v "$PWD/test:/t:ro,z" -v "$PWD:/s:ro,z" \
    quay.io/rockylinux/rockylinux:8 bash /t/test-el8-live.sh
# setup.sh install, cron jobs and uninstall
podman run --rm -q -v "$PWD:/s:ro,z" quay.io/rockylinux/rockylinux:9 bash /s/test/test-setup.sh
```
