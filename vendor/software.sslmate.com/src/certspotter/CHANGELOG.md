# Change Log

## v0.16.0 (2023-02-21)
- Write malformed certs and failed healthchecks to filesystem so scripts
  can access them.
- Automatically execute scripts under `$CERTSPOTTER_CONFIG_DIR/hooks.d`
  if it exists.
- Automatically email addresses listed in `$CERTSPOTTER_CONFIG_DIR/email_recipients`
  if it exists.

## v0.15.1 (2023-02-09)
- Fix some typos in help and error messages.
- Allow version to be set via linker flag, to facilitate distro package building.

## v0.15.0 (2023-02-08)
- **Significant behavior change**: certspotter is now intended to run as
  a daemon instead of a cron job.  Specifically, certspotter no longer
  terminates unless it receives SIGTERM or SIGINT or there is a serious error.
  You should remove certspotter from your crontab and arrange to run it as a
  daemon, passing either the `-email` option or `-script` option to configure
  how you want to be notified about certificates.

  Reason for this change: although using cron made sense in the early days of
  Certificate Transparency, certspotter now needs to run continuously to reliably
  keep up with the high growth rate of contemporary CT logs, and to gracefully
  handle the many transient errors that can arise when monitoring CT.
  See <https://github.com/SSLMate/certspotter/issues/63> for background.

- `-script` is now officially supported and can be used to execute
  a command when a certificate is discovered or there is an error.  For details,
  see the [certspotter-script(8) man page](man/certspotter-script.md).

  Note the following changes from the experimental, undocumented `-script`
  option found in previous versions:
  - The script is also executed when there is an error.  Consult the `$EVENT`
    variable to determine why the script was executed.
  - The `$DNS_NAMES` and `$IP_ADDRESSES` variables have been removed because
    the OS limits the size of environment variables and some certificates have
    too many identifiers.  To determine a certificate's identifiers, you can
    read the JSON file specified by the `$JSON_FILENAME` variable, as explained
    in the [certspotter-script(8) man page](man/certspotter-script.md).
  - The `$CERT_TYPE` variable has been removed because it is almost always
    a serious mistake (that can make you miss malicious certificates) to treat
    certificates and precertificates differently.  If you are currently
    using this variable to skip precertificates, stop doing that because
    precertificates imply the existence of a corresponding certificate that you
    **might not** be separately notified about.  For more details, see
    <https://github.com/SSLMate/certspotter/commit/cd2bb429fc2f4060a33ec8eb8b71a3eb12e9ba93>.
  - New variable `$WATCH_ITEM` contains the first watch list item which
    matched the certificate.

- New `-email` option can be used to send an email when a certificate is
  discovered or there is an error.  Your system must have a working `sendmail`
  command.

- (Behavior change) You must specify the `-stdout` option if you want discovered
  certificates to be written to stdout.  This only makes sense when running
  certspotter from the terminal; when running as a daemon you probably want to
  use `-email` or `-script` instead.

- Once a day, certspotter will send you a notification (per `-email` or
  `-script`) if any problems are preventing it from detecting all certificates.
  As in previous versions of certspotter, errors are written to stderr when they
  occur, but since most errors are transient, you can now ignore stderr and rely
  on the daily health check to notify you about any persistent problems that
  require your attention.

- certspotter now saves `.json` and `.txt` files alongside the `.pem` files
  containing parsed representations of the certificate.

- `.pem` files no longer have `.cert` or `.precert` in the filename.

- certspotter will save its state periodically, and before terminating due to
  SIGTERM or SIGINT, meaning it can resume monitoring without having to
  re-download entries it has already processed.

- The experimental "BygoneSSL" feature has been removed due to limited utility.

- The `-num_workers` option has been removed.

- The `-all_time` option has been removed. You can remove the certspotter state
  directory if you want to re-download all entries.

- The minimum supported Go version is now 1.19.

## v0.14.0 (2022-06-13)
- Switch to Go module versioning conventions.

## v0.13 (2022-06-13)
- Reduce minimum Go version to 1.17.
- Update install instructions.

## v0.12 (2022-06-07)
- Retry failed log requests.  This should make certspotter resilient
  to rate limiting by logs.
- Add `-version` flag.
- Eliminate unnecessary dependency. certspotter now depends only on
  golang.org/x packages.
- Switch to Go modules.

## v0.11 (2021-08-17)
- Add support for contacting logs via HTTP proxies;
  just set the appropriate environment variable as documented at
  <https://golang.org/pkg/net/http/#ProxyFromEnvironment>.
- Work around RFC 6962 ambiguity related to consistency proofs
  for empty trees.

## v0.10 (2020-04-29)
- Improve speed by processing logs in parallel
- Add `-start_at_end` option to begin monitoring new logs at the end,
  which significantly speeds up Cert Spotter, at the cost of missing
  certificates that were added to a log before Cert Spotter starts
  monitoring it
- (Behavior change) Scan logs in their entirety the first time Cert
  Spotter is run, unless `-start_at_end` specified (behavior change)
- The log list is now retrieved from certspotter.org at startup instead
  of being embedded in the source. This will allow Cert Spotter to react
  more quickly to the frequent changes in logs.
- (Behavior change) the `-logs` option now expects a JSON file in the v2
  log list format. See <https://www.certificate-transparency.org/known-logs>
  and <https://www.gstatic.com/ct/log_list/v2/log_list_schema.json>.
- `-logs` now accepts an HTTPS URL in addition to a file path.
- (Behavior change) the `-underwater` option has been removed. If you want
  its behavior, specify `https://loglist.certspotter.org/underwater.json` to
  the `-logs` option.

## v0.9 (2018-04-19)
- Add Cloudflare Nimbus logs
- Remove Google Argon 2017 log
- Remove WoSign and StartCom logs due to disqualification by Chromium
  and extended downtime

## v0.8 (2017-12-08)
- Add Symantec Sirius log
- Add DigiCert 2 log

## v0.7 (2017-11-13)
- Add Google Argon logs
- Fix bug that caused crash on 32 bit architectures

## v0.6 (2017-10-19)
- Add Comodo Mammoth and Comodo Sabre logs
- Minor bug fixes and improvements

## v0.5 (2017-05-18)
- Remove PuChuangSiDa 1 log due to excessive downtime and presumptive
  disqualification from Chrome
- Add Venafi Gen2 log
- Improve monitoring robustness under certain pathological behavior
  by logs
- Minor documentation improvements

## v0.4 (2017-04-03)
- Add PuChuangSiDa 1 log
- Remove Venafi log due to fork and disqualification from Chrome

## v0.3 (2017-02-20)
- Revise `-all_time` flag (behavior change):
  - If `-all_time` is specified, scan the entirety of all logs, even
    existing logs
  - When a new log is added, scan it in its entirety even if `-all_time`
    is not specified
- Add new logs:
  - Google Icarus
  - Google Skydiver
  - StartCom
  - WoSign
- Overhaul log processing and auditing logic:
  - STHs are never deleted unless they can be verified
  - Multiple unverified STHs can be queued per log, laying groundwork
    for STH pollination support
  - New state directory layout; current state directories will be
    migrated, but migration will be removed in a future version
  - Persist condensed Merkle Tree state between runs, instead of
    reconstructing it from consistency proof every time
- Use a lock file to prevent multiple instances of Cert Spotter from
  running concurrently (which could clobber the state directory).
- Minor bug fixes and improvements

## v0.2 (2016-08-25)
- Suppress duplicate identifiers in output.
- Fix "EOF" error when running under Go 1.7.
- Fix bug where hook script could fail silently.
- Fix compilation under Go 1.5.

## v0.1 (2016-07-27)
- Initial release.
