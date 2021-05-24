# libhoney Changelog

## 1.15.2 2021-01-22

NOTE: v1.15.1 may cause update warnings due to checksum error, please use v1.15.2 instead.

### Maintenance

- Add Github action to manage project labels (#110)
- Automate the creation of draft releases when project is tagged (#109)

## 1.15.1 2021-01-14

### Improvements

- Fix data race on dynFields length in Builder.Clone (#72)

### Maintenance

- Update dependencies
    - github.com/klauspost/compress from 1.11.2 to 1.11.4 (#105, #106)

## 1.15.0 2020-11-10

- Mask writekey when printing events (#103)

## 1.14.1 2020-9-24

- Add .editorconfig to help provide consistent IDE styling (#99)

## 1.14.0 2020-09-01

- Documentation - document potential failures if pendingWorkCapacity not specified
- Documentation - use Deprecated tags for deprecated fields
- Log when event batch is rejected with an invalid API key
- Dependency bump (compress)

## 1.13.0 2020-08-21

- This release includes a change by @apechimp that makes Flush thread-safe (#80)
- Update dependencies
- Have a more obvious default statsd prefix (libhoney)
