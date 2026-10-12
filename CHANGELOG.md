# Changelog

All notable changes to this project will be documented in this file, in reverse chronological order by release.

## [0.6.0](https://github.com/clerq-io/pybranca/compare/v0.5.1...v0.6.0) - 2026-10-12

### Changed
- Replace pybase62 with gmpy2 for base62 conversion. Encoding and decoding large tokens is no longer quadratic. The token format is unchanged.
- Decoding rejects non-canonical base62 tokens (whitespace, leading zero, sign).
- Require Python 3.9 or higher.

### Fixed
- Test vector 3 was shadowed by a duplicate test name and never ran.

## [0.5.0](https://github.com/tuupola/pybranca/compare/0.4.0...0.5.0) - 2021-08-17

### Changed
- Assume string keys are hex encoded ([#11](https://github.com/tuupola/pybranca/pull/11)).

### Added
- Test vectors from the spec ([#8](https://github.com/tuupola/pybranca/pull/8)).

## [0.4.0](https://github.com/tuupola/pybranca/compare/0.3.0...0.4.0) - 2020-11-04

### Fixed
- Timestamp is now checked as the last step ([#5](https://github.com/tuupola/pybranca/pull/5)).

## [0.3.0](https://github.com/tuupola/pybranca/compare/0.2.0...0.3.0) - 2019-02-03

### Added
- Helper to get the timestamp from the token ([#1](https://github.com/tuupola/pybranca/pull/1)).


## 0.2.0 - 2018-03-20

Initial realease.