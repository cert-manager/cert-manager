# Changelog

## 1.12.0 (2017-09-11)

### Changed

- #79: Include the error context in the error string (thanks @guywithnose)
- #80: Bump the Go versions for Travis CI testing (thanks @AlekSi)

## 1.11.1 (2017-04-28)

### Fixed

- #76: Fix submodule handling for Windows (thanks @m0j0hn)

## 1.11.0 (2017-03-23)

### Added

- #65: Exposed CmdFromDir function (thanks @erizocosmico)

### Changed

- #69: Updated testing for Go 1.8

### Fixed

- #64: Testing fatal error if bzr not installed (thanks @kevinburke)

## 1.10.2 (2017-01-24)

### Fixed

- #63: Remove extra quotes in submodule export (thanks @dt)

## 1.10.1 (2017-01-18)

### Fixed

- #62: Added windows testing via appveyor and fixed issues under windows.

## 1.10.0 (2017-01-09)

### Added

- #60: Handle Git submodules (thanks @sdboyer)
- #61: Add gometalinter to testing

## 1.9.0 (2016-11-18)

### Added

- #50: Auto-detect remotes with file:// prefix.
- #59: Testing against Go 1.7

### Changed

- Removed auto-detection for Google Code as the service is deprecated
- Added auto-detection of git.openstack.org

### Fixed

- #53: Git not fetching tags off branch

## 1.8.0 (2016-06-29)

### Added

- #43: Detect when tool (e.g., git, svn, etc) not installed
- #49: Detect access denied and not found situations

### Changed

- #48: Updated Go Report Gard url to new format
- Refactored SVN handling to detect when not in a top level directory
- Updating tagging to v[SemVer] structure for compatibility with other tools.

### Fixed

- #45: Fixed hg's update method so that it pulls from remote before updates

## 1.7.0 (2016-05-05)

- Adds a glide.yaml file with some limited information.
- Implements #37: Ability to export source as a directory.
- Implements #36: Get current version-ish with Current method. This returns
  a branch (if on tip) or equivalent tip, a tag if on a tag, or a revision if
  on an individual revision. Note, the tip of branch is VCS specific so usage
  may require detecting VCS type.

## 1.6.1 (2016-04-27)

- Fixed #30: tags from commit should not have ^{} appended (seen in git)
- Fixed #29: isDetachedHead fails with non-english locales (git)
- Fixed #33: Access denied and not found http errors causing xml parsing errors

## 1.6.0 (2016-04-18)

- Issue #26: Added Init method to initialize a repo at the local location
  (thanks tony).
- Issue #19: Added method to retrieve tags for a commit.
- Issue #24: Reworked errors returned from common methods. Now differing
  VCS implementations return the same errors. The original VCS specific error
  is available on the error. See the docs for more details.
- Issue #25: Export the function RunFromDir which runs VCS commands from the
  root of the local directory. This is useful for those that want to build and
  extend on top of the vcs package (thanks tony).
- Issue #22: Added Ping command to test if remote location is present and
  accessible.

## 1.5.1 (2016-03-23)

- Fixing bug parsing some Git commit dates.

## 1.5.0 (2016-03-22)

- Add Travis CI testing for Go 1.6.
- Issue #17: Add CommitInfo method allowing for a common way to get commit
  metadata from all VCS.
- Autodetect types that have git@ or hg@ users.
- Autodetect git+ssh, bzr+ssh, git, and svn+ssh scheme urls.
- On Bitbucket for ssh style URLs retrieve the type from the URL. This allows
  for private repo type detection.
- Issue #14: Autodetect ssh/scp style urls (thanks chonthu).

## 1.4.1 (2016-03-07)

- Fixes #16: some windows situations are unable to create parent directory.

## 1.4.0 (2016-02-15)

- Adding support for IBM JazzHub.

## 1.3.1 (2016-01-27)

- Issue #12: Failed to checkout Bzr repo when parent directory didn't
  exist (thanks cyrilleverrier).

## 1.3.0 (2015-11-09)

- Issue #9: Added Date method to get the date/time of latest commit (thanks kamilchm).

## 1.2.0 (2015-10-29)

- Adding IsDirty method to detect a checkout with uncommitted changes.

## 1.1.4 (2015-10-28)

- Fixed #8: Git IsReference not detecting branches that have not been checked
  out yet.

## 1.1.3 (2015-10-21)

- Fixing issue where there are multiple go-import statements for go redirects

## 1.1.2 (2015-10-20)

- Fixes #7: hg not checking out code when Get is called

## 1.1.1 (2015-10-20)

- Issue #6: Allow VCS commands to be run concurrently.

## 1.1.0 (2015-10-19)

- #5: Added output of failed command to returned errors.

## 1.0.0 (2015-10-06)

- Initial release.
