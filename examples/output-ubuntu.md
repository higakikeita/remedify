# Remediation plan: `testdata/fixtures/images/ubuntu-1804.tar.gz`

- **OS**: ubuntu 18.04
- **Package manager**: apt
- **Remediation steps**: 1 (covering 4 packages)
- **No fix available**: 1 packages

> ⚠️ **EOL**: Ubuntu 18.04 standard repositories no longer receive security updates. Fixes for many CVEs require Ubuntu Pro (ESM). Commands below may fail to find the fixed version without ESM enrollment.

## e2fsprogs (+3 related packages)  `MEDIUM`

- Packages: `e2fsprogs`, `libcom-err2`, `libext2fs2`, `libss2` (same source, one update)
- Installed: `1.44.1-1ubuntu1.1` -> Fix: `1.44.1-1ubuntu1.2`
- CVEs: CVE-2019-5094
- **Vendor backport (Ubuntu)**: the fixed version is a distro backport — it will not match the upstream version number. Scanners comparing against upstream may still flag it; trust the vendor advisory below.

```bash
apt-get install --only-upgrade e2fsprogs=1.44.1-1ubuntu1.2 libcom-err2=1.44.1-1ubuntu1.2 libext2fs2=1.44.1-1ubuntu1.2 libss2=1.44.1-1ubuntu1.2
```
- Advisories: [Ubuntu USN](https://ubuntu.com/security/notices/USN-4142-1) / [Debian DSA](https://www.debian.org/security/2019/dsa-4535) / [Red Hat CVE](https://access.redhat.com/security/cve/CVE-2019-5094)

## No fix available

These findings have no fixed version yet. Options: mitigate, accept the risk with justification, or track the vendor advisory.

- **bash** `LOW` (CVE-2019-18276) — No vendor fix released yet

