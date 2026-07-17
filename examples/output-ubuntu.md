# Remediation plan: `prod-web-host (Ubuntu 22.04)`

- **OS**: ubuntu 22.04
- **Package manager**: apt
- **Fixable packages**: 4

## libc6  `CRITICAL`

- Installed: `2.35-0ubuntu3.6` -> Fix: `2.35-0ubuntu3.8`
- CVEs: CVE-2024-33599
- **Vendor backport (Ubuntu)**: the fixed version is a distro backport — it will not match the upstream version number. Scanners comparing against upstream may still flag it; trust the vendor advisory below.

```bash
apt-get install --only-upgrade libc6=2.35-0ubuntu3.8
```
- ⚠️ libc update: reboot strongly recommended (all processes link against it).
- Advisories: [Ubuntu USN](https://ubuntu.com/security/notices/USN-6762-1) / [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-33599)

## libssl3  `HIGH`

- Installed: `3.0.2-0ubuntu1.15` -> Fix: `3.0.2-0ubuntu1.18`
- CVEs: CVE-2024-5535, CVE-2024-6119
- **Vendor backport (Ubuntu)**: the fixed version is a distro backport — it will not match the upstream version number. Scanners comparing against upstream may still flag it; trust the vendor advisory below.

```bash
apt-get install --only-upgrade libssl3=3.0.2-0ubuntu1.18
```
- ⚠️ Restart services that link against OpenSSL (nginx, sshd, etc.).
- Advisories: [Ubuntu USN](https://ubuntu.com/security/notices/USN-6986-1) / [Ubuntu USN](https://ubuntu.com/security/notices/USN-6903-1) / [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-6119)

## linux-image-generic  `HIGH`

- Installed: `5.15.0.105.102` -> Fix: `5.15.0.107.104`
- CVEs: CVE-2024-26923

```bash
apt-get install --only-upgrade linux-image-generic=5.15.0.107.104
```
- ⚠️ Kernel update: reboot required.
- Advisories: [Ubuntu USN](https://ubuntu.com/security/notices/USN-6767-1)

## curl  `MEDIUM`

- Installed: `7.81.0-1ubuntu1.15` -> Fix: `7.81.0-1ubuntu1.16`
- CVEs: CVE-2024-2398
- **Vendor backport (Ubuntu)**: the fixed version is a distro backport — it will not match the upstream version number. Scanners comparing against upstream may still flag it; trust the vendor advisory below.

```bash
apt-get install --only-upgrade curl=7.81.0-1ubuntu1.16
```
- Advisories: [Ubuntu USN](https://ubuntu.com/security/notices/USN-6718-1)

