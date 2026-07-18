#!/usr/bin/env python3
"""
remedify - Turn vulnerability scan results into concrete, OS-specific remediation commands.

"copa patches container images. remedify tells you how to patch everything else."

v0.2:
  * Consolidated remediation steps (source-package grouping)
  * "No fix available" section (uses Trivy's Status field)
  * EOL / ESM awareness
  * Input : Trivy JSON (`trivy image|fs|rootfs ... --format json`)
  * Output: Markdown report / shell script / JSON

Usage:
  python3 remedify.py scan.json                    # markdown report (default)
  python3 remedify.py scan.json --format shell     # executable remediation script
  python3 remedify.py scan.json --format json      # machine-readable
  python3 remedify.py scan.json --min-severity HIGH

Stdlib only. No dependencies.
"""

import argparse
import csv
import io
import json
import os
import re
import sys
from collections import defaultdict

__version__ = "0.12.0"

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# ---------------------------------------------------------------------------
# Distro handling
# ---------------------------------------------------------------------------

APT_FAMILIES = {"debian", "ubuntu"}
DNF_FAMILIES = {"redhat", "rhel", "centos", "rocky", "almalinux", "alma",
                "oracle", "fedora", "amazon"}
APK_FAMILIES = {"alpine", "wolfi", "chainguard"}
ZYPPER_FAMILIES = {"suse", "opensuse", "sles", "opensuse-leap", "opensuse-tumbleweed"}

# Vendor backport markers embedded in package versions
BACKPORT_PATTERNS = [
    (re.compile(r"ubuntu", re.I), "Ubuntu"),
    (re.compile(r"\+esm", re.I), "Ubuntu ESM"),
    (re.compile(r"\+deb\d+|~deb\d+", re.I), "Debian"),
    (re.compile(r"\.el\d+", re.I), "RHEL"),
    (re.compile(r"\.amzn\d+", re.I), "Amazon Linux"),
]

# Advisory URL patterns worth surfacing (vendor sources first)
ADVISORY_PATTERNS = [
    ("Ubuntu USN", re.compile(r"ubuntu\.com/security/notices|ubuntu\.com/usn")),
    ("Debian DSA", re.compile(r"security-tracker\.debian\.org|debian\.org/security")),
    ("RHEL Errata", re.compile(r"access\.redhat\.com/errata")),
    ("Red Hat CVE", re.compile(r"access\.redhat\.com/security/cve")),
    ("Amazon ALAS", re.compile(r"alas\.aws\.amazon\.com")),
    ("SUSE", re.compile(r"suse\.com/security")),
    ("Alpine", re.compile(r"security\.alpinelinux\.org")),
    ("NVD", re.compile(r"nvd\.nist\.gov")),
]

# Packages whose update implies reboot / service restarts
REBOOT_PACKAGES = re.compile(r"^(linux-image|linux-headers|linux-generic|linux|kernel)(-|$)")
LIBC_PACKAGES = {"libc6", "glibc", "libc-bin", "musl"}
RESTART_HINT_PACKAGES = {
    "openssl": "Restart services that link against OpenSSL (nginx, sshd, etc.).",
    "libssl3": "Restart services that link against OpenSSL (nginx, sshd, etc.).",
    "libssl1.1": "Restart services that link against OpenSSL (nginx, sshd, etc.).",
    "systemd": "Run `systemctl daemon-reexec` or reboot.",
    "dbus": "A reboot is recommended after updating dbus.",
}

# End-of-life distro versions (standard repos no longer receive security fixes).
# Deliberately conservative; roadmap: pull from endoflife.date API.
EOL_VERSIONS = {
    "ubuntu": {
        "versions": {"14.04", "16.04", "18.04", "20.04"},
        "note": ("Ubuntu {v} standard repositories no longer receive security "
                 "updates. Fixes for many CVEs require Ubuntu Pro (ESM). "
                 "Commands below may fail to find the fixed version without "
                 "ESM enrollment."),
    },
    "debian": {
        "versions": {"8", "9", "10"},
        "note": ("Debian {v} is end-of-life. Security fixes may only exist in "
                 "Debian LTS/ELTS. Consider upgrading the base OS."),
    },
    "centos": {
        "versions": {"6", "7", "8"},
        "note": ("CentOS {v} is end-of-life. No further security updates are "
                 "published. Migrate to a supported distribution "
                 "(Rocky/Alma/RHEL/CentOS Stream)."),
    },
    "amazon": {
        "versions": {"1", "2", "2018.03"},
        "note": ("Amazon Linux {v} is end-of-life (AL2 since 2026-06-30). "
                 "Migrate to AL2023."),
    },
}

# Language-package ecosystems: Trivy Result.Type / Sysdig package type -> ecosystem
LANG_ECOSYSTEMS = {
    # Trivy types
    "jar": "java", "pom": "java", "gradle-lockfile": "java", "sbt-lockfile": "java",
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm",
    "pip": "python", "poetry": "python", "pipenv": "python", "python-pkg": "python",
    "gomod": "go", "gobinary": "go",
    "gemspec": "ruby", "bundler": "ruby",
    "composer": "php",
    "cargo": "rust",
    "nuget": "dotnet", "dotnet-core": "dotnet",
    # Sysdig package types
    "java": "java", "javascript": "npm", "python": "python", "golang": "go",
    "ruby": "ruby", "php": "php", "rust": "rust", "c#": "dotnet",
}


def app_fix_action(ecosystem: str, package: str, version: str):
    """Human-actionable fix for an application dependency. Always implies rebuild."""
    if ecosystem == "java":
        return (f"Update `{package}` to `{version}` in pom.xml / build.gradle "
                f"(check the dependency tree: it may be transitive — pin via "
                f"dependencyManagement / constraints).")
    if ecosystem == "npm":
        return f"`npm install {package}@{version}` (update package.json / lockfile)."
    if ecosystem == "python":
        return f"`pip install --upgrade {package}=={version}` and update requirements.txt / lockfile."
    if ecosystem == "go":
        return f"`go get {package}@v{version.lstrip('v')} && go mod tidy`."
    if ecosystem == "ruby":
        return f"Update `{package}` to `{version}` in Gemfile, then `bundle update {package}`."
    if ecosystem == "php":
        return f"`composer require {package}:{version}`."
    if ecosystem == "rust":
        return f"Update `{package}` to `{version}` in Cargo.toml, then `cargo update -p {package}`."
    if ecosystem == "dotnet":
        return f"`dotnet add package {package} --version {version}`."
    return f"Update `{package}` to `{version}` in your dependency manifest."


# Third-party / vendor image detection: you don't build these, so the
# highest-leverage fix is upgrading to the newest vendor tag, not patching
# in place. Patterns are heuristics — extend as needed.
THIRD_PARTY_REGISTRY_PATTERNS = [
    (re.compile(r"^registry\.k8s\.io/"), "Kubernetes"),
    (re.compile(r"^k8s\.gcr\.io/"), "Kubernetes"),
    (re.compile(r"gke-release/"), "Google GKE"),
    (re.compile(r"^gcr\.io/(google-containers|distroless|gke-release)"), "Google"),
    (re.compile(r"^mcr\.microsoft\.com/"), "Microsoft"),
    (re.compile(r"^public\.ecr\.aws/"), "AWS"),
    (re.compile(r"amazonaws\.com/"), "AWS"),
    (re.compile(r"^registry\.(access\.)?redhat\.(com|io)/"), "Red Hat"),
    (re.compile(r"^nvcr\.io/"), "NVIDIA"),
    (re.compile(r"^quay\.io/"), "the vendor"),
    (re.compile(r"^(docker\.io/)?(library/)?(bitnami|grafana|prom|curlimages|"
                r"weaveworksdemos|istio|envoyproxy|fluent|calico)/"), "the vendor"),
]
# Bare official Docker Hub images ("debian:12", "redis:7.0.4", ...)
DOCKER_OFFICIAL_IMAGES = {
    "debian", "ubuntu", "alpine", "centos", "fedora", "rockylinux", "almalinux",
    "amazonlinux", "busybox", "redis", "nginx", "tomcat", "postgres", "mysql",
    "mariadb", "node", "python", "golang", "php", "ruby", "openjdk", "httpd",
    "traefik", "memcached", "mongo", "rabbitmq", "haproxy", "registry", "caddy",
}


def looks_like_image(target: str):
    """Heuristic: does the scan target look like a container image reference
    (registry/repo:tag or @sha256:) rather than a host?"""
    t = _s(target).strip()
    if not t or " " in t:  # "prod-web-host (Ubuntu 22.04)" has a space
        return False
    if "@sha256:" in t or "/" in t:
        return True
    # bare "name:tag" with a plausible tag
    if ":" in t:
        _, _, tag = t.partition(":")
        return bool(tag) and "/" not in tag
    return False


def detect_third_party(target: str):
    """Return a vendor label if the image looks vendor-built, else None."""
    t = _s(target).strip()
    if not t:
        return None
    for pattern, vendor in THIRD_PARTY_REGISTRY_PATTERNS:
        if pattern.search(t):
            return vendor
    # bare official image: no registry, no namespace ("redis:7.0.4")
    name = t.split("@")[0].split(":")[0]
    if "/" not in name and name.lower() in DOCKER_OFFICIAL_IMAGES:
        return "Docker Official Images"
    if name.startswith("docker.io/library/") and \
            name.split("/")[-1] in DOCKER_OFFICIAL_IMAGES:
        return "Docker Official Images"
    return None


# Trivy Status values that mean "no command to give you"
UNFIXED_STATUS_LABELS = {
    "affected": "No vendor fix released yet",
    "fix_deferred": "Fix deferred by vendor",
    "will_not_fix": "Vendor will not fix — assess exposure and mitigate",
    "end_of_life": "Distro version is EOL — no fix will be published",
    "": "No fixed version reported",
}



def _d(x):
    """Coerce to dict."""
    return x if isinstance(x, dict) else {}


def _l(x):
    """Coerce to list."""
    return x if isinstance(x, list) else []


def _s(x):
    """Coerce to string ('' for None/invalid)."""
    if isinstance(x, str):
        return x
    if x is None or isinstance(x, (dict, list)):
        return ""
    return str(x)


# ---------------------------------------------------------------------------
# Input safety (trust boundary)
# ---------------------------------------------------------------------------
# Package names and versions come from scan results, which are derived from a
# scanned image's package DB — a field a malicious base-image author controls.
# remedify emits shell commands from these values, so an unvalidated name like
# "libfoo$(cmd)" would become command injection when the script is run as root.
# We whitelist against distro naming rules and REJECT anything that doesn't
# match, rather than trying to quote-escape hostile input. Rejected findings
# are surfaced separately (never silently dropped).

# OS package identifiers: superset of dpkg/rpm/apk naming rules. Names start
# with alnum; names/versions allow only [A-Za-z0-9 . + - _ : ~]. No shell
# metacharacters ($ ` ; | & < > ( ) space newline quotes …) can pass.
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")
_PKG_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~:_-]*$")
# App/lang ecosystems (Go module paths, npm scopes, Maven coords) legitimately
# use "/", "@", "()" — but these never reach a shell (rendered as text/fix
# instructions, or passed to Ansible's argument list), so we validate only that
# they contain no characters that could break our own output framing.
_APP_NAME_RE = re.compile(r"^[^\x00-\x1f`$;&|<>\\\n\r]+$")


def is_safe_os_package(name, version):
    return bool(_PKG_NAME_RE.match(_s(name))) and \
        bool(_PKG_VERSION_RE.match(_s(version)))


# Opaque identifiers from API responses (scan result IDs) go into URL paths.
# A server-controlled "../" or absolute-URL-like value must not redirect our
# request. Whitelist, don't trust the server.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def is_safe_identifier(value):
    return bool(_IDENTIFIER_RE.match(_s(value)))


def detect_pkg_manager(family: str, os_name: str):
    f = (family or "").lower()
    if f in APT_FAMILIES:
        return "apt"
    if f in DNF_FAMILIES:
        if f == "amazon" and str(os_name).strip().startswith("2"):
            return "yum"
        return "dnf"
    if f in APK_FAMILIES:
        return "apk"
    if f in ZYPPER_FAMILIES:
        return "zypper"
    return None


def fix_command(pkg_manager: str, packages, version: str, assume_yes: bool = False):
    """Consolidated command for one or more packages sharing a fixed version.

    All package managers pin the target version (deterministic execution,
    not just deterministic text). assume_yes is for scripts (shell/CI);
    interactive report forms stay confirmable."""
    if isinstance(packages, str):
        packages = [packages]
    y = "-y " if assume_yes else ""
    if pkg_manager == "apt":
        specs = " ".join(f"{p}={version}" for p in packages)
        return f"apt-get install {y}--only-upgrade {specs}"
    if pkg_manager in ("dnf", "yum"):
        specs = " ".join(f"{p}-{version}" for p in packages)
        return f"{pkg_manager} update {y}{specs}".replace("  ", " ")
    if pkg_manager == "apk":
        specs = " ".join(f"{p}={version}" for p in packages)
        return f"apk add {specs}"
    if pkg_manager == "zypper":
        ni = "--non-interactive " if assume_yes else ""
        specs = " ".join(f"{p}={version}" for p in packages)
        return f"zypper {ni}install {specs}"
    return None


def preamble(pkg_manager: str):
    return {
        "apt": "apt-get update",
        "dnf": "dnf makecache",
        "yum": "yum makecache",
        "apk": "apk update",
        "zypper": "zypper refresh",
    }.get(pkg_manager)


def detect_backport(version: str):
    for pattern, vendor in BACKPORT_PATTERNS:
        if pattern.search(version or ""):
            return vendor
    return None


# EOL detection reads a vendored endoflife.date snapshot (eol_data.json,
# shipped next to this file). This stays OFFLINE and zero-dependency — the
# crown jewel "scp one file to an air-gapped host" is preserved — while the
# data is kept fresh by a weekly CI job that regenerates the snapshot via PR
# (scripts/update_eol.py). The hardcoded EOL_VERSIONS above is the ultimate
# fallback if the snapshot is missing. --check-eol adds a live network lookup.

ENDOFLIFE_PRODUCTS = {
    "ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine",
    "centos": "centos", "redhat": "rhel", "rhel": "rhel",
    "amazon": "amazon-linux", "rocky": "rocky-linux", "almalinux": "almalinux",
    "fedora": "fedora", "opensuse": "opensuse", "suse": "sles",
}

_VENDORED_EOL = None


def _vendored_eol_products():
    global _VENDORED_EOL
    if _VENDORED_EOL is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "eol_data.json")
        try:
            with open(path, encoding="utf-8") as f:
                _VENDORED_EOL = _d(json.load(f).get("products"))
        except (OSError, ValueError):
            _VENDORED_EOL = {}
    return _VENDORED_EOL


def _eol_note_from_cycles(family, os_name, cycles, today):
    """Pure matcher. Returns (matched, note): matched=False → caller should fall
    back; matched=True, note=None → supported (trust this over any fallback)."""
    import datetime
    version = _s(os_name).strip().split()[0] if _s(os_name).strip() else ""
    if not version:
        return (False, None)
    for cycle in cycles or []:
        if not isinstance(cycle, dict):
            continue
        cyc = _s(cycle.get("cycle"))
        if not cyc:
            continue
        if version == cyc or version.startswith(cyc + ".") or \
                cyc == version.split(".")[0]:
            eol = cycle.get("eol")
            past = False
            if eol is True:
                past = True
            elif isinstance(eol, str):
                try:
                    past = datetime.date.fromisoformat(eol) <= today
                except ValueError:
                    past = False
            if past:
                when = eol if isinstance(eol, str) else "already"
                return (True, f"{family} {os_name} is end-of-life "
                        f"({when}). Standard repositories no longer receive "
                        f"security updates — plan an OS upgrade.")
            return (True, None)  # explicitly supported
    return (False, None)


def _detect_eol_static(family: str, os_name: str):
    entry = EOL_VERSIONS.get((family or "").lower())
    if entry and str(os_name).strip() in entry["versions"]:
        return entry["note"].format(v=os_name)
    return None


def detect_eol(family: str, os_name: str, today=None):
    """Offline EOL check: vendored endoflife.date snapshot first, hardcoded
    table as fallback. No network."""
    import datetime
    today = today or datetime.date.today()
    product = ENDOFLIFE_PRODUCTS.get(_s(family).lower())
    if product:
        cycles = _vendored_eol_products().get(product)
        matched, note = _eol_note_from_cycles(family, os_name, cycles, today)
        if matched:
            return note
    return _detect_eol_static(family, os_name)


def _http_get_json(url, timeout=10):
    """Small GET helper; factored out so tests can monkeypatch it."""
    import urllib.request
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _eol_cache_path(product):
    import tempfile
    d = os.path.join(os.environ.get("REMEDIFY_CACHE_DIR",
                                    os.path.join(tempfile.gettempdir(), "remedify-cache")))
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        return None
    return os.path.join(d, f"eol-{product}.json")


def _load_eol_cycles(product, ttl_hours=24):
    """Return endoflife.date cycles for a product, cached to disk with a TTL.
    Returns [] on any error."""
    import time
    path = _eol_cache_path(product)
    if path and os.path.exists(path):
        try:
            if time.time() - os.path.getmtime(path) < ttl_hours * 3600:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
        except (OSError, ValueError):
            pass
    try:
        data = _http_get_json(f"https://endoflife.date/api/{product}.json")
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    if path:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except OSError:
            pass
    return data


def detect_eol_live(family, os_name, today=None):
    """--check-eol path: query endoflife.date over the network (cached ~24h),
    else fall back to the offline detect_eol (vendored snapshot + static
    table). Never raises."""
    import datetime
    today = today or datetime.date.today()
    product = ENDOFLIFE_PRODUCTS.get(_s(family).lower())
    if product:
        matched, note = _eol_note_from_cycles(
            family, os_name, _load_eol_cycles(product), today)
        if matched:
            return note
    return detect_eol(family, os_name, today)


def classify_references(refs):
    """Return list of (label, url), vendor advisories first, deduped, max 3.

    Near-duplicate advisories from the same family (USN-4142-1 / USN-4142-2)
    are collapsed to the first seen.
    """
    scored = []
    for url in refs or []:
        for i, (label, pattern) in enumerate(ADVISORY_PATTERNS):
            if pattern.search(url):
                scored.append((i, label, url))
                break
    scored.sort(key=lambda t: t[0])
    seen_urls, seen_families, out = set(), set(), []
    for _, label, url in scored:
        if url in seen_urls:
            continue
        family = re.sub(r"-\d+/?$", "", url.rstrip("/"))
        if family in seen_families:
            continue
        seen_urls.add(url)
        seen_families.add(family)
        out.append((label, url))
        if len(out) >= 3:
            break
    return out


def post_update_hints(package: str):
    hints = []
    if REBOOT_PACKAGES.match(package):
        hints.append("Kernel update: reboot required.")
    if package in LIBC_PACKAGES:
        hints.append("libc update: reboot strongly recommended (all processes link against it).")
    if package in RESTART_HINT_PACKAGES:
        hints.append(RESTART_HINT_PACKAGES[package])
    return hints


# ---------------------------------------------------------------------------
# Version comparison (loose; PoC-grade)
# ---------------------------------------------------------------------------

_EPOCH_RE = re.compile(r"^(\d+):(.*)$")


def _split_epoch(v: str):
    """'1:2.3.4' -> (1, '2.3.4'); no epoch -> (0, v). dpkg compares epoch first."""
    m = _EPOCH_RE.match(_s(v))
    if m:
        return int(m.group(1)), m.group(2)
    return 0, _s(v)


def _dpkg_order(c: str):
    """dpkg character order: '~' before everything (even end-of-string),
    then letters, then non-letters by codepoint."""
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str):
    """Faithful port of dpkg's verrevcmp(): alternate comparing non-digit
    runs (via _dpkg_order) and digit runs (numerically)."""
    ia = ib = 0
    la, lb = len(a), len(b)
    while ia < la or ib < lb:
        while ((ia < la and not a[ia].isdigit()) or
               (ib < lb and not b[ib].isdigit())):
            ca = _dpkg_order(a[ia]) if ia < la and not a[ia].isdigit() else 0
            cb = _dpkg_order(b[ib]) if ib < lb and not b[ib].isdigit() else 0
            if ca != cb:
                return -1 if ca < cb else 1
            ia += 1
            ib += 1
        na = 0
        while ia < la and a[ia].isdigit():
            na = na * 10 + int(a[ia])
            ia += 1
        nb = 0
        while ib < lb and b[ib].isdigit():
            nb = nb * 10 + int(b[ib])
            ib += 1
        if na != nb:
            return -1 if na < nb else 1
    return 0


def _split_revision(v: str):
    """dpkg splits upstream/revision at the LAST '-'; missing revision = '0'."""
    if "-" in v:
        upstream, _, revision = v.rpartition("-")
        return upstream, revision
    return v, "0"


def compare_versions(a: str, b: str):
    """-1 / 0 / 1 with dpkg semantics: epoch, then upstream (verrevcmp),
    then Debian revision (verrevcmp). Tilde sorts before release; digit
    runs compare numerically."""
    ea, ra = _split_epoch(a)
    eb, rb = _split_epoch(b)
    if ea != eb:
        return -1 if ea < eb else 1
    ua, va = _split_revision(ra)
    ub, vb = _split_revision(rb)
    c = _verrevcmp(ua, ub)
    if c != 0:
        return c
    return _verrevcmp(va, vb)


def highest_version(versions):
    import functools
    return max(versions, key=functools.cmp_to_key(compare_versions))


# ---------------------------------------------------------------------------
# Trivy parser
# ---------------------------------------------------------------------------

def parse_trivy(data: dict):
    meta = _d(data.get("Metadata"))
    os_info = _d(meta.get("OS"))
    family = _s(os_info.get("Family"))
    os_name = _s(os_info.get("Name"))
    target = _s(data.get("ArtifactName")) or "unknown"

    parsed = _empty_parsed(target, family, os_name)

    for result in _l(data.get("Results")):
        if not isinstance(result, dict):
            continue
        klass = result.get("Class")
        is_os = klass in (None, "os-pkgs")
        ecosystem = LANG_ECOSYSTEMS.get(_s(result.get("Type")).lower())
        if not is_os and (klass != "lang-pkgs" or not ecosystem):
            continue
        for v in _l(result.get("Vulnerabilities")):
            if not isinstance(v, dict):
                continue
            refs = [r for r in _l(v.get("References")) if isinstance(r, str)]
            if _s(v.get("PrimaryURL")):
                refs = [_s(v.get("PrimaryURL"))] + refs
            _add_finding(
                parsed,
                pkg=_s(v.get("PkgName")),
                installed=_s(v.get("InstalledVersion")) or None,
                fixed=_s(v.get("FixedVersion")).strip(),
                severity=(_s(v.get("Severity")) or "UNKNOWN").upper(),
                vuln_id=_s(v.get("VulnerabilityID")),
                status=_s(v.get("Status")).lower(),
                title=_s(v.get("Title")),
                references=refs,
                ecosystem=None if is_os else ecosystem,
                location=_s(result.get("Target")) if not is_os else None,
            )
    return parsed


def _empty_parsed(target="unknown", family="", os_name=""):
    return {
        "target": target, "family": family, "os_name": os_name,
        "findings": defaultdict(lambda: {
            "vulns": [], "fixed_versions": set(), "installed": None,
            "max_severity": "UNKNOWN", "references": [],
            "in_use": False, "exploitable": False, "kev": False,
        }),
        "unfixed": defaultdict(lambda: {
            "vulns": [], "installed": None, "max_severity": "UNKNOWN",
            "ecosystem": None,
            "in_use": False, "exploitable": False, "kev": False,
        }),
        "app": defaultdict(lambda: {
            "vulns": [], "fixed_versions": set(), "installed": None,
            "max_severity": "UNKNOWN", "locations": set(),
            "in_use": False, "exploitable": False, "kev": False,
        }),
        "rejected": [],
    }


def _add_finding(parsed, pkg, installed, fixed, severity, vuln_id,
                 status="", title="", references=None, ecosystem=None,
                 location=None, in_use=False, exploitable=False, kev=False):
    """Route one vulnerability record into findings / app / unfixed."""
    if not pkg:
        return
    sev = severity if severity in SEVERITY_ORDER else \
        {"NEGLIGIBLE": "LOW"}.get(severity, "UNKNOWN")
    vuln = {"id": vuln_id, "severity": sev, "title": title, "status": status}

    def _merge_flags(bucket):
        bucket["in_use"] = bucket["in_use"] or in_use
        bucket["exploitable"] = bucket["exploitable"] or exploitable
        bucket["kev"] = bucket["kev"] or kev

    if not fixed or fixed.lower() in ("none", "n/a", "-"):
        u = parsed["unfixed"][pkg]
        u["installed"] = installed or u["installed"]
        _merge_flags(u)
        u["ecosystem"] = ecosystem
        u["vulns"].append(vuln)
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(u["max_severity"], 0):
            u["max_severity"] = sev
        return

    if ecosystem:
        # lang-pkg names/versions never reach a shell, but must not break our
        # own output framing (Ansible YAML, markdown).
        if not _APP_NAME_RE.match(pkg) or "\n" in _s(fixed) or "\r" in _s(fixed):
            parsed["rejected"].append({"package": pkg, "reason": "unsafe characters"})
            return
        a = parsed["app"][(ecosystem, pkg)]
        a["installed"] = installed or a["installed"]
        _merge_flags(a)
        if location:
            a["locations"].add(location)
        for candidate in re.split(r"[,\s]+", fixed):
            if candidate:
                a["fixed_versions"].add(candidate)
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(a["max_severity"], 0):
            a["max_severity"] = sev
        a["vulns"].append(vuln)
        return

    # OS package -> emitted into shell commands. Whitelist name AND every
    # candidate fixed version; reject (don't escape) anything hostile.
    safe_versions = [c for c in re.split(r"[,\s]+", fixed) if c]
    if not _PKG_NAME_RE.match(pkg) or \
            not all(_PKG_VERSION_RE.match(c) for c in safe_versions):
        parsed["rejected"].append({
            "package": pkg, "cves": [vuln_id] if vuln_id else [],
            "reason": "package name or version failed distro naming validation "
                      "(possible malicious scan input) — not turned into a command"})
        return

    f = parsed["findings"][pkg]
    f["installed"] = installed or f["installed"]
    _merge_flags(f)
    for candidate in re.split(r"[,\s]+", fixed):
        if candidate:
            f["fixed_versions"].add(candidate)
    if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(f["max_severity"], 0):
        f["max_severity"] = sev
    f["vulns"].append(vuln)
    f["references"].extend(references or [])


# ---------------------------------------------------------------------------
# Sysdig CSV parser (vulnerability report exports)
# ---------------------------------------------------------------------------
# Column names vary across Sysdig report templates and versions, so we match
# headers against aliases, case-insensitively. To adapt to a new export
# variant, extend these alias lists — nothing else should need to change.

SYSDIG_COLUMN_ALIASES = {
    "vuln_id": ["vulnerability id", "cve id", "vuln id", "cve", "vulnerability"],
    "severity": ["severity", "vulnerability severity"],
    "package": ["package name", "package", "package path", "resource name"],
    "installed": ["package version", "installed version", "version",
                  "current version"],
    "fixed": ["fix version", "fixed in", "fixed version", "fix",
              "solved in version"],
    "pkg_type": ["package type", "type"],
    "os": ["image os", "os", "operating system", "os name", "distro"],
    "target": ["image", "image name", "hostname", "host", "asset",
               "workload", "image tag"],
}

# Only OS packages get commands; language packages are on the roadmap
SYSDIG_OS_PKG_TYPES = {"os", "deb", "rpm", "apk", "dpkg", ""}


def _sysdig_header_map(fieldnames):
    mapping = {}
    lowered = {(f or "").lstrip("﻿").strip().lower(): f
               for f in fieldnames or []}
    for key, aliases in SYSDIG_COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in lowered:
                mapping[key] = lowered[alias]
                break
    return mapping


def parse_os_string(os_string: str):
    """'Ubuntu 22.04' / 'ubuntu:22.04' / 'rhel 9.3' -> (family, name)."""
    s = _s(os_string).strip().replace(":", " ")
    if not s:
        return "", ""
    parts = s.split()
    family = parts[0].lower()
    if family in ("red", "redhat") and len(parts) > 1 and parts[1].lower() == "hat":
        family, parts = "redhat", [p for p in parts if p.lower() != "hat"]
    name = " ".join(parts[1:])
    # normalize common vendor spellings
    family = {"rhel": "redhat", "amazonlinux": "amazon", "amzn": "amazon"}.get(family, family)
    return family, name


def parse_sysdig_csv(text: str, os_override: str = None):
    try:  # tolerate semicolon/tab-delimited exports (Excel locale variants)
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    cols = _sysdig_header_map(reader.fieldnames)
    required = {"vuln_id", "package", "fixed"}
    missing = required - set(cols)
    if missing:
        expected = {k: SYSDIG_COLUMN_ALIASES[k] for k in sorted(missing)}
        sys.exit("error: could not find required column(s) in Sysdig CSV: "
                 f"{sorted(missing)}. Accepted header names: {expected}. "
                 "If your export uses different headers, please open an issue "
                 "with the header row.")

    parsed = _empty_parsed("sysdig-report")
    os_string = ""
    for row in reader:
        def col(key, default=""):
            return (row.get(cols[key], default) or default).strip() if key in cols else default

        pkg = col("package")
        if not pkg:
            continue
        if col("target"):
            parsed["target"] = col("target")
        if col("os"):
            os_string = col("os")

        pkg_type = col("pkg_type").lower()
        ecosystem = None
        if pkg_type not in SYSDIG_OS_PKG_TYPES:
            ecosystem = LANG_ECOSYSTEMS.get(pkg_type)
            if not ecosystem:
                continue  # unknown package type
        _add_finding(parsed, pkg=pkg, installed=col("installed"),
                     fixed=col("fixed"), severity=(col("severity") or "UNKNOWN").upper(),
                     vuln_id=col("vuln_id"), ecosystem=ecosystem)

    parsed["family"], parsed["os_name"] = parse_os_string(os_override or os_string)
    return parsed


# ---------------------------------------------------------------------------
# Grype JSON parser (`grype <target> -o json`)
# ---------------------------------------------------------------------------

GRYPE_OS_TYPES = {"deb", "rpm", "apk"}
GRYPE_LANG_TYPES = {
    "npm": "npm", "python": "python", "java-archive": "java",
    "go-module": "go", "gem": "ruby", "rust-crate": "rust",
    "dotnet": "dotnet", "php-composer": "php",
}


def parse_grype(data: dict):
    distro = _d(data.get("distro"))
    family = _s(distro.get("name")).lower()
    os_name = _s(distro.get("version"))
    source = _d(data.get("source"))
    target = _s(_d(source.get("target")).get("userInput")) or \
        _s(source.get("target")) or "grype-scan"

    parsed = _empty_parsed(target, family, os_name)
    for m in _l(data.get("matches")):
        if not isinstance(m, dict):
            continue
        v = _d(m.get("vulnerability"))
        a = _d(m.get("artifact"))
        a_type = _s(a.get("type")).lower()
        ecosystem = None
        if a_type not in GRYPE_OS_TYPES:
            ecosystem = GRYPE_LANG_TYPES.get(a_type)
            if not ecosystem:
                continue
        fix = _d(v.get("fix"))
        fixed = ""
        if _s(fix.get("state")) == "fixed":
            versions = [x for x in _l(fix.get("versions")) if isinstance(x, str) and x]
            fixed = versions[0] if len(versions) == 1 else \
                (highest_version(versions) if versions else "")
        locations = [_s(_d(loc).get("path")) for loc in _l(a.get("locations"))]
        location = next((p for p in locations if p), None)
        _add_finding(
            parsed,
            pkg=_s(a.get("name")),
            installed=_s(a.get("version")) or None,
            fixed=fixed,
            severity=(_s(v.get("severity")) or "UNKNOWN").upper(),
            vuln_id=_s(v.get("id")),
            status="" if fixed else _s(fix.get("state")).replace("-", "_"),
            references=[u for u in _l(v.get("urls")) if isinstance(u, str)],
            ecosystem=ecosystem,
            location=location if ecosystem else None,
        )
    return parsed


# ---------------------------------------------------------------------------
# OSV-Scanner parser (`osv-scanner --format json`)
# ---------------------------------------------------------------------------
# Shape: {"results": [{"source": {...}, "packages": [
#   {"package": {"name","version","ecosystem"},
#    "vulnerabilities": [{"id", "affected":[{"ranges":[{"events":[{"fixed":..}]}]}],
#                         "database_specific": {"severity": "HIGH"}, ...}]}]}]}
# OSV ecosystems: "Debian:12", "Ubuntu:22.04", "Alpine:v3.19" (OS) and
# "npm", "PyPI", "Go", "Maven", "RubyGems", "crates.io", "Packagist", "NuGet".

OSV_OS_ECOSYSTEMS = {"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine",
                     "red hat": "redhat", "rocky linux": "rocky",
                     "almalinux": "almalinux", "suse": "suse", "opensuse": "opensuse"}
OSV_LANG_ECOSYSTEMS = {
    "npm": "npm", "pypi": "python", "go": "go", "maven": "java",
    "rubygems": "ruby", "crates.io": "rust", "packagist": "php", "nuget": "dotnet",
}


def _osv_severity(vuln):
    ds = _d(vuln.get("database_specific"))
    sev = _s(ds.get("severity")).upper()
    if sev in SEVERITY_ORDER:
        return sev
    # CVSS score fallback
    for s in _l(vuln.get("severity")):
        score = _s(_d(s).get("score"))
        m = re.search(r"/([0-9.]+)$", score) or re.match(r"^([0-9.]+)$", score)
        if m:
            try:
                v = float(m.group(1))
            except ValueError:
                continue
            return ("CRITICAL" if v >= 9 else "HIGH" if v >= 7 else
                    "MEDIUM" if v >= 4 else "LOW")
    return "UNKNOWN"


def _osv_fixed_version(vuln):
    """Highest 'fixed' event across affected ranges."""
    fixes = []
    for aff in _l(vuln.get("affected")):
        for rng in _l(_d(aff).get("ranges")):
            for ev in _l(_d(rng).get("events")):
                f = _s(_d(ev).get("fixed"))
                if f:
                    fixes.append(f)
    return highest_version(fixes) if fixes else ""


def parse_osv(data: dict, os_override: str = None):
    parsed = _empty_parsed("osv-scan")
    os_string = ""
    for result in _l(data.get("results")):
        if not isinstance(result, dict):
            continue
        src = _d(result.get("source"))
        if _s(src.get("path")):
            parsed["target"] = _s(src.get("path"))
        for p in _l(result.get("packages")):
            if not isinstance(p, dict):
                continue
            pkg = _d(p.get("package"))
            eco_raw = _s(pkg.get("ecosystem"))
            eco_base = eco_raw.split(":")[0].strip().lower()
            ecosystem = None
            if eco_base in OSV_OS_ECOSYSTEMS:
                if not os_string:
                    os_string = eco_raw.replace(":", " ")
            else:
                ecosystem = OSV_LANG_ECOSYSTEMS.get(eco_base)
                if not ecosystem:
                    continue  # unknown ecosystem
            for v in _l(p.get("vulnerabilities")):
                if not isinstance(v, dict):
                    continue
                refs = [_s(_d(r).get("url")) for r in _l(v.get("references"))]
                _add_finding(
                    parsed, pkg=_s(pkg.get("name")),
                    installed=_s(pkg.get("version")) or None,
                    fixed=_osv_fixed_version(v),
                    severity=_osv_severity(v),
                    vuln_id=_s(v.get("id")),
                    references=[r for r in refs if r],
                    ecosystem=ecosystem,
                    location=_s(src.get("path")) if ecosystem else None)
    parsed["family"], parsed["os_name"] = parse_os_string(os_override or os_string)
    return parsed


# ---------------------------------------------------------------------------
# Sysdig scan-result JSON parser (sysdig-cli-scanner / Vulnerability Management API)
# ---------------------------------------------------------------------------
# Shape: {"result": {"metadata": {...}, "packages": [
#   {"type": "os"|"java"|..., "name", "version", "path", "suggestedFix",
#    "vulns": [{"name": "CVE-...", "severity": {"value": "Critical"},
#               "fixedInVersion": "..."}]}]}}
# NOTE: field names validated against sysdig-cli-scanner output; treat as beta
# until confirmed against your tenant's API version.

SYSDIG_NUMERIC_SEVERITY = {
    0: "CRITICAL", 1: "HIGH", 2: "MEDIUM", 3: "LOW", 4: "LOW",  # 4 = negligible
    5: "UNKNOWN", 6: "UNKNOWN", 7: "UNKNOWN",
}


def _sysdig_severity(sev):
    if isinstance(sev, dict):
        sev = sev.get("value", "UNKNOWN")
    if isinstance(sev, bool):
        return "UNKNOWN"
    if isinstance(sev, (int, float)):
        return SYSDIG_NUMERIC_SEVERITY.get(int(sev), "UNKNOWN")
    return (_s(sev) or "UNKNOWN").upper() or "UNKNOWN"


def parse_sysdig_json(data: dict, os_override: str = None):
    result = data.get("result", data) if isinstance(data, dict) else {}
    result = _d(result)
    meta = _d(result.get("metadata"))
    target = (_s(meta.get("pullString")) or _s(meta.get("imageId"))
              or _s(result.get("mainAssetName")) or "sysdig-scan")
    os_string = _s(meta.get("baseOs")) or _s(meta.get("os"))

    # packages: list (cli-scanner) or dict keyed by id (VM API v1)
    packages = result.get("packages")
    if isinstance(packages, dict):
        pkg_iter = packages.values()
    else:
        pkg_iter = _l(packages)

    # VM API v1 keeps vulnerabilities in a separate table referenced by id
    vuln_table = result.get("vulnerabilities")
    if isinstance(vuln_table, list):
        vuln_table = {(_s(v.get("id")) or _s(v.get("name"))): v
                      for v in vuln_table if isinstance(v, dict)}
    else:
        vuln_table = _d(vuln_table)

    parsed = _empty_parsed(target)
    for pkg in pkg_iter:
        if not isinstance(pkg, dict):
            continue
        pkg_type = _s(pkg.get("type")).lower()
        ecosystem = None
        if pkg_type not in SYSDIG_OS_PKG_TYPES:
            ecosystem = LANG_ECOSYSTEMS.get(pkg_type)
            if not ecosystem:
                continue

        vulns = pkg.get("vulns")
        if not isinstance(vulns, list):
            refs = (_l(pkg.get("vulnsRefs")) or _l(pkg.get("vulnerabilitiesRefs"))
                    or _l(pkg.get("vulnRefs")))
            vulns = [vuln_table[r] for r in refs
                     if isinstance(r, str) and isinstance(vuln_table.get(r), dict)]

        for v in vulns or []:
            if not isinstance(v, dict):
                v = vuln_table.get(v) if isinstance(v, str) else None
                if not isinstance(v, dict):
                    continue
            fixed = (_s(v.get("fixedInVersion")) or _s(v.get("fixVersion"))
                     or _s(pkg.get("suggestedFix")))
            _add_finding(parsed, pkg=_s(pkg.get("name")),
                         installed=_s(pkg.get("version")) or None, fixed=fixed,
                         severity=_sysdig_severity(v.get("severity")),
                         vuln_id=_s(v.get("name")) or _s(v.get("vulnName")) or _s(v.get("cve")),
                         ecosystem=ecosystem,
                         location=_s(pkg.get("path")) or None,
                         in_use=bool(pkg.get("isRunning")),
                         exploitable=bool(v.get("exploitable")),
                         kev=bool(v.get("cisaKev")))

    if os_override or os_string:
        parsed["family"], parsed["os_name"] = parse_os_string(os_override or os_string)
    return parsed


def fetch_sysdig(api_url: str, token: str, result_id: str = None, filter_expr: str = None,
                 insecure: bool = False, ca_bundle: str = None, limit: int = 1):
    """Fetch a scan result from the Sysdig Vulnerability Management API.

    Without --result-id, lists runtime results and picks the first match.
    Beta: endpoint paths follow the public VM API (v1); report issues with
    your region/API version if they differ.
    """
    import ssl
    import urllib.request

    if insecure:
        ctx = ssl._create_unverified_context()
        print("warning: TLS certificate verification disabled (--insecure). "
              "Use --ca-bundle with your corporate CA for regular use.",
              file=sys.stderr)
    elif ca_bundle:
        ctx = ssl.create_default_context(cafile=ca_bundle)
    else:
        ctx = ssl.create_default_context()

    # strip regular and full-width whitespace that sneaks in via copy-paste
    token = (token or "").strip(" \t\r\n　 ")

    import urllib.error
    import urllib.parse

    base = urllib.parse.urlsplit(api_url.rstrip("/"))
    if base.scheme not in ("http", "https") or not base.netloc:
        sys.exit(f"error: invalid --api-url '{api_url}'.")

    class _NoAuthCrossOrigin(urllib.request.HTTPRedirectHandler):
        """Follow redirects, but strip the bearer token if a redirect leaves
        the original origin — urllib otherwise resends Authorization to the new
        host (no token-stripping like requests has)."""
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            new = super().redirect_request(req, fp, code, msg, headers, newurl)
            if new is not None:
                dest = urllib.parse.urlsplit(newurl)
                if (dest.scheme, dest.netloc) != (base.scheme, base.netloc):
                    try:
                        new.remove_header("Authorization")
                    except Exception:
                        pass
            return new

    opener = urllib.request.build_opener(
        _NoAuthCrossOrigin(),
        urllib.request.HTTPSHandler(context=ctx))

    def get(path):
        req = urllib.request.Request(
            base.geturl() + path,
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/json"})
        try:
            with opener.open(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except ssl.SSLCertVerificationError as e:
            sys.exit(f"error: TLS verification failed ({e.reason}). If you are "
                     "behind a corporate TLS-inspecting proxy, pass "
                     "--ca-bundle /path/to/corp-ca.pem, or --insecure to test.")

    # API path prefixes vary by tenant generation; probe in order.
    prefixes = ["/secure/vulnerability/v1", "/secure/vulnerability/v1beta1"]
    last_err = None

    if not result_id:
        suffix = f"/runtime-results?limit={max(1, int(limit))}"
        if filter_expr:
            import urllib.parse
            suffix += "&filter=" + urllib.parse.quote(filter_expr)
        listing = prefix = None
        for p in prefixes:
            try:
                listing = get(p + suffix)
                prefix = p
                break
            except urllib.error.HTTPError as e:
                last_err = f"{p}{suffix} -> HTTP {e.code}"
                if e.code == 401:
                    sys.exit("error: 401 Unauthorized. Check SYSDIG_API_TOKEN "
                             "(Settings > Sysdig Secure API token) and that "
                             "--api-url matches your tenant region.")
                if e.code != 404:
                    raise
        if listing is None:
            sys.exit("error: no known runtime-results endpoint responded "
                     f"(last: {last_err}). Your tenant may use a different "
                     "API version — run with a Sysdig scan-result JSON file "
                     "instead, and open an issue with your region.")
        rows = [r for r in _l(listing.get("data")) if isinstance(r, dict)]
        if not rows:
            sys.exit("error: no runtime scan results matched. "
                     "Try --result-id or adjust --filter.")
        results = []
        for row in rows:
            rid = _s(row.get("resultId")) or _s(row.get("id"))
            if not is_safe_identifier(rid):
                print(f"warning: skipping result with unexpected id {rid!r}",
                      file=sys.stderr)
                continue
            name = _s(row.get("mainAssetName")) or _s(row.get("resourceName"))
            print(f"info: fetching {rid} ({name})", file=sys.stderr)
            results.append(get(f"{prefix}/results/{rid}"))
        return results

    if not is_safe_identifier(result_id):
        sys.exit(f"error: --result-id must match [A-Za-z0-9._-]+ (got {result_id!r}).")
    for p in prefixes:
        try:
            return [get(f"{p}/results/{result_id}")]
        except urllib.error.HTTPError as e:
            last_err = f"{p}/results/{result_id} -> HTTP {e.code}"
            if e.code != 404:
                raise
    sys.exit(f"error: result not found on any known endpoint (last: {last_err}).")


def detect_input_format(raw: str):
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError:
            return "trivy"
        if "Results" in data:
            return "trivy"
        if "matches" in data:
            return "grype"
        if isinstance(data, dict) and isinstance(data.get("results"), list) and \
                any(isinstance(r, dict) and "packages" in r
                    for r in data["results"]):
            return "osv"
        if "packages" in data.get("result", data):
            return "sysdig-json"
        return "trivy"
    return "sysdig-csv"


# ---------------------------------------------------------------------------
# Plan builder
# ---------------------------------------------------------------------------

def parse_scan_file(path, input_fmt="auto", os_override=None):
    """Read and parse one scan file (or '-' for stdin) into a parsed dict.
    Shared by the plan path and verify. Exits cleanly on bad input."""
    try:
        raw = sys.stdin.read() if path == "-" else \
            open(path, encoding="utf-8-sig").read()
    except OSError as e:
        sys.exit(f"error: cannot read '{path}': {e.strerror or e}")
    if not raw.strip():
        sys.exit(f"error: '{path}' is empty.")
    fmt = input_fmt if input_fmt != "auto" else detect_input_format(raw)

    if fmt in ("trivy", "grype", "osv", "sysdig-json"):
        try:
            data = json.loads(raw)
        except ValueError as e:
            sys.exit(f"error: '{path}' is not valid JSON ({e}).")
    if fmt == "trivy":
        if "Results" not in data:
            sys.exit(f"error: '{path}' does not look like Trivy JSON (missing 'Results').")
        parsed = parse_trivy(data)
        if os_override:
            parsed["family"], parsed["os_name"] = parse_os_string(os_override)
    elif fmt == "grype":
        parsed = parse_grype(data)
        if os_override:
            parsed["family"], parsed["os_name"] = parse_os_string(os_override)
    elif fmt == "osv":
        parsed = parse_osv(data, os_override=os_override)
    elif fmt == "sysdig-json":
        parsed = parse_sysdig_json(data, os_override=os_override)
    else:
        parsed = parse_sysdig_csv(raw, os_override=os_override)
    return parsed


def build_plan(parsed, min_severity="UNKNOWN", context="auto", eol_fn=detect_eol):
    pkg_manager = detect_pkg_manager(parsed["family"], parsed["os_name"])
    threshold = SEVERITY_ORDER.get(min_severity.upper(), 0)

    # Per-package items (kept for JSON consumers / tests)
    items = []
    for pkg, f in sorted(parsed["findings"].items()):
        if SEVERITY_ORDER.get(f["max_severity"], 0) < threshold:
            continue
        target_version = highest_version(f["fixed_versions"])
        items.append({
            "package": pkg,
            "installed": f["installed"],
            "fix_version": target_version,
            "severity": f["max_severity"],
            "cves": sorted({v["id"] for v in f["vulns"] if v["id"]}),
            "command": fix_command(pkg_manager, pkg, target_version) if pkg_manager else None,
            "backport": detect_backport(target_version),
            "advisories": classify_references(f["references"]),
            "hints": post_update_hints(pkg),
            "in_use": f["in_use"], "exploitable": f["exploitable"], "kev": f["kev"],
        })
    items.sort(key=lambda i: -SEVERITY_ORDER.get(i["severity"], 0))

    # Consolidated steps: same installed+fixed version pair => almost always
    # binary packages built from one source package => one remediation action.
    groups = defaultdict(list)
    for item in items:
        groups[(item["installed"], item["fix_version"])].append(item)

    steps = []
    for (installed, fix_version), members in groups.items():
        packages = [m["package"] for m in members]
        cves = sorted({c for m in members for c in m["cves"]})
        severity = max((m["severity"] for m in members),
                       key=lambda s: SEVERITY_ORDER.get(s, 0))
        advisories, seen = [], set()
        for m in members:
            for a in m["advisories"]:
                if a[1] not in seen:
                    seen.add(a[1])
                    advisories.append(a)
        hints = sorted({h for m in members for h in m["hints"]})
        steps.append({
            "packages": packages,
            "installed": installed,
            "fix_version": fix_version,
            "severity": severity,
            "cves": cves,
            "command": fix_command(pkg_manager, packages, fix_version) if pkg_manager else None,
            "backport": detect_backport(fix_version),
            "advisories": advisories[:3],
            "hints": hints,
            "in_use": any(m["in_use"] for m in members),
            "exploitable": any(m["exploitable"] for m in members),
            "kev": any(m["kev"] for m in members),
        })
    steps.sort(key=lambda s: (-SEVERITY_ORDER.get(s["severity"], 0),
                              -(s["kev"] * 4 + s["exploitable"] * 2 + s["in_use"])))

    # Application dependencies (lang-pkgs): fix = upgrade + rebuild
    app_steps = []
    for (ecosystem, pkg), a in sorted(parsed.get("app", {}).items()):
        if SEVERITY_ORDER.get(a["max_severity"], 0) < threshold:
            continue
        fix_version = highest_version(a["fixed_versions"])
        app_steps.append({
            "ecosystem": ecosystem,
            "package": pkg,
            "installed": a["installed"],
            "fix_version": fix_version,
            "severity": a["max_severity"],
            "cves": sorted({v["id"] for v in a["vulns"] if v["id"]}),
            "locations": sorted(a["locations"]),
            "action": app_fix_action(ecosystem, pkg, fix_version),
            "in_use": a["in_use"], "exploitable": a["exploitable"], "kev": a["kev"],
        })
    app_steps.sort(key=lambda s: (-SEVERITY_ORDER.get(s["severity"], 0),
                                  -(s["kev"] * 4 + s["exploitable"] * 2 + s["in_use"])))

    # Unfixed findings (never filtered by min-severity: silent omission erodes trust)
    unfixed = []
    for pkg, u in sorted(parsed["unfixed"].items()):
        statuses = {v["status"] for v in u["vulns"]}
        status = next(iter(statuses)) if len(statuses) == 1 else "mixed"
        unfixed.append({
            "package": pkg,
            "installed": u["installed"],
            "severity": u["max_severity"],
            "cves": sorted({v["id"] for v in u["vulns"] if v["id"]}),
            "status": status,
            "status_label": UNFIXED_STATUS_LABELS.get(status, f"Status: {status}"),
            "in_use": u["in_use"], "exploitable": u["exploitable"], "kev": u["kev"],
        })
    unfixed.sort(key=lambda i: -SEVERITY_ORDER.get(i["severity"], 0))

    third_party = detect_third_party(parsed["target"])
    if context == "auto":
        effective_context = "image" if (third_party or
                                        looks_like_image(parsed["target"])) else "host"
    else:
        effective_context = context

    return {
        "target": parsed["target"],
        "os": f'{parsed["family"]} {parsed["os_name"]}'.strip(),
        "pkg_manager": pkg_manager,
        "preamble": preamble(pkg_manager) if pkg_manager else None,
        "eol_warning": eol_fn(parsed["family"], parsed["os_name"]),
        "third_party": third_party,
        "context": effective_context,
        "items": items,
        "steps": steps,
        "app_steps": app_steps,
        "unfixed": unfixed,
        "rejected": parsed.get("rejected", []),
    }


# ---------------------------------------------------------------------------
# Fleet summary (multi-workload aggregation)
# ---------------------------------------------------------------------------

def build_fleet_summary(plans, top=15):
    """Aggregate identical fixes across workloads: one fix -> N targets."""
    agg = {}

    def add(key, kind, label, command, severity, cves, flags, target):
        e = agg.setdefault(key, {
            "kind": kind, "label": label, "command": command,
            "severity": severity, "cves": set(), "targets": set(),
            "kev": False, "exploitable": False, "in_use": False,
        })
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(e["severity"], 0):
            e["severity"] = severity
        e["cves"].update(cves)
        e["targets"].add(target)
        for f in ("kev", "exploitable", "in_use"):
            e[f] = e[f] or flags.get(f, False)

    for plan in plans:
        target = plan["target"]
        for s in plan["steps"]:
            key = ("os", s["command"] or f"{s['packages']}={s['fix_version']}")
            add(key, "os", ", ".join(s["packages"]), s["command"],
                s["severity"], s["cves"], s, target)
        for s in plan["app_steps"]:
            key = ("app", s["ecosystem"], s["package"], s["fix_version"])
            add(key, "app", f"{s['package']} -> {s['fix_version']} ({s['ecosystem']})",
                None, s["severity"], s["cves"], s, target)

    entries = list(agg.values())
    entries.sort(key=lambda e: (-len(e["targets"]),
                                -SEVERITY_ORDER.get(e["severity"], 0),
                                -(e["kev"] * 4 + e["exploitable"] * 2 + e["in_use"])))
    for e in entries:
        e["cves"] = sorted(e["cves"])
        e["targets"] = sorted(e["targets"])
    return {"workloads": len(plans), "unique_fixes": len(entries),
            "top_fixes": entries[:top]}


def render_fleet_markdown(summary):
    lines = ["# Fleet summary", ""]
    lines.append(f"- **Workloads**: {summary['workloads']}")
    lines.append(f"- **Unique fixes across fleet**: {summary['unique_fixes']}")
    lines.append("")
    lines.append("## Top fixes (one action, most coverage)")
    lines.append("")
    for e in summary["top_fixes"]:
        n = len(e["targets"])
        badges = _priority_badges(e)
        badge = f" — 🚨 {', '.join(badges)}" if badges else ""
        lines.append(f"- **{e['label']}** `{e['severity']}` — fixes "
                     f"**{n} workload{'s' if n > 1 else ''}**, "
                     f"{len(e['cves'])} CVEs{badge}")
        if e["command"]:
            lines.append(f"  - `{e['command']}`")
        lines.append(f"  - Targets: {', '.join(f'`{t}`' for t in e['targets'])}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _priority_badges(x):
    badges = []
    if x.get("kev"):
        badges.append("CISA KEV (known exploited)")
    if x.get("exploitable"):
        badges.append("public exploit available")
    if x.get("in_use"):
        badges.append("package in use at runtime")
    return badges


def _step_title(step):
    pkgs = step["packages"]
    if len(pkgs) == 1:
        return pkgs[0]
    return f"{pkgs[0]} (+{len(pkgs) - 1} related packages)"


def render_markdown(plan):
    lines = []
    lines.append(f"# Remediation plan: `{plan['target']}`")
    lines.append("")
    lines.append(f"- **OS**: {plan['os']}")
    lines.append(f"- **Package manager**: {plan['pkg_manager'] or 'unsupported (see notes)'}")
    lines.append(f"- **Remediation steps**: {len(plan['steps'])} "
                 f"(covering {len(plan['items'])} packages)")
    if plan["app_steps"]:
        lines.append(f"- **Application dependencies (rebuild required)**: "
                     f"{len(plan['app_steps'])}")
    if plan["unfixed"]:
        lines.append(f"- **No fix available**: {len(plan['unfixed'])} packages")
    lines.append("")
    if plan["eol_warning"]:
        lines.append(f"> ⚠️ **EOL**: {plan['eol_warning']}")
        lines.append("")
    if plan["third_party"]:
        lines.append(f"> ℹ️ **Third-party image** (built by {plan['third_party']}): "
                     f"you likely don't build this image, so the highest-leverage "
                     f"fix is upgrading to the newest vendor tag/release. The "
                     f"commands below are reference for the image maintainer — "
                     f"check for a newer tag first.")
        lines.append("")
    elif plan.get("context") == "image" and plan["steps"]:
        lines.append("> 🏗️ **Container image** (immutable infra): the durable fix "
                     "is to update the base image / package versions in your "
                     "Dockerfile and **rebuild**, not to patch a running "
                     "container in place. Use the commands below in the build "
                     "(e.g. a `RUN` layer), then redeploy — running them in a "
                     "live container is lost on the next restart.")
        lines.append("")
    if not plan["pkg_manager"]:
        lines.append("> Unsupported OS family for command generation. "
                     "Findings are listed without commands.")
        lines.append("")

    for step in plan["steps"]:
        lines.append(f"## {_step_title(step)}  `{step['severity']}`")
        lines.append("")
        if len(step["packages"]) > 1:
            lines.append(f"- Packages: {', '.join(f'`{p}`' for p in step['packages'])} "
                         f"(same installed/fixed versions — updated together)")
        lines.append(f"- Installed: `{step['installed']}` -> Fix: `{step['fix_version']}`")
        lines.append(f"- CVEs: {', '.join(step['cves'])}")
        badges = _priority_badges(step)
        if badges:
            lines.append(f"- 🚨 **Priority**: {', '.join(badges)}")
        if step["backport"]:
            lines.append(f"- **Vendor backport ({step['backport']})**: the fixed version is a "
                         f"distro backport — it will not match the upstream version number. "
                         f"Scanners comparing against upstream may still flag it; trust the "
                         f"vendor advisory below.")
        if step["command"]:
            lines.append("")
            lines.append("```bash")
            lines.append(step["command"])
            lines.append("```")
        for hint in step["hints"]:
            lines.append(f"- ⚠️ {hint}")
        if step["advisories"]:
            lines.append("- Advisories: " + " / ".join(
                f"[{label}]({url})" for label, url in step["advisories"]))
        lines.append("")

    if plan["app_steps"]:
        lines.append("## Application dependencies (rebuild required)")
        lines.append("")
        lines.append("These are language packages inside your application or image. "
                     "OS package managers cannot fix them — and neither can copa. "
                     "Update the dependency, rebuild, and redeploy.")
        lines.append("")
        for step in plan["app_steps"]:
            lines.append(f"### {step['package']}  `{step['severity']}` ({step['ecosystem']})")
            lines.append("")
            lines.append(f"- Installed: `{step['installed']}` -> Fix: `{step['fix_version']}`")
            lines.append(f"- CVEs: {', '.join(step['cves'])}")
            if step["locations"]:
                lines.append(f"- Found in: {', '.join(f'`{l}`' for l in step['locations'])}")
            badges = _priority_badges(step)
            if badges:
                lines.append(f"- 🚨 **Priority**: {', '.join(badges)}")
            lines.append(f"- Fix: {step['action']}")
            lines.append("")

    if plan["unfixed"]:
        lines.append("## No fix available")
        lines.append("")
        lines.append("These findings have no fixed version yet. Options: mitigate, "
                     "accept the risk with justification, or track the vendor advisory.")
        lines.append("")
        for u in plan["unfixed"]:
            line = (f"- **{u['package']}** `{u['severity']}` "
                    f"({', '.join(u['cves'])}) — {u['status_label']}")
            badges = _priority_badges(u)
            if badges:
                line += f" — 🚨 {', '.join(badges)}"
            lines.append(line)
        lines.append("")

    if plan.get("rejected"):
        lines.append("## ⛔ Rejected findings (unsafe scan input)")
        lines.append("")
        lines.append("These package identifiers failed distro naming validation "
                     "and were **not** turned into commands. Package names "
                     "containing shell metacharacters are not legitimate — this "
                     "usually means malformed or malicious scan input. Investigate "
                     "the source image before trusting the scan.")
        lines.append("")
        for r in plan["rejected"]:
            lines.append(f"- `{r['package']}` — {r['reason']}")
        lines.append("")

    return "\n".join(lines)


def render_shell(plan):
    lines = [
        "#!/usr/bin/env bash",
        f"# Remediation script generated by remedify v{__version__} "
        f"for {plan['target']} ({plan['os']})",
        "# Review before running. Run as root or with sudo.",
        "# These commands are derived from scan input; package identifiers are",
        "# validated against distro naming rules before being emitted here.",
        "set -euo pipefail",
        "",
    ]
    for r in plan.get("rejected", []):
        lines.append(f"# REJECTED (unsafe scan input, not run): "
                     f"{r['package']} — {r['reason']}")
    if plan.get("rejected"):
        lines.append("")
    if plan["eol_warning"]:
        lines.append(f"# EOL WARNING: {plan['eol_warning']}")
        lines.append("")
    if plan["third_party"]:
        lines.append(f"# THIRD-PARTY IMAGE (built by {plan['third_party']}): prefer "
                     f"upgrading to the newest vendor tag over patching in place.")
        lines.append("")
    if plan["pkg_manager"] == "apt":
        lines.append("export DEBIAN_FRONTEND=noninteractive")
    if plan["preamble"]:
        lines.append(plan["preamble"])
        lines.append("")
    needs_reboot = False
    for step in plan["steps"]:
        if not step["command"]:
            continue
        step = dict(step, command=fix_command(
            plan["pkg_manager"], step["packages"], step["fix_version"],
            assume_yes=True))
        lines.append(f"# {', '.join(step['packages'])} {step['installed']} -> "
                     f"{step['fix_version']} [{step['severity']}] {', '.join(step['cves'])}")
        badges = _priority_badges(step)
        if badges:
            lines.append(f"#   PRIORITY: {', '.join(badges)}")
        if step["backport"]:
            lines.append(f"#   NOTE: {step['backport']} vendor backport — version differs from upstream")
        for hint in step["hints"]:
            lines.append(f"#   WARNING: {hint}")
            if "reboot" in hint.lower():
                needs_reboot = True
        lines.append(step["command"])
        lines.append("")
    if plan["app_steps"]:
        lines.append("# --- Application dependencies: fix in source + rebuild image ---")
        for step in plan["app_steps"]:
            lines.append(f"# {step['package']} ({step['ecosystem']}) "
                         f"{step['installed']} -> {step['fix_version']} "
                         f"[{step['severity']}] {', '.join(step['cves'])}")
        lines.append("")
    if plan["unfixed"]:
        lines.append("# --- No fix available (informational) ---")
        for u in plan["unfixed"]:
            lines.append(f"# {u['package']} [{u['severity']}] "
                         f"{', '.join(u['cves'])}: {u['status_label']}")
        lines.append("")
    if needs_reboot:
        lines.append('echo "One or more updates require a reboot. Schedule one."')
    return "\n".join(lines)


def render_json(plan):
    return json.dumps(plan, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# verify — closed loop: did the fix actually land?
# ---------------------------------------------------------------------------
# Diffs a before/after scan pair. Built entirely on compare_versions (the
# dpkg-correct comparator with the 10k property test) — no new version logic.
# "remaining" is sub-typed so an operator knows *why* a finding survived.

def _flatten_findings(parsed):
    """(pkg, cve) -> {installed, severity, required, ecosystem}. required is the
    highest fixed version, or None when no fix exists (unfixed bucket)."""
    out = {}

    def put(pkg, ecosystem, installed, required, vulns):
        for v in vulns:
            cve = v.get("id")
            if not cve:
                continue
            out[(pkg, cve)] = {
                "installed": _s(installed) or None,
                "severity": v.get("severity", "UNKNOWN"),
                "required": required,
                "ecosystem": ecosystem,
            }

    for pkg, f in parsed["findings"].items():
        req = highest_version(f["fixed_versions"]) if f["fixed_versions"] else None
        put(pkg, None, f["installed"], req, f["vulns"])
    for (eco, pkg), a in parsed.get("app", {}).items():
        req = highest_version(a["fixed_versions"]) if a["fixed_versions"] else None
        put(pkg, eco, a["installed"], req, a["vulns"])
    for pkg, u in parsed["unfixed"].items():
        put(pkg, u.get("ecosystem"), u["installed"], None, u["vulns"])
    return out


def _classify(before, after):
    """Return (category, reason, detail) for a (pkg,cve) present in both."""
    bi, ai = before["installed"], after["installed"]
    required = after["required"] or before["required"]

    # fix version exists and we're at/above it, yet still flagged
    if required and ai and compare_versions(ai, required) >= 0:
        return ("anomaly", "installed_at_or_above_fix",
                f"installed {ai} ≥ fix {required}, still reported "
                f"(scanner cache / version-string mismatch?)")
    if required is None:
        return ("remaining", "no_fix", "no fixed version available")
    # a fix appeared since baseline (was unfixable) — more informative than
    # "untouched", so check before the unchanged-version branch
    if before["required"] is None and after["required"] is not None:
        return ("remaining", "now_fixable",
                f"fix newly published — was unfixable at baseline; upgrade to {required}")
    if ai and bi and compare_versions(ai, bi) < 0:
        return ("remaining", "regressed", f"version went backwards: {ai}")
    if ai and bi and compare_versions(ai, bi) == 0:
        return ("remaining", "untouched", f"still {ai} (fix {required})")
    return ("remaining", "upgraded_but_short",
            f"upgraded to {ai} but need {required}")


def verify(before_parsed, after_parsed):
    b = _flatten_findings(before_parsed)
    a = _flatten_findings(after_parsed)
    b_pkgs = {p for (p, _) in b}
    a_pkgs = {p for (p, _) in a}

    resolved, remaining, new, anomalies = [], [], [], []

    for key, bf in b.items():
        pkg, cve = key
        if key not in a:
            reason = "package_removed" if pkg not in a_pkgs else "not_reported"
            resolved.append({"package": pkg, "cve": cve,
                             "severity": bf["severity"], "reason": reason})
            continue
        af = a[key]
        cat, reason, detail = _classify(bf, af)
        row = {"package": pkg, "cve": cve, "severity": af["severity"],
               "reason": reason, "detail": detail,
               "installed": af["installed"], "required": af["required"] or bf["required"],
               "backport": detect_backport(af["required"] or bf["required"] or "")}
        (anomalies if cat == "anomaly" else remaining).append(row)

    for key, af in a.items():
        if key not in b:
            new.append({"package": key[0], "cve": key[1],
                        "severity": af["severity"], "installed": af["installed"],
                        "required": af["required"]})

    # scoring: "fixable" = things we could have fixed (resolved + remaining that
    # had a fix). no_fix remaining is expected, not counted against the rate.
    actionable_remaining = [r for r in remaining if r["reason"] != "no_fix"]
    unfixable_remaining = [r for r in remaining if r["reason"] == "no_fix"]
    fixable = len(resolved) + len(actionable_remaining)
    rate = (len(resolved) / fixable) if fixable else 1.0

    return {
        "before": before_parsed["target"], "after": after_parsed["target"],
        "os": f'{after_parsed["family"]} {after_parsed["os_name"]}'.strip(),
        "different_target": before_parsed["target"] != after_parsed["target"],
        "score": {
            "fixable": fixable, "resolved": len(resolved),
            "rate": round(rate, 3),
            "remaining_actionable": len(actionable_remaining),
            "new": len(new), "unfixable_remaining": len(unfixable_remaining),
            "anomalies": len(anomalies),
        },
        "resolved": sorted(resolved, key=lambda r: r["package"]),
        "remaining": sorted(actionable_remaining + unfixable_remaining,
                            key=lambda r: -SEVERITY_ORDER.get(r["severity"], 0)),
        "new": sorted(new, key=lambda r: -SEVERITY_ORDER.get(r["severity"], 0)),
        "anomalies": anomalies,
    }


_REASON_LABEL = {
    "untouched": "untouched",
    "upgraded_but_short": "upgraded but short of the fix",
    "regressed": "version regressed",
    "no_fix": "no fix available (expected)",
    "now_fixable": "🟢 fix newly published — was unfixable at baseline",
}


def render_verify_markdown(v):
    L = ["# Remediation verification", ""]
    L.append(f"**{v['before']} → {v['after']}** ({v['os']})")
    s = v["score"]
    L.append("")
    L.append(f"Fixed **{s['resolved']} / {s['fixable']}** fixable findings — "
             f"**{int(s['rate'] * 100)}%**. {s['remaining_actionable']} remaining, "
             f"{s['new']} new, {s['unfixable_remaining']} unfixable (expected)"
             + (f", {s['anomalies']} anomalies" if s['anomalies'] else "") + ".")
    L.append("")
    if v["different_target"]:
        L.append("> ⚠️ Comparing different targets — treat cross-target results "
                 "as advisory.")
        L.append("")

    actionable = [r for r in v["remaining"] if r["reason"] != "no_fix"]
    if actionable:
        L.append(f"## ⛔ Still vulnerable ({len(actionable)}) — action needed")
        L.append("")
        for r in actionable:
            line = (f"- **{r['package']}** `{r['cve']}` {r['severity']} — "
                    f"{_REASON_LABEL.get(r['reason'], r['reason'])}: {r['detail']}")
            L.append(line)
            if r["reason"] == "upgraded_but_short" and r["backport"]:
                L.append(f"  - Vendor backport ({r['backport']}): the fix version "
                         f"won't match the upstream number.")
        L.append("")
    if v["new"]:
        L.append(f"## 🆕 New since baseline ({len(v['new'])})")
        L.append("")
        for r in v["new"]:
            L.append(f"- **{r['package']}** `{r['cve']}` {r['severity']}")
        L.append("")
    if v["anomalies"]:
        L.append(f"## 🔎 Anomalies ({len(v['anomalies'])})")
        L.append("")
        for r in v["anomalies"]:
            L.append(f"- **{r['package']}** `{r['cve']}` — {r['detail']}")
        L.append("")
    if v["resolved"]:
        L.append(f"## ✅ Resolved ({len(v['resolved'])})")
        L.append("")
        L.append(", ".join(sorted({r["cve"] for r in v["resolved"]})))
        L.append("")
    nofix = [r for r in v["remaining"] if r["reason"] == "no_fix"]
    if nofix:
        L.append(f"## 🟡 No fix available — still present, expected ({len(nofix)})")
        L.append("")
        for r in nofix:
            L.append(f"- **{r['package']}** `{r['cve']}` {r['severity']}")
        L.append("")
    return "\n".join(L)


def verify_exit_code(v, fail_on):
    """exit 2 if any actionable-remaining or new finding at/above fail_on."""
    if not fail_on:
        return 0
    threshold = SEVERITY_ORDER.get(fail_on.upper(), 0)
    pool = [r for r in v["remaining"] if r["reason"] != "no_fix"] + v["new"]
    if any(SEVERITY_ORDER.get(r["severity"], 0) >= threshold for r in pool):
        return 2
    return 0


def _yaml_str(s):
    """Quote a string for our generated YAML (conservative: always quote)."""
    return json.dumps(_s(s), ensure_ascii=False)


def render_ansible(plan):
    """Emit an Ansible playbook play for one plan. String-built YAML —
    structure is fixed, so no YAML library is needed (zero dependencies)."""
    pm = plan["pkg_manager"]
    module = {
        "apt": ("ansible.builtin.apt", "name", lambda s: [f"{p}={s['fix_version']}" for p in s["packages"]]),
        "dnf": ("ansible.builtin.dnf", "name", lambda s: [f"{p}-{s['fix_version']}" for p in s["packages"]]),
        "yum": ("ansible.builtin.yum", "name", lambda s: [f"{p}-{s['fix_version']}" for p in s["packages"]]),
        "apk": ("community.general.apk", "name", lambda s: list(s["packages"])),
        "zypper": ("community.general.zypper", "name", lambda s: list(s["packages"])),
    }.get(pm)

    L = []
    L.append(f"# Remediation playbook generated by remedify v{__version__}")
    L.append(f"# Target: {plan['target']} ({plan['os']})")
    if plan["eol_warning"]:
        L.append(f"# EOL WARNING: {plan['eol_warning']}")
    if plan["third_party"]:
        L.append(f"# THIRD-PARTY IMAGE: prefer upgrading to the newest vendor tag.")
    for u in plan["unfixed"]:
        L.append(f"# NO FIX AVAILABLE: {u['package']} "
                 f"[{u['severity']}] {', '.join(u['cves'])} — {u['status_label']}")
    for s in plan["app_steps"]:
        L.append(f"# APP DEPENDENCY (fix in source + rebuild): {s['package']} "
                 f"-> {s['fix_version']} ({s['ecosystem']})")
    L.append(f"- name: {_yaml_str('Remediate ' + plan['target'])}")
    L.append("  hosts: \"{{ target_hosts | default('all') }}\"")
    L.append("  become: true")
    L.append("  vars:")
    L.append("    allow_reboot: false")
    L.append("  tasks:")

    if not module:
        L.append("    - name: \"Unsupported OS family — no package tasks generated\"")
        L.append("      ansible.builtin.debug:")
        L.append(f"        msg: {_yaml_str('remedify could not map OS ' + plan['os'])}")
        return "\n".join(L) + "\n"

    mod_name, key, specs = module
    needs_reboot = False
    if pm == "apt":
        L.append("    - name: \"Refresh package cache\"")
        L.append(f"      {mod_name}:")
        L.append("        update_cache: true")
    for s in plan["steps"]:
        title = (f"Fix {', '.join(s['packages'])} [{s['severity']}] "
                 f"({', '.join(s['cves'][:4])}"
                 f"{' …' if len(s['cves']) > 4 else ''})")
        L.append(f"    - name: {_yaml_str(title)}")
        L.append(f"      {mod_name}:")
        L.append(f"        {key}:")
        for item in specs(s):
            L.append(f"          - {_yaml_str(item)}")
        if pm in ("apt", "dnf", "yum"):
            L.append("        state: present")
        else:
            L.append("        state: latest")
        if any("reboot" in h.lower() for h in s["hints"]):
            needs_reboot = True
    if needs_reboot:
        L.append("    - name: \"Reboot (kernel/libc updated) — enable with -e allow_reboot=true\"")
        L.append("      ansible.builtin.reboot:")
        L.append("        reboot_timeout: 600")
        L.append("      when: allow_reboot | bool")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        prog="remedify",
        description="Turn vulnerability scan results into OS-specific remediation commands.")
    ap.add_argument("scan", nargs="?", default=None,
                    help="Path to Trivy JSON, Sysdig scan-result JSON, or Sysdig CSV "
                         "export ('-' for stdin). Omit when using --from-sysdig.")
    ap.add_argument("--format", choices=["markdown", "shell", "json", "ansible"],
                    default="markdown")
    ap.add_argument("--min-severity", default="UNKNOWN",
                    choices=["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    ap.add_argument("--context", default="auto", choices=["auto", "host", "image"],
                    help="Remediation context. 'image' recommends rebuilding "
                         "from an updated Dockerfile (immutable infra); 'host' "
                         "patches in place. Default: auto-detect from the target.")
    ap.add_argument("--input",
                    choices=["auto", "trivy", "grype", "osv", "sysdig-csv",
                             "sysdig-json"],
                    default="auto", help="Input format (default: auto-detect)")
    ap.add_argument("--os", dest="os_override", default=None, metavar="FAMILY:VERSION",
                    help="OS override for inputs lacking OS metadata, "
                         "e.g. 'ubuntu:22.04' or 'redhat:9.3'")
    ap.add_argument("--from-sysdig", action="store_true",
                    help="Fetch scan results from the Sysdig VM API "
                         "(requires --api-url and SYSDIG_API_TOKEN env var). Beta.")
    ap.add_argument("--api-url", default=None,
                    help="Sysdig API base URL, e.g. https://app.us2.sysdig.com")
    ap.add_argument("--result-id", default=None,
                    help="Specific scan result ID (default: latest runtime result)")
    ap.add_argument("--limit", type=int, default=1, metavar="N",
                    help="With --from-sysdig: process the N most recent runtime "
                         "results in one report (default: 1)")
    ap.add_argument("--filter", dest="filter_expr", default=None,
                    help="Sysdig runtime-results filter expression")
    ap.add_argument("--insecure", action="store_true",
                    help="Skip TLS certificate verification (testing only)")
    ap.add_argument("--ca-bundle", default=None,
                    help="Path to CA bundle (e.g. corporate proxy CA)")
    ap.add_argument("--dump", default=None, metavar="FILE",
                    help="Save the raw API response JSON to FILE (debugging)")
    ap.add_argument("--fail-on", default=None,
                    choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    help="Exit with code 2 if any finding at or above this "
                         "severity exists (CI gate)")
    ap.add_argument("--baseline", default=None, metavar="BEFORE_SCAN",
                    help="Verify mode: diff this before-scan against the after-"
                         "scan given as the positional argument, and report "
                         "whether the fixes landed.")
    ap.add_argument("--check-eol", action="store_true",
                    help="Check live EOL data from endoflife.date (network; "
                         "cached ~24h). Default off — the static table is used "
                         "so remedify stays offline/zero-dependency by default.")
    ap.add_argument("--version", action="version", version=f"remedify {__version__}")
    args = ap.parse_args()

    if args.baseline:
        if not args.scan:
            sys.exit("error: verify needs two scans: "
                     "remedify --baseline before.json after.json")
        before = parse_scan_file(args.baseline, args.input, args.os_override)
        after = parse_scan_file(args.scan, args.input, args.os_override)
        v = verify(before, after)
        print(render_json(v) if args.format == "json"
              else render_verify_markdown(v))
        sys.exit(verify_exit_code(v, args.fail_on))

    if args.from_sysdig:
        import os as _os
        token = _os.environ.get("SYSDIG_API_TOKEN")
        if not args.api_url or not token:
            sys.exit("error: --from-sysdig requires --api-url and the "
                     "SYSDIG_API_TOKEN environment variable.")
        data_list = fetch_sysdig(args.api_url, token, args.result_id, args.filter_expr,
                                 insecure=args.insecure, ca_bundle=args.ca_bundle,
                                 limit=args.limit)
        if args.dump:
            with open(args.dump, "w", encoding="utf-8") as f:
                json.dump(data_list[0] if len(data_list) == 1 else data_list, f, indent=2)
            print(f"info: raw API response saved to {args.dump}", file=sys.stderr)
        parsed_list = [parse_sysdig_json(d, os_override=args.os_override)
                       for d in data_list]
    else:
        if not args.scan:
            sys.exit("error: provide a scan file (or '-' for stdin), "
                     "or use --from-sysdig.")
        parsed_list = [parse_scan_file(args.scan, args.input, args.os_override)]

    for parsed in parsed_list:
        if not parsed["family"] and (parsed["findings"] or parsed["unfixed"]):
            print(f"warning: no OS information for '{parsed['target']}'; pass --os "
                  "(e.g. --os ubuntu:22.04) to generate OS package commands.",
                  file=sys.stderr)

    eol_fn = detect_eol_live if args.check_eol else detect_eol
    plans = [build_plan(p, args.min_severity, args.context, eol_fn=eol_fn)
             for p in parsed_list]

    fleet = build_fleet_summary(plans) if len(plans) > 1 else None

    if args.format == "json":
        if len(plans) == 1:
            print(render_json(plans[0]))
        else:
            print(json.dumps({"fleet_summary": fleet, "plans": plans},
                             indent=2, ensure_ascii=False))
    elif args.format == "shell":
        parts = []
        if fleet:
            head = ["# ==== FLEET SUMMARY: top fixes across "
                    f"{fleet['workloads']} workloads ===="]
            for e in fleet["top_fixes"][:5]:
                head.append(f"#   {e['label']} [{e['severity']}] -> "
                            f"{len(e['targets'])} workloads")
            parts.append("\n".join(head))
        parts.append(render_shell(plans[0]))
        for plan in plans[1:]:
            body = render_shell(plan)
            body = "\n".join(l for l in body.splitlines()
                             if not l.startswith("#!") and l != "set -euo pipefail")
            parts.append(f"# {'=' * 60}\n{body}")
        print("\n\n".join(parts))
    elif args.format == "ansible":
        print("---\n" + "\n".join(render_ansible(plan) for plan in plans), end="")
    else:
        parts = [render_fleet_markdown(fleet)] if fleet else []
        parts.extend(render_markdown(plan) for plan in plans)
        print("\n\n---\n\n".join(parts))

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        worst = 0
        for plan in plans:
            for coll in (plan["steps"], plan["app_steps"], plan["unfixed"]):
                for item in coll:
                    worst = max(worst, SEVERITY_ORDER.get(item["severity"], 0))
        if worst >= threshold:
            sys.exit(2)


if __name__ == "__main__":
    main()
