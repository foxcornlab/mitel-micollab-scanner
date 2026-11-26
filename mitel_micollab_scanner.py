#!/usr/bin/env python3
"""Detection-only triage for Mitel MiCollab MISA-2026-0012.

Five flaws in the Audio, Web and Video Conferencing (AWV) component
of Mitel MiCollab, all unauthenticated, all in the same supported
range — MiCollab 10.3 (10.3.0.18) and earlier — and all fixed by the
same action: upgrade to 10.3 (10.3.0.18) and apply the patch in
Mitel knowledge base article KB000129195, or upgrade to a later
release. Mitel published advisory MISA-2026-0012 on 16 November
2026 and updated it to revision 2.0 on 24 November 2026 with the
CVE numbers. The CVE records were published on 19 November 2026.
CISA added all five to its Known Exploited Vulnerabilities catalog
on 25 November 2026, due 28 November 2026 (CVE-2026-133311 due
9 December 2026).

    CVE-2026-133323  blind OS command injection (CWE-78)   CVSS 10.0
    CVE-2026-133303  XML injection (CWE-91)                CVSS 9.0
    CVE-2026-133311  improper authentication (CWE-287)     CVSS 5.9
    CVE-2026-133275  arbitrary file upload (CWE-434)       CVSS 5.3
    CVE-2026-133324  authentication bypass (CWE-636)       CVSS 5.3

Scores are Mitel's, from MISA-2026-0012. NVD lists CVE-2026-133323
at 9.8 rather than 10.0, and some trackers list CVE-2026-133303 at
9.8 rather than 9.0 — both agree the two are critical, they disagree
on the decimal. This scanner follows Mitel and says so.

The exploitation is confirmed, not theoretical. Accenture APEX Labs
reports a threat actor exploiting these flaws in the wild before
Mitel's advisory existed: web-shell activity at one victim before
23:00 UTC on 15 November 2026, first command 12 minutes after the
first request, root within 30 minutes, and the MiCollab LDAP
connector's directory credentials used against a domain controller
within 32 minutes. A second victim's server held a persistent HTTPS
channel to the same actor infrastructure since 9 November 2026.
The actor fingerprinted the MiCollab version first, then bypassed
AWV authentication, uploaded files, and dropped a web shell under
the pictures directory. Patching now does not undo a break-in that
started earlier — any internet-facing MiCollab on 10.3.0.18 or
earlier was exploitable by this actor, and a suspected compromise
should be treated as a directory compromise, not an isolated
application-server incident.

Detection only. This scanner never sends a payload, never submits a
form, and never POSTs anything. What it does instead is grade the
MiCollab version against Mitel's fix, read the version your server
already discloses on its public pages, check whether the AWV
component answers at all from the outside (Mitel's own mitigation
is to restrict external access to AWV), and hunt your access logs
and local trees for the indicators Accenture published for this
campaign. An unverified public proof of concept exists that POSTs
real command-injection payloads to two admin PHP paths
(/npm/admin/cmd.php and /npm/admin/NuPoint/import_contacts.php);
this scanner deliberately does not do that. It only GETs those
paths with no parameters and reports whether they answer at all,
and the verdict never depends on them.

The trap that matters most here: 10.3.0.18 looks patched and is
not. Mitel lists 10.3 (10.3.0.18) among the affected versions. The
fix is to upgrade to that release and then apply the patch in
KB000129195, or upgrade to a later release. A version string alone
cannot tell you whether the patch is installed on a 10.3.0.18 box,
so this scanner grades 10.3.0.18 VULNERABLE and tells you to check
the patch locally. A version above 10.3.0.18 grades FIXED, because
Mitel says the security update will be included in later MiCollab
releases.

Fixed releases, per MISA-2026-0012 (primary source):

    MiCollab 10.3 (10.3.0.18) + patch KB000129195, or a later release

Earlier supported releases have no fix on their own line — upgrade
to 10.3.0.18 and apply the patch, or move to a later release.
End-of-support releases get no fix either.
"""

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "1.0.0"

CVE_MAIN = "CVE-2026-133323"
CVE_BATCH = (
    "CVE-2026-133275",
    "CVE-2026-133303",
    "CVE-2026-133311",
    "CVE-2026-133323",
    "CVE-2026-133324",
)
CVSS = "10.0"
CWE = "CWE-78"
PRODUCT = "Mitel MiCollab"
ADVISORY = "MISA-2026-0012"
ADVISORY_PUBLISHED = "2026-11-16"
ADVISORY_UPDATED = "2026-11-24"
CVE_PUBLISHED = "2026-11-19"
EXPLOITED_SINCE = "2026-11-09"
KEV_ADDED = "2026-11-25"
KEV_DUE = "2026-11-28"
KEV_DUE_AUTH = "2026-12-09"  # CVE-2026-133311 only
PATCH_KB = "KB000129195"
FIXED_VERSION = (10, 3, 0, 18)

EXIT_CLEAN = 0
EXIT_VULNERABLE = 1
EXIT_UNKNOWN = 2
EXIT_USAGE = 3

# MiCollab versions are four parts: 10.3.0.18. Three-part versions
# ("10.3.0") are tolerated and read as (10, 3, 0, 0); a suffix
# ("10.3.0.18-patch1") is reported, not graded — grading uses the
# numeric prefix, which is the honest limit of a version string.
VERSION_TOKEN = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?")

# A version token sitting next to the product name, e.g. the login
# page footer "MiCollab 10.3.0.18" or a title "MiCollab 10.2.0.9".
VERSION_NEAR_PRODUCT = re.compile(
    r"MiCollab[^0-9]{0,80}?(\d+\.\d+(?:\.\d+){0,2})", re.IGNORECASE)

# Any four-part version token anywhere on a page already identified
# as MiCollab — the fallback when the version is not next to the
# product name (for example in a script URL or a footer line).
VERSION_ANY_FOUR_PART = re.compile(r"\b(\d+\.\d+\.\d+\.\d+)\b")

# "Version: 10.3.0.18" style labels.
VERSION_LABELLED = re.compile(
    r"[Vv]ersion\s*[:=]\s*(\d+\.\d+(?:\.\d+){0,2})")

MAX_LOG_BYTES = 50 * 1024 * 1024  # per file, so a giant log cannot OOM us

# Accenture APEX Labs indicators for the MISA-2026-0012 campaign
# (primary source for the hunt): actor infrastructure, the web-shell
# path, the AWV CGI path, and the actor's egress checks.
ACTOR_IPS = ("204.76.203.204", "204.76.203.216")
ACTOR_DOMAINS = (
    "204-76-203-204.sslip.io",
    "freeware-peter-desktop-parker.trycloudflare.com",
)
ACTOR_TLS_SHA256 = (
    "df2184dda5ca97d0c8589640ac1eb9392dfab8cc990f51949099ce757f47397f")
ACTOR_JARM = "1dd40d40d00040d00042d43d000000e1ea2a807a629b496b664cf07ad7c08d"
ACTOR_JA3S = "475c9302dc42b2751db9edcac3b74891"

# What the campaign's log lines look like: requests for a shell under
# the pictures directory, POSTs to the AWV CGIs, and the actor's
# egress checks (IP-echo services, Cloudflare quick tunnels, Maven
# Central for JDBC drivers). These are hunt patterns for your own
# logs, not a signature that proves a clean box when absent.
LOG_HUNT_PATTERNS = (
    (r"/pictures/[^ ]*shell\.(asp|jsp)", "web shell under /pictures/"),
    (r"/awcuser/cgi-bin/", "request to AWV CGI path"),
    (r"204\.76\.203\.204", "actor server 204.76.203.204"),
    (r"204\.76\.203\.216", "actor server 204.76.203.216"),
    (r"204-76-203-204\.sslip\.io", "actor domain sslip.io"),
    (r"trycloudflare\.com", "Cloudflare quick tunnel"),
    (r"api\.ipify\.org", "IP-echo check (api.ipify.org)"),
    (r"ifconfig\.me", "IP-echo check (ifconfig.me)"),
    (r"repo1\.maven\.org", "Maven Central download (JDBC drivers)"),
)

# Host artifacts from the Accenture report: actor tooling staged on
# compromised hosts. File names, matched case-insensitively.
IOC_FILE_PATTERNS = (
    (re.compile(r"shell\.(asp|jsp)$", re.IGNORECASE),
     "web shell (shell.asp/shell.jsp)"),
    (re.compile(r"roast.*\.py$", re.IGNORECASE),
     "Kerberoasting script (roast*.py)"),
    (re.compile(r"mkccache\.py$", re.IGNORECASE),
     "actor tooling (mkccache.py)"),
    (re.compile(r"testcreds2?\.py$", re.IGNORECASE),
     "credential-testing script (testcreds*.py)"),
    (re.compile(r"relay(_one)?\.(exp|py)$", re.IGNORECASE),
     "relay script (relay_one.exp / relay.py)"),
    (re.compile(r"_batch_.*\.tgz$", re.IGNORECASE),
     "staged exfiltration archive (*_batch_*.tgz)"),
    (re.compile(r"t\.cgi$", re.IGNORECASE),
     "actor tooling on a database server web root (t.cgi)"),
)

# Paths the scanner GETs (plain reads, no parameters, no POST).
# /awcuser/cgi-bin/ is the AWV CGI path from the Accenture report;
# the two /npm/admin/ paths are claimed by an unverified public
# proof of concept — presence there is reported, never graded.
PROBE_PATHS = ("/", "/portal/", "/awv/")
AWV_CGI_PATH = "/awcuser/cgi-bin/"
UNVERIFIED_ADMIN_PATHS = (
    "/npm/admin/cmd.php",
    "/npm/admin/NuPoint/import_contacts.php",
)


def parse_version(raw):
    """Parse "10.3.0.18" (or "10.3.0", "10.3", "v10.3.0.18") into
    a (10, 3, 0, 18) tuple. Returns None when the string carries no
    version token at all. Missing components default to 0."""
    if raw is None:
        return None
    match = VERSION_TOKEN.search(str(raw).strip())
    if not match:
        return None
    parts = [int(match.group(i)) if match.group(i) is not None else 0
             for i in (1, 2, 3, 4)]
    return tuple(parts)


def fmt_version(version):
    """Render a version tuple the way Mitel writes it: 10.3.0.18."""
    return ".".join(str(p) for p in version)


def grade(version):
    """Grade a parsed MiCollab version tuple against MISA-2026-0012.

    Returns (verdict, detail) with verdict VULNERABLE, FIXED or
    UNKNOWN. The fix is 10.3 (10.3.0.18) plus the patch in
    KB000129195, or a later release — so 10.3.0.18 itself grades
    VULNERABLE, because a version string cannot show whether the
    patch is installed. Anything above 10.3.0.18 grades FIXED,
    because Mitel says the security update will be included in
    later releases. Anything below it is vulnerable with no fix on
    its own line. A major version above 10 has no advisory coverage
    and grades UNKNOWN rather than being guessed at.
    """
    if version is None:
        return "UNKNOWN", "no parseable version"
    major = version[0]

    if major > 10:
        return "UNKNOWN", (
            "%s is above every release MISA-2026-0012 covers — no "
            "advisory coverage for MiCollab %d, check the advisory "
            "before trusting this grade" % (fmt_version(version), major))

    if version == FIXED_VERSION:
        return "VULNERABLE", (
            "%s is the release the patch is built for, and the base "
            "release alone is NOT patched — apply the patch in "
            "%s, or upgrade to a later release. A version string "
            "cannot show whether the patch is installed, so check "
            "it on the box. (Exploited in the wild since %s; CISA "
            "KEV due %s)"
            % (fmt_version(version), PATCH_KB, EXPLOITED_SINCE, KEV_DUE))

    if version > FIXED_VERSION:
        return "FIXED", (
            "%s is above %s — Mitel says the security update in "
            "%s is included in later MiCollab releases"
            % (fmt_version(version), fmt_version(FIXED_VERSION), PATCH_KB))

    if version[0] == 10 and version[1] < 3:
        return "VULNERABLE", (
            "%s is below the fixed release — upgrade to 10.3 "
            "(10.3.0.18) and apply the patch in %s, or upgrade to "
            "a later release. There is no fix on the 10.%d line. "
            "(Exploited in the wild since %s; CISA KEV due %s)"
            % (fmt_version(version), PATCH_KB, version[1],
               EXPLOITED_SINCE, KEV_DUE))

    return "VULNERABLE", (
        "%s is below the fixed release — upgrade to 10.3 "
        "(10.3.0.18) and apply the patch in %s, or upgrade to a "
        "later release. (Exploited in the wild since %s; CISA KEV "
        "due %s)"
        % (fmt_version(version), PATCH_KB, EXPLOITED_SINCE, KEV_DUE))


def version_from_body(body):
    """Pull a MiCollab version out of a page body.

    Prefers a version token sitting next to the product name
    ("MiCollab 10.3.0.18"), then a labelled "Version: x.y.z.w",
    then any four-part version token on the page. Returns None
    when nothing parseable is there.
    """
    if not body:
        return None
    match = VERSION_NEAR_PRODUCT.search(body)
    if match:
        found = parse_version(match.group(1))
        if found is not None:
            return found
    match = VERSION_LABELLED.search(body)
    if match:
        found = parse_version(match.group(1))
        if found is not None:
            return found
    match = VERSION_ANY_FOUR_PART.search(body)
    if match:
        return parse_version(match.group(1))
    return None


def is_micollab_page(body, headers):
    """Decide whether a fetched page is a MiCollab server.

    "MiCollab" in the body is the primary marker; "Mitel" together
    with "AWV" (or "Audio, Web and Video") is the secondary one, for
    pages that brand the component rather than the product.
    """
    lowered = (body or "").lower()
    if "micollab" in lowered:
        return True
    if "mitel" in lowered and ("awv" in lowered
                               or "audio, web and video" in lowered):
        return True
    server = (headers or {}).get("Server", "") or ""
    if "micollab" in server.lower():
        return True
    return False


def _unverified_context():
    """MiCollab servers in labs often run self-signed certificates;
    the probes only read public pages, so verification is skipped
    the way a browser in a lab does it. Never send credentials over
    this channel — this tool never sends any."""
    return ssl._create_unverified_context()


def fetch(url, timeout=10):
    """Plain GET. Returns (status, headers dict, body, error).

    Status None means the connection itself failed; the error string
    says why. HTTPS uses an unverified context (see above).
    Redirects are followed (MiCollab's root usually redirects to
    the portal), and the final URL is reported in the notes by the
    caller when it matters.
    """
    headers = {
        "User-Agent": "mitel-micollab-scanner/1.0 (detection-only triage)"
    }
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_unverified_context()))
    try:
        with opener.open(request, timeout=timeout) as resp:
            return (resp.status, dict(resp.headers),
                    resp.read().decode("utf-8", errors="replace"), None)
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, dict(exc.headers), body, None
    except Exception as exc:  # connection refused, DNS, timeout, TLS
        return None, {}, "", str(exc)


def classify_awv_response(status):
    """Classify one plain GET of the AWV CGI path.

    Returns (state, note). A 200/401/403 means the AWV component
    answers from the outside — the thing Mitel's mitigation says to
    restrict. A 404 means the path is not there. Anything else is
    reported as it stands; exposure alone is not a vulnerability
    verdict, the version verdict still rules.
    """
    if status is None:
        return "UNKNOWN", "could not reach the AWV CGI path"
    if status == 200:
        return "EXPOSED", (
            "%s answers HTTP 200 — the AWV component is reachable "
            "from the outside. Mitel's mitigation is to restrict "
            "external access to AWV until the fix is applied"
            % AWV_CGI_PATH)
    if status in (401, 403):
        return "EXPOSED", (
            "%s answers HTTP %d — the AWV component is there and "
            "answers from the outside (behind auth). Mitel's "
            "mitigation is to restrict external access to AWV "
            "until the fix is applied" % (AWV_CGI_PATH, status))
    if status == 404:
        return "ABSENT", (
            "%s returns HTTP 404 — the AWV CGI path is not there "
            "(or this is not a MiCollab server)" % AWV_CGI_PATH)
    if status in (301, 302, 303, 307, 308):
        return "REDIRECT", (
            "%s redirects (HTTP %d) — the AWV path is not served "
            "directly here; grade the version, not the redirect"
            % (AWV_CGI_PATH, status))
    return "UNKNOWN", (
        "%s returned HTTP %d — not a recognisable AWV answer"
        % (AWV_CGI_PATH, status))


def probe_url(base_url):
    """Grade a live MiCollab server from public reads only.

    GETs /, /portal/ and /awv/ looking for MiCollab markers and a
    version string, then GETs /awcuser/cgi-bin/ to see whether AWV
    answers from the outside, then GETs the two admin PHP paths an
    unverified public proof of concept names (no parameters, no
    POST) and reports only whether they answer. Returns (verdict,
    detail, notes list).

    The version verdict rules. AWV exposure and admin-path presence
    can only add certainty in one direction: an exposed AWV on a
    vulnerable (or unknown) version is the exploitable condition
    itself. A version above the fix still grades FIXED even if AWV
    answers, because the fix closes the flaws, not the component.
    """
    notes = []
    base = base_url.rstrip("/")
    version = None
    version_source = None
    identified = False

    for path in PROBE_PATHS:
        status, headers, body, error = fetch("%s%s" % (base, path))
        if status is None:
            notes.append("could not fetch %s: %s" % (path, error))
            continue
        if is_micollab_page(body, headers):
            identified = True
        if status == 200 and version is None:
            found = version_from_body(body)
            if found is not None:
                version = found
                version_source = path
        elif status == 404:
            notes.append("%s is absent (404)" % path)
        elif status not in (200,):
            notes.append("%s returned HTTP %d" % (path, status))

    if not identified:
        notes.append("no page answered as MiCollab — check the URL; "
                     "this may not be a MiCollab server at all")

    awv_status, _h, _b, awv_error = fetch("%s%s" % (base, AWV_CGI_PATH))
    if awv_status is None:
        awv_state, awv_note = "UNKNOWN", (
            "could not reach %s: %s" % (AWV_CGI_PATH, awv_error))
    else:
        awv_state, awv_note = classify_awv_response(awv_status)
    notes.append("AWV probe: %s" % awv_note)

    for path in UNVERIFIED_ADMIN_PATHS:
        status, _h, _b, error = fetch("%s%s" % (base, path))
        if status is None:
            notes.append("%s: could not reach it (%s) — no conclusion"
                         % (path, error))
        elif status == 404:
            notes.append("%s: HTTP 404 (path absent)" % path)
        else:
            notes.append(
                "%s: answers HTTP %d — the path an unverified public "
                "proof of concept names is present. Presence alone is "
                "not a verdict: the path is named by one unreviewed "
                "PoC, not by Mitel or Accenture, and this scanner "
                "sends it nothing" % (path, status))

    if version is not None:
        verdict, detail = grade(version)
        notes.append("version %s read from %s"
                     % (fmt_version(version), version_source))
        if awv_state == "EXPOSED" and verdict == "VULNERABLE":
            detail += (
                "; and the AWV component answers from the outside — "
                "that is the exposed component the flaws sit in. "
                "Restrict external access to AWV now, then patch")
        elif awv_state == "EXPOSED" and verdict == "FIXED":
            notes.append(
                "AWV still answers from the outside, which is "
                "expected — the fix closes the flaws, it does not "
                "remove the component. Restricting external access "
                "to AWV is still good hygiene")
        return verdict, detail, notes

    if identified:
        if awv_state == "EXPOSED":
            return "VULNERABLE", (
                "this is a MiCollab server and its AWV component "
                "answers from the outside, but no version could be "
                "read — treat it as vulnerable until the version is "
                "graded locally with --version (10.3.0.18 and "
                "earlier are all affected; 10.3.0.18 itself still "
                "needs the %s patch)" % PATCH_KB), notes
        return "UNKNOWN", (
            "this looks like a MiCollab server but discloses no "
            "version on its public pages — grade the version "
            "locally with --version (10.3.0.18 and earlier are all "
            "affected; 10.3.0.18 itself still needs the %s patch)"
            % PATCH_KB), notes

    return "UNKNOWN", (
        "no MiCollab server identified at %s and no version could "
        "be read — check the URL, or grade the version locally "
        "with --version" % base), notes


def scan_access_log(path):
    """Grep access logs for the Accenture campaign's indicators.

    Accepts one log file or a directory of .log files. Flags every
    line matching the hunt patterns (actor IPs and domains, the
    web-shell path under /pictures/, AWV CGI requests, the actor's
    IP-echo and tunnel checks, Maven Central downloads) and marks
    POSTs to /awcuser/cgi-bin/ as exploitation probes: a POST to an
    AWV CGI from an unfamiliar source is never normal traffic.
    Returns (hits, notes). A hit is a lead worth investigating, not
    proof of a breach — and no hits is not a clean bill, because
    the actor filtered its requests out of local logs at the
    confirmed victim and logs rotate. Hunt in upstream proxy and
    WAF logs too. The campaign began 9 November 2026: check the
    timestamps on any hits against that date; this tool does not
    parse log timestamps.
    """
    hits = []
    notes = []
    target = Path(path)
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = sorted(target.glob("*.log"))
        if not files:
            return hits, ["no .log files under %s" % path]
    else:
        return hits, ["access log path %s does not exist" % path]
    compiled = [(re.compile(p, re.IGNORECASE), label)
                for p, label in LOG_HUNT_PATTERNS]
    for logfile in files:
        try:
            size = logfile.stat().st_size
        except OSError:
            continue
        with logfile.open(errors="replace") as handle:
            if size > MAX_LOG_BYTES:
                handle.seek(size - MAX_LOG_BYTES)
                handle.readline()  # drop the partial first line
            for lineno, line in enumerate(handle, start=1):
                lowered = line.lower()
                labels = [label for pattern, label in compiled
                          if pattern.search(line)]
                if not labels:
                    continue
                is_post = ('"post ' in lowered
                           and "/awcuser/cgi-bin/" in lowered)
                hits.append((str(logfile), lineno, line.rstrip("\n"),
                             is_post, labels))
                if len(hits) >= 50:
                    notes.append("hit cap reached (50), refine the search")
                    return hits, notes
    return hits, notes


def scan_ioc_dir(path):
    """Hunt a MiCollab tree for the campaign's host artifacts.

    Walks the tree (a web root, /tmp, wherever the server lives)
    for the file names Accenture published: shell.asp/shell.jsp
    under a pictures directory, roast*.py, mkccache.py,
    testcreds*.py, relay scripts, *_batch_*.tgz archives, and
    t.cgi. Returns (hits, notes). A hit is a post-exploit sign —
    treat it as a compromise until proven otherwise — and no hits
    is not a clean bill, because the actor cleaned up after
    itself.
    """
    target = Path(path)
    if not target.exists():
        return [], ["IOC path %s does not exist" % path]
    hits = []
    for found in sorted(target.rglob("*")):
        if not found.is_file():
            continue
        name = found.name
        parts = [p.lower() for p in found.parts]
        for pattern, label in IOC_FILE_PATTERNS:
            if not pattern.search(name):
                continue
            if label.startswith("web shell") and "pictures" not in parts:
                # A shell.asp outside a pictures directory is still
                # worth flagging, but the campaign planted it under
                # /pictures/ — say where it was found.
                hits.append((str(found), "%s (not under a pictures "
                             "directory)" % label))
            else:
                hits.append((str(found), label))
            break
        if len(hits) >= 50:
            return hits, ["hit cap reached (50), refine the search"]
    return hits, []


def grade_one(entry):
    """Grade one inventory entry.

    Entry keys: "version" (string), "url" (server base URL).
    Optional: "access_log" path, "ioc_dir" path. Returns a result
    dict.
    """
    result = {"host": entry.get("host", entry.get("url",
                                                 entry.get("version", "?")))}
    version = None
    notes = []
    if "version" in entry:
        version = parse_version(entry["version"])
        if version is None:
            notes.append("version %r is not parseable" % entry["version"])
        verdict, detail = grade(version)
        result["verdict"] = verdict
        result["detail"] = detail
    elif "url" in entry:
        verdict, detail, url_notes = probe_url(entry["url"])
        result["verdict"] = verdict
        result["detail"] = detail
        notes.extend(url_notes)
    else:
        return dict(result, verdict="UNKNOWN",
                    detail="entry has no version or url",
                    notes=notes)
    if version is not None:
        result["version"] = fmt_version(version)
    result["notes"] = notes
    log_path = entry.get("access_log")
    if log_path:
        hits, log_notes = scan_access_log(log_path)
        notes.extend(log_notes)
        result["access_log_hits"] = [
            {"file": f, "line": n, "text": t, "post": p, "labels": labels}
            for f, n, t, p, labels in hits
        ]
        posts = [h for h in hits if h[3]]
        if hits:
            result["detail"] += (
                "; %d access-log line(s) match the campaign indicators "
                "(%d POST%s to AWV CGIs) — investigate, and check "
                "timestamps against the campaign window (from 9 Nov "
                "2026; web-shell activity before 23:00 UTC 15 Nov "
                "2026 at the confirmed victim)"
                % (len(hits), len(posts),
                   "s" if len(posts) != 1 else ""))
    ioc_path = entry.get("ioc_dir")
    if ioc_path:
        hits, ioc_notes = scan_ioc_dir(ioc_path)
        notes.extend(ioc_notes)
        result["ioc_hits"] = [
            {"file": f, "label": label} for f, label in hits
        ]
        if hits:
            result["detail"] += (
                "; %d host artifact(s) from the campaign (%s) — "
                "treat the box as compromised until proven otherwise"
                % (len(hits), ", ".join(h[1] for h in hits[:3])))
    return result


def worst_verdict(results):
    """The fleet verdict is the worst of its members."""
    order = {"VULNERABLE": 0, "UNKNOWN": 1, "FIXED": 2}
    return min(results, key=lambda r: order.get(r["verdict"], 1))["verdict"]


def print_result(result, as_json=False):
    """One result, human or machine readable."""
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print("[%s] %s" % (result["verdict"], result["host"]))
    if "version" in result:
        print("  version: %s" % result["version"])
    print("  %s" % result["detail"])
    for note in result.get("notes", []):
        print("  note: %s" % note)
    for hit in result.get("access_log_hits", []):
        print("  log hit %s:%s%s [%s]: %s" % (
            hit["file"], hit["line"],
            " [POST to AWV CGI — exploitation probe]"
            if hit["post"] else "",
            "; ".join(hit["labels"]), hit["text"]))
    for hit in result.get("ioc_hits", []):
        print("  ioc %s (%s — SUSPICIOUS)" % (hit["file"], hit["label"]))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for Mitel MiCollab %s "
                    "(%s, CVSS %s). Grades the MiCollab version "
                    "against the %s fix. Never sends payloads, never "
                    "POSTs." % (CVE_MAIN, ADVISORY, CVSS, PATCH_KB))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--version", metavar="VERSION",
                       help="grade a version string, e.g. 10.3.0.18")
    group.add_argument("--version-file", metavar="FILE",
                       help="read the version from a file (first line)")
    group.add_argument("--url", metavar="URL",
                       help="grade a live MiCollab server from public "
                            "reads: /, /portal/, /awv/, one GET of "
                            "%s, and presence checks on the two admin "
                            "PHP paths an unverified PoC names"
                            % AWV_CGI_PATH)
    group.add_argument("--inventory-json", metavar="FILE",
                       help="grade a fleet from a JSON list of entries")
    group.add_argument("--list", action="store_true",
                       help="print the fixed-version table and exit")
    parser.add_argument("--access-log", metavar="PATH",
                        help="grep an access log (file or dir of .log) "
                             "for the campaign indicators")
    parser.add_argument("--ioc-dir", metavar="PATH",
                        help="hunt a MiCollab tree for the campaign's "
                             "host artifacts (shell.asp, roast*.py, "
                             "*_batch_*.tgz, ...)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    args = parser.parse_args(argv)

    if args.list:
        print("%s — %s (%s) — CVSS %s" % (PRODUCT, CVE_MAIN, ADVISORY, CVSS))
        print("affected: MiCollab 10.3 (10.3.0.18) and earlier, supported "
              "releases; older lines have no fix on the line")
        print("fixed:    10.3 (10.3.0.18) + patch %s, or a later release "
              "(advisory %s, first issued %s, rev 2.0 %s; CVE published "
              "%s; exploited since %s; CISA KEV added %s, due %s)"
              % (PATCH_KB, ADVISORY, ADVISORY_PUBLISHED, ADVISORY_UPDATED,
                 CVE_PUBLISHED, EXPLOITED_SINCE, KEV_ADDED, KEV_DUE))
        print("also:     CVE-2026-133303 (XML injection, 9.0), "
              "CVE-2026-133311 (improper authentication, 5.9, KEV due "
              "%s), CVE-2026-133275 (arbitrary file upload, 5.3), "
              "CVE-2026-133324 (authentication bypass, 5.3) — same "
              "range, same fix" % KEV_DUE_AUTH)
        print("needs:    the AWV component reachable from the outside; "
              "all five flaws are unauthenticated")
        print("trap:     10.3.0.18 alone is NOT patched — the patch in "
              "%s is a separate step, and a version string cannot "
              "show whether it is installed" % PATCH_KB)
        return EXIT_CLEAN

    if args.inventory_json:
        try:
            entries = json.loads(Path(args.inventory_json).read_text())
        except (OSError, ValueError) as exc:
            print("cannot read inventory: %s" % exc, file=sys.stderr)
            return EXIT_USAGE
        if not isinstance(entries, list) or not entries:
            print("inventory must be a non-empty JSON list", file=sys.stderr)
            return EXIT_USAGE
        results = [grade_one(entry) for entry in entries]
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            for result in results:
                print_result(result)
        verdict = worst_verdict(results)
        return {"VULNERABLE": EXIT_VULNERABLE, "UNKNOWN": EXIT_UNKNOWN}.get(
            verdict, EXIT_CLEAN)

    entry = {}
    if args.version is not None:
        entry["version"] = args.version
    elif args.version_file is not None:
        try:
            entry["version"] = Path(args.version_file).read_text().splitlines()[0]
        except (OSError, IndexError) as exc:
            print("cannot read version file: %s" % exc, file=sys.stderr)
            return EXIT_USAGE
    elif args.url is not None:
        entry["url"] = args.url
    entry["host"] = entry.get("url") or entry.get("version") or "?"
    if args.access_log:
        entry["access_log"] = args.access_log
    if args.ioc_dir:
        entry["ioc_dir"] = args.ioc_dir

    result = grade_one(entry)
    print_result(result, as_json=args.json)
    return {"VULNERABLE": EXIT_VULNERABLE, "UNKNOWN": EXIT_UNKNOWN}.get(
        result["verdict"], EXIT_CLEAN)


if __name__ == "__main__":
    sys.exit(main())
