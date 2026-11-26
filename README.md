# `mitel-micollab-scanner`

Detection-only triage for `MISA-2026-0012`, the five flaws in the `Audio, Web and Video Conferencing (AWV)` component of `Mitel MiCollab` that let an unauthenticated attacker run commands on the box. `Mitel` published the advisory on `16 Nov 2026` and updated it to revision `2.0` on `24 Nov 2026` with the `CVE` numbers. `CISA` added all five to its `Known Exploited Vulnerabilities` catalog on `25 Nov 2026`, due `28 Nov 2026` (`CVE-2026-133311` due `9 Dec 2026`). Grades your `MiCollab` version against the fix, reads the version your server already discloses on its public pages, checks whether `AWV` answers from the outside at all, and hunts your logs and local trees for the indicators of the campaign that exploited these flaws before the advisory existed. Nothing here sends a payload, submits a form, or `POST`s anything.

## `What it checks`

* `CVE-2026-133323` — blind OS command injection (`CWE-78`) in the `AWV` component, from insufficient parameter sanitization. `CVSS 3.1 10.0` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H`) per `Mitel` (`MTLVULN-1864`). `NVD` lists it at `9.8` rather than `10.0` — both agree it is critical, they disagree on the decimal, and this scanner follows `Mitel`.
* `CVE-2026-133303` — `XML` injection (`CWE-91`) in `AWV`, `CVSS 9.0` per `Mitel` (`MTLVULN-1862`). Some trackers list it at `9.8`; same disagreement, same answer.
* `CVE-2026-133311` — improper authentication (`CWE-287`), `CVSS 5.9` (`MTLVULN-1863`). Needs knowledge of a system-generated random identifier or pre-staged content, and only reaches the affected functionality.
* `CVE-2026-133275` — arbitrary file upload (`CWE-434`), `CVSS 5.3` (`MTLVULN-1861`).
* `CVE-2026-133324` — authentication bypass (`CWE-636`), `CVSS 5.3` (`MTLVULN-1877`).

Fixed versions, per the vendor advisory `MISA-2026-0012` (primary source):

| `Product` | `Fix` |
| --- | --- |
| `MiCollab 10.3 (10.3.0.18)` and earlier | Upgrade to `10.3 (10.3.0.18)` and apply the patch in `KB000129195`, or upgrade to a later release |

Earlier supported releases have no fix on their own line — upgrade to `10.3.0.18` and apply the patch, or move to a later release. End-of-support releases get no fix either.

This was exploited before disclosure, not after it. `Accenture APEX Labs` reports a threat actor exploiting these flaws in the wild before `Mitel's` advisory existed: web-shell activity at one victim before `23:00 UTC on 15 Nov 2026`, first command `12` minutes after the first request, root within `30` minutes, and the `MiCollab LDAP` connector's directory credentials used against a domain controller within `32` minutes. A second victim's server held a persistent `HTTPS` channel to the same actor infrastructure since `9 Nov 2026`. The actor fingerprinted the `MiCollab` version first, then bypassed `AWV` authentication, uploaded files, and dropped a web shell under the pictures directory. Patching now does not undo a break-in that started earlier — any internet-facing `MiCollab` on `10.3.0.18` or earlier was exploitable by this actor, and a suspected compromise should be treated as a directory compromise, not an isolated application-server incident.

If you cannot patch yet, restrict external access to the `AWV` component — that is `Mitel's` own mitigation, and it covers any path a `MiVoice Border Gateway` web proxy publishes, because a proxy in front of `MiCollab` did not stop the exploitation at the confirmed victim.

## `Usage`

```bash
# grade a version string
python3 mitel_micollab_scanner.py --version "10.2.0.9"
python3 mitel_micollab_scanner.py --version "10.3.0.18"
python3 mitel_micollab_scanner.py --version "10.4.0.0"

# a live server: public reads only — /, /portal/, /awv/, one GET of /awcuser/cgi-bin/
python3 mitel_micollab_scanner.py --url https://micollab.example.com

# hunt the access logs for the campaign indicators (actor IPs, /pictures/ shells, AWV CGI POSTs)
python3 mitel_micollab_scanner.py --version "10.2.0.9" --access-log /var/log/apache2/access.log

# hunt a MiCollab tree for the campaign's host artifacts (shell.asp, roast*.py, *_batch_*.tgz)
python3 mitel_micollab_scanner.py --version "10.2.0.9" --ioc-dir /var/mitel

# a whole fleet at once
python3 mitel_micollab_scanner.py --inventory-json fleet.json

# machine output / the fixed-version table
python3 mitel_micollab_scanner.py --version "10.2.0.9" --json
python3 mitel_micollab_scanner.py --list
```

`--url` `GET`s `/`, `/portal/` and `/awv/` looking for `MiCollab` markers and a version string, `GET`s `/awcuser/cgi-bin/` to see whether `AWV` answers from the outside, and `GET`s the two admin `PHP` paths an unverified public proof of concept names (`/npm/admin/cmd.php`, `/npm/admin/NuPoint/import_contacts.php`) with no parameters, reporting only whether they answer. `--access-log` greps for the actor `IPs` (`204.76.203.204`, `204.76.203.216`), the actor domains, `/pictures/` shell requests, `AWV CGI` requests (marking `POST`s), and the actor's egress checks (`api.ipify.org`, `ifconfig.me`, `trycloudflare.com`, `repo1.maven.org`). `--ioc-dir` walks a tree for `shell.asp` / `shell.jsp`, `roast*.py`, `mkccache.py`, `testcreds*.py`, relay scripts, `*_batch_*.tgz` archives, and `t.cgi`.

Exit codes: `0` patched / no hits, `1` vulnerable or hits found, `2` unknown, `3` usage error.

## `Traps`

* The patch-is-not-the-release trap. `10.3.0.18` looks patched and is not. `Mitel` lists `10.3 (10.3.0.18)` among the affected versions. The fix is to upgrade to that release and then apply the patch in `KB000129195`, or upgrade to a later release. A version string alone cannot tell you whether the patch is installed on a `10.3.0.18` box, so this scanner grades `10.3.0.18` `VULNERABLE` and tells you to check the patch on the box. Do not let a `10.3.0.18` reading reassure you.
* The patch-is-not-enough trap. Patching closes the hole, it does not undo a break-in. The actor was exploiting these flaws from at least `9 Nov 2026`, a week before the advisory, and it filtered its own requests out of the local web server, error and admin logs at the confirmed victim — so a clean local log proves nothing on its own. Hunt in upstream proxy and `WAF` logs, image the box before patching or rebuilding, and treat a suspected compromise as a directory compromise: reset the `LDAP` connector account and any Kerberoastable service accounts, and rotate administrator, `SIP` trunk and file-share credentials reachable from the server. `--access-log` checks the campaign indicators for you, `--ioc-dir` checks the host artifacts, and no hits in the places checked is not a clean bill.
* The version-hiding trap. `MiCollab` does not always print its version on a public page. Then `--url` reports `UNKNOWN` (or `VULNERABLE` if `AWV` answers and no version could be read) and you grade the version locally with `--version` instead. An unknown version is not a safe version — every supported release up to `10.3.0.18` is affected.
* The proxy-does-not-protect trap. At the confirmed victim the exploitation requests passed through an internet-facing reverse proxy, and `Mitel's` mitigation explicitly covers any path a `MiVoice Border Gateway` web proxy publishes. Do not assume a proxy in front of `MiCollab` protects `AWV`.
* The `CVSS` decimal trap. `Mitel` rates `CVE-2026-133323` at `10.0`; `NVD` lists `9.8`. Some trackers rate `CVE-2026-133303` at `9.8` against `Mitel's 9.0`. Neither disagreement changes any verdict — both flaws are critical, unauthenticated, and actively exploited, and the fix is the same either way.

## `Sources`

* `Mitel` Product Security Advisory `MISA-2026-0012` (`16 Nov 2026`, rev `2.0` `24 Nov 2026`, primary source for the affected range `10.3 (10.3.0.18)` and earlier, the fix — `10.3.0.18` plus the patch in `KB000129195`, or a later release — the `CVSS` scores, and the `AWV` mitigation)
* `CISA KEV` catalog (`25 Nov 2026`, added all five `CVE`s, due `28 Nov 2026` except `CVE-2026-133311` due `9 Dec 2026`; corroborated by the `25 Nov` `KEV` trackers)
* `Accenture APEX Labs`, "When patch day comes too late: MiCollab flaws exploited before disclosure" (primary source for the pre-disclosure exploitation, the intrusion timeline, and the full indicator list: actor `IPs` `204.76.203.204` / `204.76.203.216`, the `sslip.io` and `trycloudflare.com` domains, the `TLS` fingerprints, the `/pictures/*/shell.asp` web shell, the `/awcuser/cgi-bin/` exploitation pattern, and the `/tmp` tooling names)
* `CVE-2026-133323` record, published `19 Nov 2026` (primary source for the flaw description and the `MTLVULN-1864` mapping; `NVD` lists `9.8` against `Mitel's 10.0`)
* `Tenable` `CVE-2026-133323` page (corroborates the `10.0` vector and the `MISA-2026-0012` reference)

Where sources disagree, this scanner follows the vendor advisory and the `CVE` record and says so. The live disagreements are the `CVSS` decimals (`10.0` per `Mitel` vs `9.8` per `NVD` for `CVE-2026-133323`; `9.0` per `Mitel` vs `9.8` on some trackers for `CVE-2026-133303`) — neither changes any verdict.

## `Related work`

An unverified public proof of concept exists that `POST`s real command-injection payloads to `/npm/admin/cmd.php` and `/npm/admin/NuPoint/import_contacts.php` and checks whether a marker echoes back. The paths it names are not confirmed by `Mitel` or `Accenture`, and the payloads it sends are exploit traffic. This scanner deliberately does not do that: it only `GET`s those paths with no parameters and reports whether they answer, and the verdict never depends on them. No `nuclei` template for `CVE-2026-133323` was indexed as of `25 Nov 2026`, and no dedicated version scanner was found. This tool is the defensive counterpart that covers what a single probe does not: version grading against the vendor fix with the `10.3.0.18` patch trap stated plainly, exposure fingerprinting of a live server from public reads, and the access-log and host-artifact hunts from the published campaign — all without sending exploit traffic. No `foxcornlab` scanner covered `MiCollab` before this one.

## `Thanks to`

* `Mitel` — for the advisory that names all five flaws plainly, the same-day patch on the supported release, and the `AWV` mitigation for customers who cannot patch at once
* `Accenture APEX Labs` — for publishing the pre-disclosure exploitation, the full indicator list, and the plain warning that patching alone does not evict an attacker who was already in
* `CISA` — for the `25 Nov 2026` `KEV` listing that put a three-day clock on the fix

Educational and defensive use only. This tool detects exposure, it does not exploit anything. If you run `MiCollab`, upgrade to `10.3 (10.3.0.18)` and apply the patch in `KB000129195`, or upgrade to a later release — then hunt, because the actor was in before the patch existed.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
