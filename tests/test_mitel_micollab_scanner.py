#!/usr/bin/env python3
"""Tests for mitel_micollab_scanner.py.

Covers version parsing and grading, the live-server probe against
local mock servers (vulnerable, patched-but-unpatched, fixed,
unknown-version, and not-MiCollab), and the access-log and host
artifact hunts. Nothing here touches the network outside localhost.
"""

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mitel_micollab_scanner as mms


def make_server(routes):
    """A tiny HTTP server answering from a {path: (status, body)}
    map; anything else is a 404. Returns (server, thread, port)."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, body = routes.get(self.path, (404, "not found"))
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, server.server_address[1]


class GradeTests(unittest.TestCase):
    def test_below_fix_is_vulnerable(self):
        for raw in ("10.2.0.9", "10.0.0.1", "9.8.1.201", "9.1.0.0"):
            verdict, detail = mms.grade(mms.parse_version(raw))
            self.assertEqual(verdict, "VULNERABLE", raw)
            self.assertIn("10.3.0.18", detail)

    def test_fix_release_itself_is_vulnerable(self):
        # The trap: 10.3.0.18 alone is NOT patched, the KB000129195
        # patch is a separate step a version string cannot show.
        verdict, detail = mms.grade(mms.parse_version("10.3.0.18"))
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn("KB000129195", detail)
        self.assertIn("NOT patched", detail)

    def test_above_fix_is_fixed(self):
        for raw in ("10.3.0.19", "10.3.1.0", "10.4.0.0"):
            verdict, detail = mms.grade(mms.parse_version(raw))
            self.assertEqual(verdict, "FIXED", raw)

    def test_major_above_ten_is_unknown(self):
        verdict, detail = mms.grade(mms.parse_version("11.0.0.0"))
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("no advisory coverage", detail)

    def test_unparseable_is_unknown(self):
        verdict, _ = mms.grade(mms.parse_version("not a version"))
        self.assertEqual(verdict, "UNKNOWN")

    def test_parse_tolerates_prefixes_and_suffixes(self):
        self.assertEqual(mms.parse_version("v10.3.0.18"), (10, 3, 0, 18))
        self.assertEqual(mms.parse_version("10.3.0"), (10, 3, 0, 0))
        self.assertEqual(mms.parse_version("10.3"), (10, 3, 0, 0))
        self.assertEqual(mms.parse_version("MiCollab 10.3.0.18"),
                         (10, 3, 0, 18))
        self.assertIsNone(mms.parse_version(""))

    def test_fmt_version(self):
        self.assertEqual(mms.fmt_version((10, 3, 0, 18)), "10.3.0.18")


class VersionFromBodyTests(unittest.TestCase):
    def test_version_next_to_product_name(self):
        body = ("<html><head><title>MiCollab</title></head><body>"
                "<div class='footer'>MiCollab 10.2.0.9</div></body></html>")
        self.assertEqual(mms.version_from_body(body), (10, 2, 0, 9))

    def test_labelled_version(self):
        self.assertEqual(
            mms.version_from_body("Version: 10.3.0.18"), (10, 3, 0, 18))

    def test_bare_four_part_token(self):
        self.assertEqual(
            mms.version_from_body("build 10.3.0.18 ready"), (10, 3, 0, 18))

    def test_no_version(self):
        self.assertIsNone(mms.version_from_body("nothing here at all"))

    def test_is_micollab_page(self):
        self.assertTrue(mms.is_micollab_page(
            "<title>MiCollab Login</title>", {}))
        self.assertTrue(mms.is_micollab_page(
            "Mitel Audio, Web and Video Conferencing", {}))
        self.assertFalse(mms.is_micollab_page("Apache default page", {}))


class ProbeTests(unittest.TestCase):
    def run_probe(self, routes):
        server, thread, port = make_server(routes)
        try:
            return mms.probe_url("http://127.0.0.1:%d" % port)
        finally:
            server.shutdown()
            server.server_close()

    def test_vulnerable_server(self):
        routes = {
            "/": (200, "<html><head><title>MiCollab</title></head><body>"
                       "MiCollab 10.2.0.9</body></html>"),
            "/awcuser/cgi-bin/": (403, "Forbidden"),
        }
        verdict, detail, notes = self.run_probe(routes)
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn("10.2.0.9", detail)
        self.assertTrue(any("10.2.0.9" in n for n in notes))

    def test_fix_release_grades_vulnerable_with_patch_warning(self):
        routes = {
            "/": (200, "<html><title>MiCollab</title>MiCollab 10.3.0.18"
                       "</html>"),
            "/awcuser/cgi-bin/": (200, "AWV"),
        }
        verdict, detail, _ = self.run_probe(routes)
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn("KB000129195", detail)

    def test_fixed_server(self):
        routes = {
            "/": (200, "<html><title>MiCollab</title>MiCollab 10.4.0.0"
                       "</html>"),
            "/awcuser/cgi-bin/": (200, "AWV"),
        }
        verdict, detail, _ = self.run_probe(routes)
        self.assertEqual(verdict, "FIXED")

    def test_micollab_without_version_is_unknown(self):
        routes = {
            "/": (200, "<html><title>MiCollab</title>welcome</html>"),
            "/portal/": (200, "<html><title>MiCollab</title></html>"),
            "/awv/": (404, "not found"),
            "/awcuser/cgi-bin/": (404, "not found"),
        }
        verdict, detail, _ = self.run_probe(routes)
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("no version", detail.lower())

    def test_micollab_without_version_but_awv_exposed(self):
        routes = {
            "/": (200, "<html><title>MiCollab</title>welcome</html>"),
            "/awcuser/cgi-bin/": (200, "AWV"),
        }
        verdict, detail, _ = self.run_probe(routes)
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn("AWV", detail)

    def test_not_micollab_is_unknown(self):
        routes = {
            "/": (200, "<html><title>Apache2 Default</title></html>"),
        }
        verdict, detail, _ = self.run_probe(routes)
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("no MiCollab server identified", detail)

    def test_unreachable_host_is_unknown(self):
        verdict, detail, _ = mms.probe_url("http://127.0.0.1:1")
        self.assertEqual(verdict, "UNKNOWN")

    def test_version_from_portal_when_root_has_none(self):
        routes = {
            "/": (200, "<html><title>MiCollab</title>welcome</html>"),
            "/portal/": (200, "<html><title>MiCollab</title>"
                          "MiCollab 10.3.0.18</html>"),
            "/awcuser/cgi-bin/": (404, "not found"),
        }
        verdict, detail, notes = self.run_probe(routes)
        self.assertEqual(verdict, "VULNERABLE")
        self.assertTrue(any("/portal/" in n for n in notes))

    def test_awv_absent_is_noted_not_fatal(self):
        routes = {
            "/": (200, "<html><title>MiCollab</title>MiCollab 10.4.0.0"
                       "</html>"),
            "/awcuser/cgi-bin/": (404, "not found"),
        }
        verdict, detail, notes = self.run_probe(routes)
        self.assertEqual(verdict, "FIXED")
        self.assertTrue(any("404" in n for n in notes))

    def test_admin_php_presence_does_not_change_verdict(self):
        routes = {
            "/": (200, "<html><title>MiCollab</title>MiCollab 10.4.0.0"
                       "</html>"),
            "/npm/admin/cmd.php": (200, "admin"),
            "/npm/admin/NuPoint/import_contacts.php": (401, "auth"),
        }
        verdict, _, notes = self.run_probe(routes)
        self.assertEqual(verdict, "FIXED")
        self.assertTrue(any("cmd.php" in n for n in notes))


class LogHuntTests(unittest.TestCase):
    def test_actor_ip_and_shell_hits(self):
        log = (
            '10.0.0.1 - - [16/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200\n'
            '203.0.113.9 - - [16/Nov/2026:10:01:00 +0000] "POST '
            '/awcuser/cgi-bin/awv.cgi HTTP/1.1" 200\n'
            '203.0.113.9 - - [16/Nov/2026:10:02:00 +0000] "GET '
            '/pictures/x/shell.asp?c=whoami HTTP/1.1" 200\n'
            '10.0.0.2 - - [16/Nov/2026:10:03:00 +0000] "GET '
            'http://204.76.203.204/bkup/1.tgz HTTP/1.1" 201\n'
        )
        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                        delete=False) as handle:
            handle.write(log)
            path = handle.name
        try:
            hits, _ = mms.scan_access_log(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(hits), 3)
        posts = [h for h in hits if h[3]]
        self.assertEqual(len(posts), 1)
        self.assertIn("AWV CGI", posts[0][4][0])
        shells = [h for h in hits if "web shell" in "; ".join(h[4])]
        self.assertEqual(len(shells), 1)
        actors = [h for h in hits if "204.76.203.204" in h[2]]
        self.assertEqual(len(actors), 1)

    def test_clean_log_has_no_hits(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                        delete=False) as handle:
            handle.write('10.0.0.1 - - [16/Nov/2026:10:00:00 +0000] '
                         '"GET /portal/ HTTP/1.1" 200\n')
            path = handle.name
        try:
            hits, _ = mms.scan_access_log(path)
        finally:
            os.unlink(path)
        self.assertEqual(hits, [])

    def test_missing_log_path(self):
        hits, notes = mms.scan_access_log("/nonexistent/access.log")
        self.assertEqual(hits, [])
        self.assertTrue(notes)

    def test_log_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.log").write_text(
                '1.2.3.4 - - [16/Nov/2026:10:00:00 +0000] "GET '
                'http://api.ipify.org/ HTTP/1.1" 200\n')
            hits, _ = mms.scan_access_log(tmp)
        self.assertEqual(len(hits), 1)
        self.assertIn("IP-echo", hits[0][4][0])


class IocDirTests(unittest.TestCase):
    def test_campaign_artifacts_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pictures" / "x").mkdir(parents=True)
            (root / "pictures" / "x" / "shell.asp").write_text("<% evil %>")
            (root / "tmp").mkdir()
            (root / "tmp" / "roast1.py").write_text("# kerberoast")
            (root / "tmp" / "mkccache.py").write_text("# cache")
            (root / "tmp" / "data_batch_1.tgz").write_bytes(b"")
            (root / "normal.py").write_text("# harmless")
            hits, _ = mms.scan_ioc_dir(tmp)
        labels = [label for _, label in hits]
        self.assertEqual(len(hits), 4)
        self.assertTrue(any("web shell" in l for l in labels))
        self.assertTrue(any("Kerberoasting" in l for l in labels))
        self.assertTrue(any("mkccache" in l for l in labels))
        self.assertTrue(any("archive" in l for l in labels))

    def test_clean_tree_has_no_hits(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "index.html").write_text("<html/>")
            hits, _ = mms.scan_ioc_dir(tmp)
        self.assertEqual(hits, [])

    def test_missing_dir(self):
        hits, notes = mms.scan_ioc_dir("/nonexistent/tree")
        self.assertEqual(hits, [])
        self.assertTrue(notes)


class CliTests(unittest.TestCase):
    def test_version_cli_vulnerable(self):
        self.assertEqual(mms.main(["--version", "10.2.0.9"]),
                         mms.EXIT_VULNERABLE)

    def test_version_cli_fixed(self):
        self.assertEqual(mms.main(["--version", "10.4.0.0"]),
                         mms.EXIT_CLEAN)

    def test_version_cli_unknown(self):
        self.assertEqual(mms.main(["--version", "11.0.0.0"]),
                         mms.EXIT_UNKNOWN)

    def test_list_exits_clean(self):
        self.assertEqual(mms.main(["--list"]), mms.EXIT_CLEAN)

    def test_inventory_json(self):
        entries = [
            {"host": "a", "version": "10.2.0.9"},
            {"host": "b", "version": "10.4.0.0"},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as handle:
            json.dump(entries, handle)
            path = handle.name
        try:
            self.assertEqual(mms.main(["--inventory-json", path]),
                             mms.EXIT_VULNERABLE)
            self.assertEqual(mms.main(["--inventory-json", path, "--json"]),
                             mms.EXIT_VULNERABLE)
        finally:
            os.unlink(path)

    def test_version_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("10.3.0.18\n")
            path = handle.name
        try:
            self.assertEqual(mms.main(["--version-file", path]),
                             mms.EXIT_VULNERABLE)
        finally:
            os.unlink(path)

    def test_json_output(self):
        self.assertEqual(mms.main(["--version", "10.2.0.9", "--json"]),
                         mms.EXIT_VULNERABLE)


if __name__ == "__main__":
    unittest.main()
