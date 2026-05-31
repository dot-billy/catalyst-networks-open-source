import pathlib
import tempfile
import unittest

from tools import oss_guard_scan


ROOT = pathlib.Path(__file__).resolve().parents[1]


class OssGuardScanTests(unittest.TestCase):
    def scan_lines(self, lines, suffix=".txt"):
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=ROOT / "tests",
            prefix="_oss_guard_",
            suffix=suffix,
            delete=False,
        ) as fixture_file:
            fixture_file.write("\n".join(lines))
            fixture = pathlib.Path(fixture_file.name)
        try:
            return oss_guard_scan.scan_file(fixture)
        finally:
            fixture.unlink(missing_ok=True)

    def test_resend_api_key_assignment_is_secret_like(self):
        key = "RESEND" + "_API_KEY"
        quoted_key = f'"{key}"'
        value = "re_" + "abcdefghijklmnopqrstuvwxyz123456"
        findings = self.scan_lines([
            f"# {key}={value}",
            f"{key}=your-resend-api-key",
            f"{key}={value}",
            f"{quoted_key}: \"{value}\"",
            f"{quoted_key}: \"your-resend-api-key\"",
        ])

        self.assertEqual(len(findings), 3)
        self.assertRegex(findings[0], r"^tests/_oss_guard_[^:]+\.txt:1: secret-like value$")
        self.assertRegex(findings[1], r"^tests/_oss_guard_[^:]+\.txt:3: secret-like value$")
        self.assertRegex(findings[2], r"^tests/_oss_guard_[^:]+\.txt:4: secret-like value$")

    def test_resend_api_key_plumbing_references_are_allowed(self):
        key = "RESEND" + "_API_KEY"
        quoted_key = f'"{key}"'
        mailgun_key = "MAILGUN" + "_API_KEY"
        resend_var = "resend" + "_api" + "_key"

        findings = self.scan_lines(
            [
                f'{resend_var} = _env_value(env, "{key}")',
                f"if {resend_var}:",
                f"{key} = _email_settings['{key}']",
                f"{mailgun_key} = _email_settings['{mailgun_key}']",
                f'settings["ANYMAIL"] = {{{quoted_key}: {resend_var}}}',
            ],
            suffix=".py",
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
