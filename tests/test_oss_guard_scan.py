import pathlib
import unittest

from tools import oss_guard_scan


ROOT = pathlib.Path(__file__).resolve().parents[1]


class OssGuardScanTests(unittest.TestCase):
    def test_resend_api_key_assignment_is_secret_like(self):
        fixture = ROOT / "tests" / "_oss_guard_resend_fixture.txt"
        key = "RESEND" + "_API_KEY"
        value = "re_" + "abcdefghijklmnopqrstuvwxyz123456"
        fixture.write_text(
            "\n".join(
                [
                    f"# {key}={value}",
                    f"{key}=your-resend-api-key",
                    f"{key}={value}",
                ]
            ),
            encoding="utf-8",
        )
        try:
            findings = oss_guard_scan.scan_file(fixture)
        finally:
            fixture.unlink(missing_ok=True)

        self.assertEqual(
            findings,
            ["tests/_oss_guard_resend_fixture.txt:3: secret-like value"],
        )


if __name__ == "__main__":
    unittest.main()
