import io
import pathlib
import unittest
import urllib.parse
import urllib.request
import importlib.util


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "smoke_bootstrap_registration.py"


class FakeResponse:
    def __init__(self, status, url, body):
        self.status = status
        self._url = url
        self._body = body.encode()

    def geturl(self):
        return self._url

    def read(self):
        return self._body


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout=0):
        if isinstance(request, urllib.request.Request):
            url = request.full_url
            method = request.get_method()
            data = request.data
            headers = dict(request.header_items())
        else:
            url = request
            method = "GET"
            data = None
            headers = {}

        self.requests.append(
            {
                "url": url,
                "method": method,
                "data": data,
                "headers": headers,
                "timeout": timeout,
            }
        )
        return self.responses.pop(0)


class BootstrapSmokeScriptTests(unittest.TestCase):
    def load_script(self):
        self.assertTrue(SCRIPT.exists(), "missing bootstrap smoke script")
        spec = importlib.util.spec_from_file_location("smoke_bootstrap_registration", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_run_smoke_posts_bootstrap_form_and_checks_registration_closes(self):
        module = self.load_script()
        base_url = "http://smoke.example:8000"
        first = FakeOpener(
            [
                FakeResponse(200, f"{base_url}/health/", '{"status": "ok"}'),
                FakeResponse(200, f"{base_url}/login/", "Create one"),
                FakeResponse(
                    200,
                    f"{base_url}/register/",
                    'Bootstrap administrator Create the first account '
                    '<input type="hidden" name="csrfmiddlewaretoken" value="csrf-123">',
                ),
                FakeResponse(200, f"{base_url}/dashboard/", "Dashboard"),
            ]
        )
        second = FakeOpener(
            [
                FakeResponse(200, f"{base_url}/register/", "Registration is closed"),
                FakeResponse(200, f"{base_url}/login/", "Need access?"),
            ]
        )
        openers = [first, second]

        output = io.StringIO()
        result = module.run_smoke(
            base_url,
            email="first@example.test",
            password="StrongerSmokePassword123!",
            opener_factory=lambda: openers.pop(0),
            output=output,
        )

        self.assertEqual(result.email, "first@example.test")
        post_request = first.requests[3]
        self.assertEqual(post_request["method"], "POST")
        self.assertEqual(post_request["url"], f"{base_url}/register/")
        self.assertEqual(post_request["headers"]["Content-type"], "application/x-www-form-urlencoded")
        posted = urllib.parse.parse_qs(post_request["data"].decode())
        self.assertEqual(posted["csrfmiddlewaretoken"], ["csrf-123"])
        self.assertEqual(posted["email"], ["first@example.test"])
        self.assertIn("register after bootstrap: 200 closed", output.getvalue())


if __name__ == "__main__":
    unittest.main()
