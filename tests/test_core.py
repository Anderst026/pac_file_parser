import unittest

from pac_file_parser import PacFile, PacParseError
from pac_file_parser.core import parse


class ParseTests(unittest.TestCase):
    def test_extracts_find_proxy_for_url(self):
        text = (
            "function FindProxyForURL(url, host) {\n"
            "  return 'DIRECT';\n"
            "}\n"
        )
        pac = parse(text)
        self.assertIsInstance(pac, PacFile)
        self.assertEqual(pac.raw_text, text)
        self.assertEqual(
            pac.find_proxy_for_url,
            "function FindProxyForURL(url, host) {\n  return 'DIRECT';\n}",
        )

    def test_extracts_standard_helpers_only(self):
        text = (
            "function dnsResolve(host) { return host; }\n"
            "function isInNet(host, net, mask) { return false; }\n"
            "function shExpMatch(str, pattern) { return true; }\n"
            "function internalWorker() { return 0; }\n"
            "function FindProxyForURL(url, host) { return 'DIRECT'; }\n"
        )
        pac = parse(text)
        self.assertEqual(
            set(pac.helper_functions.keys()),
            {"dnsResolve", "isInNet", "shExpMatch"},
        )
        # internalWorker is a non-standard helper and is NOT reported.
        self.assertNotIn("internalWorker", pac.helper_functions)
        # Standard helpers not present in the file are simply absent.
        self.assertNotIn("dnsResolveEx", pac.helper_functions)

    def test_helper_function_text_includes_keyword_and_brace(self):
        text = (
            "function dnsResolve(host) {\n"
            "  return null;\n"
            "}\n"
            "function FindProxyForURL(url, host) { return 'DIRECT'; }\n"
        )
        pac = parse(text)
        self.assertEqual(
            pac.helper_functions["dnsResolve"],
            "function dnsResolve(host) {\n  return null;\n}",
        )

    def test_missing_find_proxy_for_url_raises(self):
        with self.assertRaises(PacParseError):
            parse("function dnsResolve(host) { return host; }\n")

    def test_empty_input_raises(self):
        with self.assertRaises(PacParseError):
            parse("")

    def test_whitespace_only_input_raises(self):
        with self.assertRaises(PacParseError):
            parse("   \n\t  \n")

    def test_non_string_input_raises(self):
        with self.assertRaises(PacParseError):
            parse(b"function FindProxyForURL() {}")  # type: ignore[arg-type]

    def test_brace_comment_with_unbalanced_braces_does_not_break_parsing(self):
        text = (
            "/* config { { { */\n"
            "function FindProxyForURL(url, host) {\n"
            "  return 'DIRECT';\n"
            "}\n"
            "/* end } */\n"
        )
        pac = parse(text)
        self.assertIn("FindProxyForURL", pac.find_proxy_for_url)
        self.assertEqual(pac.helper_functions, {})

    def test_line_comment_with_braces_ignored(self):
        text = (
            "// function fake() { return 1; }\n"
            "function FindProxyForURL(url, host) { return 'DIRECT'; }\n"
        )
        pac = parse(text)
        self.assertIn("FindProxyForURL", pac.find_proxy_for_url)
        self.assertNotIn("fake", pac.helper_functions)

    def test_function_keyword_inside_string_not_treated_as_function(self):
        text = (
            "var s = 'function dnsResolve(x) { return x; }';\n"
            "function FindProxyForURL(url, host) { return 'DIRECT'; }\n"
        )
        pac = parse(text)
        # dnsResolve only appears inside a string literal, not as a real
        # top-level function, so it must not be extracted.
        self.assertEqual(pac.helper_functions, {})

    def test_nested_function_is_part_of_parent_body(self):
        text = (
            "function FindProxyForURL(url, host) {\n"
            "  function inner() { return 'DIRECT'; }\n"
            "  return inner();\n"
            "}\n"
        )
        pac = parse(text)
        # The nested function is inside FindProxyForURL's body, so it should
        # be included verbatim in that body text and not reported separately.
        self.assertIn("function inner()", pac.find_proxy_for_url)
        self.assertNotIn("inner", pac.helper_functions)

    def test_function_keyword_prefix_is_not_function(self):
        text = (
            "var functional = 1;\n"
            "function FindProxyForURL(url, host) { return 'DIRECT'; }\n"
        )
        pac = parse(text)
        self.assertIn("FindProxyForURL", pac.find_proxy_for_url)
        self.assertEqual(pac.helper_functions, {})

    def test_comment_between_function_keyword_and_name(self):
        text = (
            "function /* hi */ FindProxyForURL(url, host) { return 'DIRECT'; }\n"
        )
        pac = parse(text)
        self.assertIn("FindProxyForURL", pac.find_proxy_for_url)

    def test_unclosed_function_body_raises(self):
        text = "function FindProxyForURL(url, host) { return 'DIRECT';\n"
        with self.assertRaises(PacParseError):
            parse(text)

    def test_helpers_returned_in_spec_order(self):
        text = (
            "function shExpMatch(s, p) { return true; }\n"
            "function dnsResolve(h) { return h; }\n"
            "function FindProxyForURL(url, host) { return 'DIRECT'; }\n"
        )
        pac = parse(text)
        # dict preserves insertion order; helpers should be inserted in the
        # order of the spec tuple, not the order they appeared in the file.
        self.assertEqual(list(pac.helper_functions.keys()), ["dnsResolve", "shExpMatch"])

    def test_stray_closing_brace_does_not_crash(self):
        text = (
            "}\n"
            "function FindProxyForURL(url, host) { return 'DIRECT'; }\n"
        )
        pac = parse(text)
        self.assertIn("FindProxyForURL", pac.find_proxy_for_url)

    def test_template_literal_with_brace_not_treated_as_block(self):
        text = (
            "var x = `${1 + 1}`;\n"
            "function FindProxyForURL(url, host) { return 'DIRECT'; }\n"
        )
        pac = parse(text)
        self.assertIn("FindProxyForURL", pac.find_proxy_for_url)

    def test_multiple_pac_helper_functions(self):
        text = (
            "function myIpAddress() { return '10.0.0.1'; }\n"
            "function dnsDomainIs(host, domain) { return false; }\n"
            "function localHostOrDomainIs(host, dom) { return true; }\n"
            "function isPlainHostName(host) { return false; }\n"
            "function FindProxyForURL(url, host) { return 'DIRECT'; }\n"
        )
        pac = parse(text)
        self.assertEqual(
            set(pac.helper_functions.keys()),
            {"myIpAddress", "dnsDomainIs", "localHostOrDomainIs", "isPlainHostName"},
        )


if __name__ == "__main__":
    unittest.main()
