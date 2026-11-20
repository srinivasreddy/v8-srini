"""Tests for _call_sites comment detection in dgf.py.

Bug 1 (from the review): the current check

    comment_pos = prefix.find("//")
    if (comment_pos >= 0 and "'" not in prefix[:comment_pos] and
            '"' not in prefix[:comment_pos] and
            "`" not in prefix[:comment_pos]):
        continue

fails when a string literal containing "//" appears before the call site
on the same line. The quotes "save" the call site from being skipped, even
though it is actually inside a comment. The same function also misses
block comments and strings containing the function name.

Run with:
    python3 tools/maglev-dgf/test_call_sites.py
or:
    python3 -m pytest tools/maglev-dgf/test_call_sites.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dgf import _call_sites, CallSite


class TestCallSitesBasics(unittest.TestCase):
    """Baseline: cases the current implementation already gets right."""

    def test_simple_call(self):
        self.assertEqual(_call_sites("f(1)", "f"), [CallSite(0, 4, "1")])

    def test_multiple_calls(self):
        self.assertEqual(len(_call_sites("f(1); f(2);", "f")), 2)

    def test_call_with_nested_parens(self):
        self.assertEqual(len(_call_sites("f(g(1), h(2))", "f")), 1)

    def test_call_with_array_arg(self):
        self.assertEqual(len(_call_sites("f([1, 2, 3])", "f")), 1)

    def test_call_with_string_arg_containing_comma(self):
        self.assertEqual(len(_call_sites("f('a,b', 2)", "f")), 1)

    def test_function_declaration_is_skipped(self):
        self.assertEqual(_call_sites("function f(x) { return x; }", "f"), [])

    def test_call_after_function_keyword_is_found(self):
        sites = _call_sites("function f(x) { return x; } f(1);", "f")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].args, "1")

    def test_method_call_not_matched(self):
        # `obj.f(1)` should not match `f` — the lookbehind excludes `.`.
        self.assertEqual(_call_sites("obj.f(1)", "f"), [])

    def test_identifier_with_suffix_not_matched(self):
        # `x_f(1)` should not match `f`.
        self.assertEqual(_call_sites("x_f(1)", "f"), [])

    def test_dollar_prefixed_identifier_not_matched(self):
        self.assertEqual(_call_sites("$f(1)", "f"), [])


class TestLineComments(unittest.TestCase):
    """Line comments: the current implementation handles these."""

    def test_whole_line_comment(self):
        self.assertEqual(_call_sites("// f(1)", "f"), [])

    def test_trailing_comment(self):
        self.assertEqual(_call_sites("x = 1; // f(1)", "f"), [])

    def test_two_commented_calls(self):
        src = "// f(1)\n// f(2)\nf(3)"
        sites = _call_sites(src, "f")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].args, "3")

    def test_line_comment_after_code_with_string_containing_slashes(self):
        # Control: the call is real code, the string with "//" is before it
        # on the same line. The current code finds it; the fix also finds it.
        sites = _call_sites('x = "//"; f(1)', "f")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].args, "1")


class TestStringVsCommentConfusion(unittest.TestCase):
    """Bug 1: strings containing `//` confuse the comment detector.

    These tests FAIL on the current implementation. They are the fix's
    acceptance tests.
    """

    def test_comment_after_string_with_double_slash(self):
        # The first `//` is inside a string; `f(1)` is inside a real comment.
        # Current code returns f(1) because `"` before `//` disables the
        # skip. The fix returns [].
        self.assertEqual(_call_sites('x = "//"; // f(1)', "f"), [])

    def test_comment_after_template_with_double_slash(self):
        # Same shape, backtick string.
        self.assertEqual(_call_sites("x = `//`; // f(1)", "f"), [])

    def test_comment_after_url_string(self):
        # Realistic: a URL in a string, then a comment.
        self.assertEqual(_call_sites('url = "http://x"; // f(1)', "f"), [])

    def test_comment_after_escaped_quote_string(self):
        # The escaped quote does not close the string, so the "//" is still
        # inside the string and the "// " after is a comment.
        self.assertEqual(_call_sites(r'x = "\"//"; // f(1)', "f"), [])

    def test_real_call_after_string_with_double_slash(self):
        # Control: no comment. The call should be found.
        sites = _call_sites('x = "//"; f(1)', "f")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].args, "1")

    def test_real_call_after_url_string(self):
        sites = _call_sites('url = "http://x"; f(1)', "f")
        self.assertEqual(len(sites), 1)

    def test_one_real_call_one_in_comment(self):
        # Realistic: one real call, one in a comment after a string with "//".
        sites = _call_sites('x = "//"; f(1); // f(2)', "f")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].args, "1")

    def test_one_real_call_before_string_one_in_comment(self):
        sites = _call_sites('f(1); x = "//"; // f(2)', "f")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].args, "1")


class TestRelatedBugs(unittest.TestCase):
    """Bugs adjacent to Bug 1. These also FAIL on the current code.

    They live in the same function and the same scanner, so the fix covers
    them; test them alongside Bug 1.
    """

    def test_call_inside_double_quoted_string(self):
        # A call name inside a string is not a call site.
        self.assertEqual(_call_sites('x = "call f(1)";', "f"), [])

    def test_call_inside_single_quoted_string(self):
        self.assertEqual(_call_sites("x = 'call f(1)';", "f"), [])

    def test_call_inside_template_literal(self):
        self.assertEqual(_call_sites("x = `call f(1)`;", "f"), [])

    def test_call_inside_block_comment(self):
        self.assertEqual(_call_sites("/* f(1) */", "f"), [])

    def test_call_after_block_comment_is_found(self):
        sites = _call_sites("/* header */ f(1)", "f")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].args, "1")

    def test_one_call_in_block_comment_one_real(self):
        sites = _call_sites("/* f(1) */ f(2);", "f")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].args, "2")

    def test_call_after_block_comment_with_slashes_in_string(self):
        # `/* ... */` followed by a string with "//", then a real call.
        sites = _call_sites('/* x */ s = "//"; f(1)', "f")
        self.assertEqual(len(sites), 1)


class TestEscapedQuotes(unittest.TestCase):
    """Escaped quotes must not close a string early."""

    def test_escaped_quote_inside_string(self):
        # The string contains a literal `"`, so it does not close early.
        # `f(1)` is inside the string.
        self.assertEqual(_call_sites(r'x = "a\"b f(1)";', "f"), [])

    def test_escaped_backslash_does_not_escape_closing_quote(self):
        # `"\\"` is one escaped backslash, then the string closes.
        # `f(1)` is in the code after the string.
        sites = _call_sites(r'x = "\\"; f(1);', "f")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].args, "1")

    def test_escaped_quote_then_comment(self):
        # The escaped quote is inside a string; the "//" after is a comment.
        self.assertEqual(_call_sites(r'x = "\""; // f(1)', "f"), [])


class TestMultipleFunctions(unittest.TestCase):
    """One detector call, one name: the tests above use `f`; also check `g`."""

    def test_call_with_different_name_uses_same_logic(self):
        self.assertEqual(_call_sites('x = "//"; // g(1)', "g"), [])
        self.assertEqual(len(_call_sites('x = "//"; g(1)', "g")), 1)

    def test_two_targets_in_one_source(self):
        src = 'x = "//"; // f(1)\ng(2)'
        self.assertEqual(_call_sites(src, "f"), [])
        self.assertEqual(len(_call_sites(src, "g")), 1)


if __name__ == "__main__":
    unittest.main()
