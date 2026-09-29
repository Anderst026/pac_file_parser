"""Parse a Proxy Auto-Configuration (PAC) file for offline inspection.

A PAC file is JavaScript text containing a ``FindProxyForURL(url, host)``
function plus a set of pre-defined helper functions such as ``dnsResolve``
and ``isInNet``. Browser engines evaluate PAC files with a restricted
JavaScript runtime; this library does NOT evaluate them. It extracts the
text of the main entry point and the helper functions so a human or tool
(inspector, linter, auditor) can inspect them without a JS engine.

Scope decisions (stated plainly so tests and callers agree):

* Only the functions the PAC specification names as standard helpers are
  reported by ``helper_functions``. The full list is in ``_PAC_HELPER_NAMES``.
  Any other function in the file, even if it looks helper-ish, is ignored by
  the helper extractor and only visible via ``raw_text``.
* A PAC file without ``FindProxyForURL`` is a hard error: the whole point of
  the format is that entry point, so silence would be misleading.
* Extraction is line/brace based, not regex-on-whole-file. PAC files in the
  wild contain brace comments (``/* ... */``) and line comments (``// ...``)
  that can nest braces; a naive regex either over-matches or under-matches.
  We scan token-by-token so braces inside comments and strings do not
  corrupt function-body boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Full set of helper function names defined by the PAC specification, in the
# order the spec lists them. Used both to recognise helpers and to return them
# in a stable, human-friendly order.
_PAC_HELPER_NAMES: Tuple[str, ...] = (
    "dnsResolve",
    "dnsResolveEx",
    "isResolvable",
    "isResolvableEx",
    "getLocalHostAddress",
    "isInNet",
    "isInNetEx",
    "isPlainHostName",
    "dnsDomainIs",
    "localHostOrDomainIs",
    "myIpAddress",
    "myIpAddressEx",
    "shExpMatch",
    "dnsDomainLevels",
    "weekdayRange",
    "dateRange",
    "timeRange",
)

# A set for O(1) membership tests; mirrors _PAC_HELPER_NAMES.
_PAC_HELPER_SET = frozenset(_PAC_HELPER_NAMES)


class PacParseError(ValueError):
    """Raised when a PAC file is structurally invalid or missing its entry point."""


@dataclass(frozen=True)
class PacFile:
    """A parsed view of a PAC file's text.

    Attributes:
        raw_text: The verbatim input text, untouched.
        find_proxy_for_url: The full text of the ``FindProxyForURL`` function,
            including its ``function`` keyword and closing brace. ``None`` is
            not used here: if the function is missing we raise at parse time.
        helper_functions: Mapping of standard PAC helper name to the full text
            of that function (with ``function`` keyword and closing brace).
            Only functions that actually appear in the file are present.
    """

    raw_text: str
    find_proxy_for_url: str
    helper_functions: Dict[str, str]


def parse(text: str) -> PacFile:
    """Parse PAC file text into a :class:`PacFile`.

    Raises:
        PacParseError: If the input is not a string, is empty after stripping,
            or contains no ``FindProxyForURL`` function.
    """
    if not isinstance(text, str):
        raise PacParseError("PAC input must be a string, got %r" % type(text).__name__)
    if not text.strip():
        raise PacParseError("PAC input is empty")

    functions = _extract_top_level_functions(text)
    find_proxy = functions.get("FindProxyForURL")
    if find_proxy is None:
        raise PacParseError("PAC file contains no FindProxyForURL function")

    helpers = {name: functions[name] for name in _PAC_HELPER_NAMES if name in functions}

    return PacFile(raw_text=text, find_proxy_for_url=find_proxy, helper_functions=helpers)


def _extract_top_level_functions(text: str) -> Dict[str, str]:
    """Return a mapping of function name to full function text.

    Only functions declared at the top level of the file (brace depth 0 before
    the ``function`` keyword) are returned. Nested function declarations inside
    another function body are ignored; they belong to their parent function's
    text, which is exactly what we want when returning the parent's full body.
    """
    functions: Dict[str, str] = {}
    i = 0
    n = len(text)
    depth = 0

    while i < n:
        c = text[i]

        # Skip line comments ``// ...`` so braces and the word "function"
        # inside them do not confuse the scanner.
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            i = _skip_line_comment(text, i, n)
            continue

        # Skip block comments ``/* ... */``. These can contain unbalanced
        # braces (e.g. ASCII art), which would wreck depth tracking.
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i = _skip_block_comment(text, i, n)
            continue

        # Skip string literals so braces and slashes inside strings are not
        # mistaken for structure. PAC files are JavaScript, so single quotes,
        # double quotes, and template literals are all possible.
        if c in ("'", '"', "`"):
            i = _skip_string(text, i, n, c)
            continue

        if c == "{":
            depth += 1
            i += 1
            continue

        if c == "}":
            # Clamp at 0 so a stray closing brace in malformed input does not
            # send depth negative and break later detection.
            depth = max(0, depth - 1)
            i += 1
            continue

        # Only attempt function detection at top level. A function declared
        # inside another function is part of that function's body text and is
        # not separately reported.
        if depth == 0 and c == "f" and text.startswith("function", i):
            consumed, name, body = _try_read_function(text, i, n)
            if consumed is not None:
                functions[name] = body
                i = consumed
                continue

        i += 1

    return functions


def _try_read_function(text: str, start: int, n: int) -> Tuple[Optional[int], str, str]:
    """Attempt to read a ``function NAME(...) { ... }`` starting at ``start``.

    Returns ``(next_index, name, full_text)`` on success, or
    ``(None, "", "")`` if the text at ``start`` is not actually a function
    declaration (e.g. ``functional`` or a property access like
    ``obj.function``).
    """
    i = start
    keyword = "function"
    if not text.startswith(keyword, i):
        return None, "", ""
    i += len(keyword)

    if i >= n or not _is_ident_break(text[i]):
        return None, "", ""

    # Skip whitespace and comments between ``function`` and the name.
    i = _skip_ws_and_comments(text, i, n)

    # The function name. PAC helpers are always named; bare arrow-style
    # ``function () {}`` is not expected, and we do not support it.
    name_start = i
    while i < n and _is_ident_char(text[i]):
        i += 1
    name = text[name_start:i]
    if not name:
        return None, "", ""

    i = _skip_ws_and_comments(text, i, n)

    # Parameter list.
    if i >= n or text[i] != "(":
        return None, "", ""
    i = _skip_parens(text, i, n)
    if i is None:
        return None, "", ""

    i = _skip_ws_and_comments(text, i, n)

    if i >= n or text[i] != "{":
        return None, "", ""

    body_end = _find_matching_brace(text, i, n)
    if body_end is None:
        return None, "", ""

    full_text = text[start:body_end]
    return body_end, name, full_text


def _skip_ws_and_comments(text: str, i: int, n: int) -> int:
    """Advance past spaces, tabs, newlines, line comments, and block comments."""
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            i = _skip_line_comment(text, i, n)
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            i = _skip_block_comment(text, i, n)
        else:
            break
    return i


def _skip_line_comment(text: str, i: int, n: int) -> int:
    """Skip past a ``//`` comment to end-of-line (or end-of-input)."""
    i += 2
    while i < n and text[i] not in "\r\n":
        i += 1
    return i


def _skip_block_comment(text: str, i: int, n: int) -> int:
    """Skip past a ``/* ... */`` comment. Handles unclosed comments at EOF."""
    i += 2
    while i < n:
        if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
            return i + 2
        i += 1
    return i


def _skip_string(text: str, i: int, n: int, quote: str) -> int:
    """Skip a string literal starting at ``quote``.

    Handles the common escapes: backslash escapes the next character, and
    inside template literals a backtick escaped as ``\``` is honored. PAC
    files in the wild do not use regex literals after helper definitions, so
    regex-literal ambiguity is out of scope and not supported.
    """
    i += 1
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    return i


def _skip_parens(text: str, i: int, n: int) -> Optional[int]:
    """Skip a balanced ``(...)`` group starting at ``text[i] == '('``.

    Strings and comments inside the group are skipped so parens inside them
    do not unbalance the count. Returns the index after the closing ``)`` or
    ``None`` if unbalanced.
    """
    assert text[i] == "("
    i += 1
    depth = 1
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            i = _skip_line_comment(text, i, n)
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i = _skip_block_comment(text, i, n)
            continue
        if c in ("'", '"', "`"):
            i = _skip_string(text, i, n, c)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _find_matching_brace(text: str, open_idx: int, n: int) -> Optional[int]:
    """Return index just past the ``}`` matching ``text[open_idx] == '{'``.

    Comments and strings inside the body are skipped so their braces do not
    affect depth. Returns ``None`` if the brace is never closed.
    """
    assert text[open_idx] == "{"
    i = open_idx + 1
    depth = 1
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            i = _skip_line_comment(text, i, n)
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i = _skip_block_comment(text, i, n)
            continue
        if c in ("'", '"', "`"):
            i = _skip_string(text, i, n, c)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _is_ident_char(c: str) -> bool:
    """JavaScript identifier character: letter, digit, underscore, dollar."""
    return c.isalnum() or c in "_$"


def _is_ident_break(c: str) -> bool:
    """Character that cannot follow the bare word ``function``.

    ``functionfoo`` is an identifier in its own right, not the ``function``
    keyword followed by name ``foo``. We require a non-identifier character
    after the keyword to be sure.
    """
    return not _is_ident_char(c)
