# PAC File Parser

Extracts the `FindProxyForURL` function and the standard PAC helper functions
(`dnsResolve`, `isInNet`, `shExpMatch`, and the rest of the spec-defined set)
from PAC file text for offline inspection. The library does not evaluate
JavaScript; it returns the source text of each function so you can read, lint,
or audit it without a JS engine.

## Usage

```python
from pac_file_parser import PacFile, PacParseError
from pac_file_parser.core import parse

pac_text = """
function dnsResolve(host) { return host; }
function FindProxyForURL(url, host) {
  return 'DIRECT';
}
"""

try:
    pac: PacFile = parse(pac_text)
except PacParseError as e:
    raise SystemExit(str(e))

print(pac.find_proxy_for_url)
for name, body in pac.helper_functions.items():
    print(name, "->", body)
```

`pac_file_parser.core.parse(text: str) -> PacFile` returns a frozen dataclass with three fields:

- `raw_text` — the verbatim input string.
- `find_proxy_for_url` — the full text of the `FindProxyForURL` function,
  including its `function` keyword and closing brace.
- `helper_functions` — a mapping of standard PAC helper name to that
  function's full text. Only functions that actually appear in the file are
  present.

## Why this exists

Browser engines run PAC files through a restricted JavaScript runtime, which
makes them awkward to inspect from outside the browser. When you need to audit
what a PAC file does (which DNS helpers it calls, what `shExpMatch` patterns
it uses, whether `FindProxyForURL` branches on `isInNet`), you usually end up
reading the file by hand. This library does that reading for you and returns
the relevant function bodies as strings.

The trade-off: this is a tokenizer, not a JS engine. It understands enough
JavaScript syntax (line comments, block comments, single/double/template
strings, balanced braces and parens) to find function boundaries correctly.
It does not understand regex literals, so a PAC file that uses a regex literal
in a place that affects brace or paren balance may parse incorrectly. In
practice, standard PAC helper functions and `FindProxyForURL` bodies do not
contain such literals, so this is a deliberate scope cut rather than an
oversight.

## Scope decisions

Only the eighteen helper function names defined by the PAC specification are
reported by `helper_functions`. Any other function in the file — even one that
looks like a helper — is ignored by the helper extractor and only visible via
`raw_text`. A PAC file without `FindProxyForURL` is a hard error, because that
function is the entire point of the format and silence would be misleading.

## Awkward edge

The parser tracks brace depth and skips comments and string literals, so a
block comment containing unbalanced braces (common in hand-written PAC files
with ASCII-art headers) will not corrupt function detection. A bare `}` at the
top of the file (malformed input) is clamped to depth 0 rather than going
negative and breaking later detection. The one edge the parser does not handle
is a regex literal whose contents affect brace or paren balance — see the
trade-off note above.
