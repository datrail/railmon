# asp_spelling

One spelling for each Agent Security Profile (ASP) value that can be written
more than one way: `root` and `0` are one user, `HTTPS://API.example.com:443/v1`
and `https://api.example.com/v1` are one endpoint, and a list's order is not
state. RailDash and Rail Center both read ASP values through this module, so
they agree on when two values are one value and report the same drift.

```python
from asp_spelling import canonical, respelled, sorted_lists

def reading(name, value):
    return canonical(sorted_lists(respelled(name, value)))

reading("user", "0") == reading("user", "root")                # True
reading("user", "ROOT") == reading("user", "root")             # False: Linux reads ROOT as its own account
```

- `respelled(name, value)` gives attribute `name`'s value in its one spelling,
  or the value as it came for an attribute `SPELLINGS` doesn't name.
- `sorted_lists(value)` puts every list in the value, at any depth, in one
  fixed order.
- `canonical(value)` is the JSON two values are compared by, so `1` and `true`
  stay two readings.

Each spelling makes two values one only where a rule says they name the same
thing (Linux, DNS, RFC 3986, the kernel's capability names, PEP 440), never
where they merely look alike. A value of a shape a spelling doesn't know is
kept as it came. Which values a caller respells is the caller's choice: both
consumers respell `ANSWERED` and `PARTIAL` values and sort every value.

RailMon's bundles don't go through it: a bundle keeps every value as it was
observed.

## Using it

It is one file with no dependencies beyond the standard library (Python 3.10+).

- **Install** it pinned to a railmon commit:
  `asp-spelling @ git+https://github.com/datrail/railmon@<commit>#subdirectory=python/asp_spelling`
- **Vendor** `asp_spelling.py` byte-for-byte and test that your copy is
  identical to railmon's, as RailDash does with RailMon's schemas.

## Versioning

`SPELLING_VERSION` (and the package version, which equals it) moves whenever a
spelling is added, dropped or changed, since the same evidence then reads
differently. Record it beside anything computed from a respelled value.

## Tests

```bash
python3 -m unittest discover -s python/asp_spelling/tests
```
