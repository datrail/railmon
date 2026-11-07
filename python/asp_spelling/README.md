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

## asp_normalize

The same package's second module turns an evidence bundle (decoded JSON, v1 or
v2) into one attribute map per agent, so both consumers profile from the same
normalized data:

```python
from asp_normalize import normalized, steps, lifted

for agent_key, attributes in normalized(bundle, shapes=MY_SHAPES):
    ...  # agent_key is None for a v1 bundle
```

- A v2 bundle's sandbox scope is merged into each agent scope. Where both
  scopes carry an attribute with different readings (compared after
  respelling), `ScopeConflict` names every `(agent_key, attribute)` pair.
- Each read (`ANSWERED`/`PARTIAL`) value is respelled, every list is sorted,
  and a `window`'s keys are sorted. Members the bundle left out stay out.
- `shapes` maps an attribute name to a predicate: a read value its predicate
  rejects is marked `FAILED` with `PARSE_FAILED`, keeping its value and author
  (`unusable` tells it from a collector's own failure). Which shapes a rule can
  use is the caller's: Rail Center passes its `SHAPES`, RailDash none.
- `steps(shapes)`, `chain`, `unliftable` and `lifted` read a map made under an
  older `RULES_VERSION` as the newer rules make the same evidence.

What a caller builds around the maps (a typed profile, its own version, an
identity for an unkeyed agent, a registration payload's profile) stays the
caller's. Rail Center's `profiling/asp.normalize` is the reference these rules
came from; its fixture corpus, run through both, is the check that they agree.

## Using it

Two files with no dependencies beyond the standard library (Python 3.10+);
`asp_normalize` imports `asp_spelling`.

- **Install** it pinned to a railmon commit:
  `asp-spelling @ git+https://github.com/datrail/railmon@<commit>#subdirectory=python/asp_spelling`
- **Vendor** the files byte-for-byte and test that your copy is identical to
  railmon's, as RailDash does with `asp_spelling.py` and RailMon's schemas.

## Versioning

`SPELLING_VERSION` moves whenever a spelling is added, dropped or changed, and
`RULES_VERSION` whenever `normalized` would make something else of the same
bundle, since the same evidence then reads differently. Record them beside
anything computed from a normalized value. A rule change is a new version with
a step of its own; an existing step never changes (`asp_normalize`'s docstring
says why). The package version is `SPELLING_VERSION`, so a consumer pinning
the package and one vendoring `asp_spelling.py` read the same number; pin the
package to a commit, as above, and record `RULES_VERSION` from the module.

## Tests

```bash
python3 -m unittest discover -s python/asp_spelling/tests
```
