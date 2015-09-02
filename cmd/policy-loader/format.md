# `policy-loader` rule file format

Both `blacklist` and `whitelist` rules are loaded into the policy database in the
same JSON file. This rule file has the following structure, currently the only allowed
types are `whitelist` and `blacklist`. `base-rules.json` in this directory contains
a number of blacklist rules for special-use domains but this should be built upon
further with high-value domains.

```
{
  "Blacklist": ["example.com", ...],
  "Whitelist:" ["another-example.com", ...]
}
```
