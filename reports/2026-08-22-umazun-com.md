# Case: umazun.com

**Impersonated brand:** Amazon
**Detection technique:** fuzzy-edit-distance (edit distance: 2)
**Risk score:** 65.0
**Status:** confirmed malicious

## Timeline

- **2026-08-20 21:26 UTC**: certificate first seen in CT logs (issuer: Let's Encrypt, log: Let's Encrypt 'Sycamore2026h2')
- **2026-08-20 21:26 UTC**: last seen (1 certificate(s) total)
- **2026-08-22 13:09 UTC**: marked as `confirmed malicious`

**Detection to confirmation window: 1.7 days**
(this is the actual lead time gained by watching CT logs instead of
finding out some other way)

## Technical signals

- Resolves to an IP: True
- Has an MX record: True
- Registrable domain: `umazun.com`

## Evidence and investigation notes

Al menos ha expirado

## Interpretation

_(fill in by hand: why this case is interesting, what makes it stand out,
what it shows. This part is not auto-generated.)_

---
*Draft generated automatically on 2026-08-22 13:20 UTC by ct-hunter from
`data/ct_hunter.db`. The timeline data can be verified against that
database.*
