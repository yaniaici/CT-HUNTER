# Case: mta-sts.aspmx.l.google.com.dragqueen.it

**Impersonated brand:** Google
**Detection technique:** subdomain-impersonation (edit distance: 0)
**Risk score:** 95.0
**Status:** confirmed malicious

## Timeline

- **2026-08-21 20:55 UTC**: certificate first seen in CT logs (issuer: Let's Encrypt, log: Let's Encrypt 'Willow2026h2')
- **2026-08-21 20:55 UTC**: last seen (1 certificate(s) total)
- **2026-08-22 13:19 UTC**: marked as `confirmed malicious`

**Detection to confirmation window: 0.7 days**
(this is the actual lead time gained by watching CT logs instead of
finding out some other way)

## Technical signals

- Resolves to an IP: True
- Has an MX record: True
- Registrable domain: `mta-sts.aspmx.l.google.com.dragqueen.it`

## Evidence and investigation notes

Confirmed by VirusTotal (3/91 engines), checked 2026-08-22.

## Interpretation

_(fill in by hand: why this case is interesting, what makes it stand out,
what it shows. This part is not auto-generated.)_

---
*Draft generated automatically on 2026-08-22 13:20 UTC by ct-hunter from
`data/ct_hunter.db`. The timeline data can be verified against that
database.*
