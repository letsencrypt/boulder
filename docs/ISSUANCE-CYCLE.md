# The Issuance Cycle

What happens during an ACME finalize request?

At a high level:

1. Check that all authorizations are good.
2. Recheck CAA for hostnames that need it.
3. Allocate and store a serial number.
4. Select a certificate profile.
5. Generate and store linting precertificate.
6. Sign, log (and don't store) precertificate.
7. Submit precertificate to CT.
8. Generate linting final certificate. Not logged or stored.
9. Sign, log, and store final certificate.

Revocation can happen at any time after (5), whether or not step (6) was successful. We do things this way so that even in the event of a power failure or error storing data, we have a record of what we planned to sign (the tbsCertificate bytes of the linting certificate).

Note that to avoid needing a migration, we chose to store the linting certificate from (5) in the "precertificates" table, which is now a bit of a misnomer.
