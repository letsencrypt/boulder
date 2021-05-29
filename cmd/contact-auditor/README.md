# Contact-Auditor
Audits subscriber registrations for e-mail addresses that
`notify-mailer` is currently configured to skip.

# Usage:

```shell
  -config string
      File containing a JSON config.
  -grace duration
      Include contacts of subscribers with certificates that expired <grace>
       period from now (default 48h0m0s)
```

## Example output:

**Successful run with no violations encountered:**

```
I004823 contact-auditor nfWK_gM Running contact-auditor with a grace period of >= 48h0m0s
I004823 contact-auditor qJ_zsQ4 Beginning database query
I004823 contact-auditor je7V9QM Query completed successfully
I004823 contact-auditor 7LzGvQI Audit finished successfully
```

**Contact JSON is valid but contains entries that are malformed or violate policy:**

```
I004823 contact-auditor nfWK_gM Running contact-auditor with a grace period of >= 48h0m0s
I004823 contact-auditor qJ_zsQ4 Beginning database query
I004823 contact-auditor je7V9QM Query completed successfully
I004823 contact-auditor 1JX1rQ8 Validation failed for ID: 100 due to: [ "<contact entry>": "<reason>" ] [ "<contact entry>": "<reason>" ] ...
...
I004823 contact-auditor 2fv7-QY Audit finished successfully
```

**Contact is not valid JSON:**

```
I004823 contact-auditor nfWK_gM Running contact-auditor with a grace period of >= 48h0m0s
I004823 contact-auditor qJ_zsQ4 Beginning database query
I004823 contact-auditor je7V9QM Query completed successfully
I004823 contact-auditor qJ_zsQ4 Unmarshal failed for ID: 100 due to: <error msg>
...
I004823 contact-auditor 2fv7-QY Audit finished successfully
```

**Audit incomplete, query ended prematurely:**

```
I004823 contact-auditor nfWK_gM Running contact-auditor with a grace period of >= 48h0m0s
I004823 contact-auditor qJ_zsQ4 Beginning database query
I004823 contact-auditor ydTVgA4 [AUDIT] Query was interrupted due to: <error msg>
...
E004823 contact-auditor 8LmTgww [AUDIT] Audit was interrupted, results may be incomplete, see log for details
Audit was interrupted, results may be incomplete, see log for details
exit status 1
```

# Configuration file:
The path to a database config file like the one below must be provided
following the `-config` flag.

```json
{
    "contactAuditor": {
      "passwordFile": "path/to/secretFile",
      "db": {
        "dbConnectFile": "path/to/secretFile",
        "maxOpenConns": 10
      }
    }
  }
  
```
