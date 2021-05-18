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

## Output:
When an invalid e-mail address is encountered an error log line will be
output in the following format:

```
validation failed for address: <e-mail> for ID: <ID> for reason: "<reason>"
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
