Boulder can provide various activity and performance metrics using StatsD if a server address is provided in the Boulder configuration file. This configuration object should look something like:

```
"statsd": {
      "server": "localhost:8125",
      "prefix": "Boulder"
}
```

The prefix will be prepended to all sent metrics to differentiate different sets of Boulder instances submitting metrics to the same StatsD server.

## List of collected metrics

This list is split up into metric topics with the names of the clients that submit these metrics.

* Logging (`cmd/boulder-*` + `cmd/ocsp-responder` + `cmd/ocsp-updater` + `cmd/admin-revoker`
  + `cmd/expiration-mailer` + `cmd/external-cert-importer`)

    ```
	[counter] Boulder.Logging.Audit
	[counter] Boulder.Logging.Alert
	[counter] Boulder.Logging.Crit
	[counter] Boulder.Logging.Debug
	[counter] Boulder.Logging.Emerg
	[counter] Boulder.Logging.Err
	[counter] Boulder.Logging.Info
	[counter] Boulder.Logging.Warning
	```

* RPC activity (all RPC servers/clients)

    ```
	[counter] Boulder.RPC.Rate.Success
  [counter] Boulder.RPC.Rate.Error
	[counter] Boulder.RPC.Traffic
	[counter] Boulder.RPC.Timeouts

	[gauge]   Boulder.RPC.CallsWaiting

	[timing]  Boulder.RPC.Latency.{RPC method name}
	```

* HTTP activity (`cmd/boulder-wfe` + `cmd/ocsp-responder`)

    ```
	[counter] Boulder.{WFE/OCSP}.HTTP.Rate

  [gauge]   Boulder.{WFE/OCSP}.HTTP.ConnectionsInFlight
	[gauge]   Boulder.{WFE/OCSP}.HTTP.OpenConnections

	[timing]  Boulder.{WFE/OCSP}.HTTP.ResponseTime.{http endpoint}
	[timing]  Boulder.{WFE/OCSP}.HTTP.ResponseTime.Failed
    ```

*  HTTP errors (`cmd/boulder-wfe`)

    ```
	[counter] Boulder.WFE.HTTP.ErrorCodes.{3 digit code}
	[counter] Boulder.WFE.HTTP.ProblemTypes.{problem type}
    ```

* DNS activity (`cmd/boulder-va` + `cmd/boulder-ra`)

    ```
    (VA)
	[counter] Boulder.VA.DNS.Rate

  [timing]  Boulder.VA.DNS.RTT.A
  [timing]  Boulder.VA.DNS.RTT.CAA
  [timing]  Boulder.VA.DNS.RTT.CNAME
  [timing]  Boulder.VA.DNS.RTT.TXT

    (RA)
  [counter] Boulder.RA.DNS.Rate

  [timing]  Boulder.RA.DNS.RTT.MX
    ```

* Validation attempts (`cmd/boulder-va`)

    ```
	[timing]  Boulder.VA.Validations.{challenge type}.{challenge status}
    ```

* Registration authority activity (`cmd/boulder-ra`)

    ```
	[counter] Boulder.RA.NewRegistrations
	[counter] Boulder.RA.NewPendingAuthorizations
	[counter] Boulder.RA.NewCertificates
	[counter] Boulder.RA.UpdatedRegistrations
	[counter] Boulder.RA.UpdatedPendingAuthorizations
	[counter] Boulder.RA.RevokedCertificates
	[counter] Boulder.RA.FinalizedAuthorizations
    ```

* Client performance profiling (`cmd/boulder-*`)

    ```
	[counter] Boulder.{cmd-name}.Gostats.Gc.Rate

	[gauge]   Boulder.{cmd-name}.Gostats.Goroutines
	[gauge]   Boulder.{cmd-name}.Gostats.Heap.Alloc
	[gauge]   Boulder.{cmd-name}.Gostats.Heap.Objects
	[gauge]   Boulder.{cmd-name}.Gostats.Heap.Idle
	[gauge]   Boulder.{cmd-name}.Gostats.Heap.InUse
	[gauge]   Boulder.{cmd-name}.Gostats.Heap.Released
	[gauge]   Boulder.{cmd-name}.Gostats.Gc.NextAt
	[gauge]   Boulder.{cmd-name}.Gostats.Gc.Count
	[gauge]   Boulder.{cmd-name}.Gostats.Gc.LastPause

	[timing]  Boulder.{cmd-name}.Gostats.Gc.PauseAvg
	  ```

* External certificate store loading (`cmd/external-cert-importer`)

    ```
  [counter] Boulder.ExistingCert.Certs.Imported
  [counter] Boulder.ExistingCert.Domains.Imported
  [counter] Boulder.ExistingCert.Removed

  [timing]  Boulder.ExistingCert.Certs.ImportLatency
  [timing]  Boulder.ExistingCert.Domains.ImportLatency
  [timing]  Boulder.ExistingCert.Certs.DeleteLatency
  [timing]  Boulder.ExistingCert.Domains.DeleteLatency
    ```

* OCSP response updating (`cmd/ocsp-updater`)

    ```
  [counter] Boulder.OCSP.Updates.Processed
  [counter] Boulder.OCSP.Updates.Failed
  [counter] Boulder.OCSP.Updates.BatchesProcessed

  [timing]  Boulder.OCSP.Updates.UpdateLatency
  [timing]  Boulder.OCSP.Updates.BatchLatency
    ```

* Certificate expiration mailing (`cmd/expiration-mailer`)

    ```
  [counter] Boulder.Mailer.Expiration.Sent
  [counter] Boulder.Mailer.Expiration.Errors.SendingNag.TemplateFailure
  [counter] Boulder.Mailer.Expiration.Errors.SendingNag.SendFailure
  [counter] Boulder.Mailer.Expiration.Errors.GetRegistration
  [counter] Boulder.Mailer.Expiration.Errors.ParseCertificate
  [counter] Boulder.Mailer.Expiration.Errors.UpdateCertificateStatus

  [timing]  Boulder.Mailer.Expiration.SendLatency
  [timing]  Boulder.Mailer.Expiration.ProcessingCertificatesLatency
    ```
