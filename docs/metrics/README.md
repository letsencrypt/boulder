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

* Logging (`cmd/boulder-*` + `cmd/ocsp-responder` + `cmd/ocsp-updater` + `cmd/admin-revoker`)

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

* RPC activity (`cmd/activity-monitor`)

    ```
	[counter] Boulder.RPC.Rate.Success
  [counter] Boulder.RPC.Rate.Error
	[counter] Boulder.RPC.Traffic

	[gauge]   Boulder.RPC.CallsWaiting

	[timing]  Boulder.RPC.ResponseTime.{RPC method name}
	```

* HTTP activity (`cmd/boulder-wfe` + `cmd/ocsp-responder`)

    ```
	[counter] Boulder.{WFE/OCSP}.HTTP.Rate

	[gauge]   Boulder.{WFE/OCSP}.HTTP.OpenConnections

	[timing]  Boulder.{WFE/OCSP}.HTTP.ResponseTime.{http endpoint}.Success
	[timing]  Boulder.{WFE/OCSP}.HTTP.ResponseTime.{http endpoint}.Error
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

	[timing]  Boulder.VA.DNS.RTT.TXT
	[timing]  Boulder.VA.DNS.RTT.CAA
	[timing]  Boulder.VA.DNS.RTT.CNAME

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
	[gauge]  Boulder.{cmd-name}.Gostats.Goroutines
	[gauge]  Boulder.{cmd-name}.Gostats.Heap.Objects
	[gauge]  Boulder.{cmd-name}.Gostats.Heap.Idle
	[gauge]  Boulder.{cmd-name}.Gostats.Heap.InUse
	[gauge]  Boulder.{cmd-name}.Gostats.Heap.Released
	[gauge]  Boulder.{cmd-name}.Gostats.Gc.NextAt

	[timing] Boulder.{cmd-name}.Gostats.Gc.PauseAvg
	```
