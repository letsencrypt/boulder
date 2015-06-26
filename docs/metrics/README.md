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

* Logging (`cmd/boulder-*` + `cmd/boulder` + `cmd/ocsp-responder` + `cmd/ocsp-updater` + `cmd/admin-revoker`)

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
	[counter] Boulder.RpcCalls
	[counter] Boulder.RpcTraffic

	[gauge]   Boulder.RpcCallsWaiting

	[timing]  Boulder.RpcResponseTime.{RPC method name}
	```

* HTTP activity (`cmd/boulder-wfe` + `cmd/boulder` + `cmd/ocsp-responder`)

    ```
	[gauge] Boulder.{cmd name}.HttpConnectionsOpen
	[counter] Boulder.{cmd name}.HttpRequests

	[timing]  Boulder.HttpResponseTime.{http endpoint}.Success
	[timing]  Boulder.HttpResponseTime.{http endpoint}.Error
    ```

*  HTTP errors (`cmd/boulder-wfe` + `cmd/boulder`)

    ```
	[counter] Boulder.HttpErrorCodes.{3 digit code}
	[counter] Boulder.HttpProblemTypes.{problem type}
    ```

* DNS activity (`cmd/boulder-va` + `cmd/boulder`)

    ```
	[timing]  Boulder.DnsRtt.A
	[timing]  Boulder.DnsRtt.AAAA
	[timing]  Boulder.DnsRtt.TXT
	[timing]  Boulder.DnsRtt.CAA
	[timing]  Boulder.DnsRtt.CNAME
    ```

* Validation attempts (`cmd/boulder-va` + `cmd/boulder`)

    ```
	[timing]  Boulder.Validations.{challenge type}.{challenge status}
    ```

* Registration authority activity (`cmd/boulder-ra` + `cmd/boulder`)

    ```
	[counter] Boulder.NewRegistrations
	[counter] Boulder.NewPendingAuthorizations
	[counter] Boulder.NewCertificates
	[counter] Boulder.UpdatedRegistrations
	[counter] Boulder.UpdatedPendingAuthorizations
	[counter] Boulder.RevokedCertificates
	[counter] Boulder.FinalizedAuthorizations
    ```

* Client performance profiling (`cmd/boulder-*` + `cmd/boulder`)

    ```
	[gauge]  Boulder.Gostats.{cmd-name}.Goroutines

	[gauge]  Boulder.Gostats.{cmd-name}.Heap.Objects
	[gauge]  Boulder.Gostats.{cmd-name}.Heap.Idle
	[gauge]  Boulder.Gostats.{cmd-name}.Heap.InUse
	[gauge]  Boulder.Gostats.{cmd-name}.Heap.Released

	[timing] Boulder.Gostats.{cmd-name}.Gc.PauseAvg
	[gauge]  Boulder.Gostats.{cmd-name}.Gc.NextAt
	```
