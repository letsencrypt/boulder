# Challenge Test Server

The `chal-test-srv` package offers a library/command that can be used by test
code to respond to HTTP-01 and DNS-01 ACME challenges.

## Install

`go install ./test/challsrv/...`

## Standalone `challsrv`

The standalone `challsrv` binary lets you run HTTP-01 and DNS-01 challenge
servers that external programs can add/remove challenge responses to using a
management HTTP API.

This is used by the Boulder integration tests to easily add/remove TXT records
for DNS-01 challenges for the `chisel.py` ACME client.

### Usage

```
Usage of challsrv:
  -dns01 string
       Comma separated bind addresses/ports for DNS-01 challenges and fake DNS data. Set empty to disable. (default ":8053")
  -http01 string
       Comma separated bind addresses/ports for HTTP-01 challenges. Set empty to disable. (default ":5002")
  -management string
       Bind address/port for management HTTP interface (default ":8056")
```

To disable a challenge type, set the bind address to `""`. E.g.:

* To run HTTP-01 only: `challsrv -dns01 ""`
* To run DNS-01 only: `chalsrv -http01 ""`

### Management Interface

_Note: These examples assume the default management interface of `:8056`_

Adding an HTTP-01 challenge response for the token `"aaaa"` with the content
`"bbbb"`:

    curl -X POST -d '{"token":"aaaa", "content":"bbbb"}' localhost:8056/add-http01

Deleting an HTTP-01 challenge response for the token `"aaaa"`:

    curl -X POST -d '{"token":"aaaa"}' localhost:8056/del-http01

Adding a DNS-01 TXT challenge for the host `"_acme-challenge.example.com."`
with the value `"bbbb"`:

    curl -X POST -d '{"host":"_acme-challenge.example.com.", "value":"bbbb"}' localhost:8056/set-txt

Deleting a DNS-01 TXT challenge for the host `"_acme-challenge.example.com."`:

    curl -X POST -d '{"host":"_acme-challenge.example.com."}' localhost:8056/clear-txt

## The `test/challsrv` package

The `test/challsrv` package can be used as a library by another program to
avoid needing to manage an external `challsrv` binary or use the HTTP based
management interface. This is used by the Boulder `load-generator` command to
manage its own in-process HTTP-01 challenge server.

### Usage

Create a challenge server responding to HTTP-01 challenges on ":8888" and
DNS-01 challenges on ":9999" and "10.0.0.1:9998":

```
  challSrv, err := challsrv.New(challsrv.Config{
    HTTPOneAddr: []string{":8888"},
    DNSOneAddr: []string{":9999", "10.0.0.1:9998"},
  })
  if err != nil {
    panic(err)
  }
```

Run the Challenge server:
```
  // Create a waitgroup that can be used to block until the challenge server has
  // cleanly shut down
  challSrvWg := new(sync.WaitGroup)
  challSrvWg.Add(1)
  // Start the Challenge server in its own Go routine
  go challSrv.Run(challSrvWg)
```

Add an HTTP-01 response for the token `"aaa"` and the value `"bbb"`, defer
cleaning it up again:
```
  challSrv.AddHTTPOneChallenge("aaa", "bbb")
  defer challSrv.DeleteHTTPOneChallenge("aaa")
```

Add a DNS-01 TXT response for the host `"_acme-challenge.example.com."` and the
value `"bbb"`, defer cleaning it up again:
```
  challSrv.AddDNSOneChallenge("_acme-challenge.example.com.", "bbb")
  defer challSrv.DeleteHTTPOneChallenge("_acme-challenge.example.com.")
```

Stop the Challenge server:
```
  // Send a Shutdown request to the challenge server
  s.challSrv.Shutdown()
  // Wait on the waitgroup we gave the challenge server when we called Run().
  // This will block until the challenge server is fully shut down.
  challSrvWg.Wait()
```
