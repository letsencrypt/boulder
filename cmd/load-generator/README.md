# `load-generator`

![](https://i.imgur.com/58ZQjyH.gif)

`load-generator` is a load testing tool for the publicly facing boulder services,
unlike `ca-bench` which makes direct RPC calls to `boulder-ca`. It currently
provides generators for the WFE and the OCSP Responder, both of which make calls
(or in the case of the WFE new authorization action sequences of calls) asynchronously
in order to avoid back pressure at the generator.

_It's a work in progress._
