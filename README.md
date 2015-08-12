Boulder - An ACME CA
====================

This is an initial implementation of an ACME-based CA. The [ACME protocol](https://github.com/letsencrypt/acme-spec/) allows the CA to automatically verify that an applicant for a certificate actually controls an identifier, and allows domain holders to issue and revoke certificates for their domains.


[![Build Status](https://travis-ci.org/letsencrypt/boulder.svg)](https://travis-ci.org/letsencrypt/boulder)
[![Coverage Status](https://coveralls.io/repos/letsencrypt/boulder/badge.svg)](https://coveralls.io/r/letsencrypt/boulder)

Docker
------

Boulder is available as a [Docker image from Quay.io](https://quay.io/repository/letsencrypt/boulder). The Docker image expects the `config.json` file to be located at `/boulder/config.json` within the container.

(Note: You can override the `config.json` location by specifying a different BOULDER_CONFIG environment variable, such as with `-e BOULDER_CONFIG=mypath/myfile.config`.)

There are no default commands; you must choose one of the executables from the `cmd` path.

There are several tags available:
 - `stable` is maintained by the Let's Encrypt team as a fairly stable copy of Boulder.
 - `latest` is a more recent build of Boulder. It may lag behind the `master` ref, as automated builds are being reworked.
 - Tags for individual short-format git refs, representing those builds.


A quick-start method for running a Boulder instance is to use one of the example configurations:

    docker run -i --name=boulder --read-only=true --rm=true -p 4000:4000 quay.io/letsencrypt/boulder:latest


Alternatively, to run all services locally, using AMQP to pass messages between them, you can use:

```
> python start.py
# start.py will use the configuration specified by BOULDER_CONFIG or test/boulder-config.json
```

To run a single module, specifying the AMQP server, you might use something more like:

```
> docker run --name=boulder --read-only=true --rm=true -v $(pwd)/.boulder-config:/boulder:ro quay.io/letsencrypt/boulder:stable boulder-ra
```



Quickstart
----------

Install RabbitMQ from https://rabbitmq.com/download.html. It's required to run
tests.

Install libtool-ltdl dev libraries, which are required for Boulder's PKCS11
support.

Ubuntu:
`sudo apt-get install libltdl3-dev`

CentOS:
`sudo yum install libtool-ltdl-devel`

OS X:
`sudo port install libtool` or `brew install libtool`

(On OS X, using port, you will have to add `CGO_CFLAGS="-I/opt/local/include" CGO_LDFLAGS="-L/opt/local/lib"` to your environment or `go` invocations.)

```
> go get github.com/letsencrypt/boulder # Ignore errors about no buildable files
> cd $GOPATH/src/github.com/letsencrypt/boulder
# This starts each Boulder component with test configs. Ctrl-C kills all.
> python ./start.py
> cd test/js
> npm install
> nodejs test.js
> ./test.sh
```

You can also check out the official client from
https://github.com/letsencrypt/lets-encrypt-preview/ and follow the setup
instructions there.

Component Model
---------------

The CA is divided into the following main components:

1. Web Front End
2. Registration Authority
3. Validation Authority
4. Certificate Authority
5. Storage Authority

This component model lets us separate the function of the CA by security context.  The Web Front End and Validation Authority need access to the Internet, which puts them at greater risk of compromise.  The Registration Authority can live without Internet connectivity, but still needs to talk to the Web Front End and Validation Authority.  The Certificate Authority need only receive instructions from the Registration Authority.

```

client <--ACME--> WFE ---+
  .                      |
  .                      +--- RA --- CA
  .                      |
client <-checks->  VA ---+

```

In Boulder, these components are represented by Go interfaces.  This allows us to have two operational modes: Consolidated and distributed.  In consolidated mode, the objects representing the different components interact directly, through function calls.  In distributed mode, each component runs in a separate process (possibly on a separate machine), and sees the other components' methods by way of a messaging layer.

Internally, the logic of the system is based around two types of objects, authorizations and certificates, mapping directly to the resources of the same name in ACME.

Requests from ACME clients result in new objects and changes to objects.  The Storage Authority maintains persistent copies of the current set of objects.

Objects are also passed from one component to another on change events.  For example, when a client provides a successful response to a validation challenge, it results in a change to the corresponding validation object.  The Validation Authority forward the new validation object to the Storage Authority for storage, and to the Registration Authority for any updates to a related Authorization object.

Boulder supports distributed operation using AMQP as a message bus (e.g., via RabbitMQ).  For components that you want to be remote, it is necessary to instantiate a "client" and "server" for that component.  The client implements the component's Go interface, while the server has the actual logic for the component.  More details in `amqp-rpc.go`.

The full details of how the various ACME operations happen in Boulder are laid out in [DESIGN.md](https://github.com/letsencrypt/boulder/blob/master/DESIGN.md)


Dependencies
------------

All Go dependencies are vendorized under the Godeps directory,
both to [make dependency management
easier](https://groups.google.com/forum/m/#!topic/golang-dev/nMWoEAG55v8)
and to [avoid insecure fallback in go
get](https://github.com/golang/go/issues/9637).

Local development also requires a RabbitMQ installation and MariaDB
10 installation. MariaDB should be run on port 3306 for the
default integration tests.

To update the Go dependencies:

```
# Disable insecure fallback by blocking port 80.
sudo /sbin/iptables -A OUTPUT -p tcp --dport 80 -j DROP
# Fetch godep
go get -u https://github.com/tools/godep
# Update to the latest version of a dependency. Alternately you can cd to the
# directory under GOPATH and check out a specific revision. Here's an example
# using cfssl:
go get -u github.com/cloudflare/cfssl/...
# Update the Godep config to the appropriate version.
godep update github.com/cloudflare/cfssl/...
# Save the dependencies, rewriting any internal or external dependencies that
# may have been added.
godep save -r ./...
git add Godeps
git commit
# Assuming you had no other iptables rules, re-enable port 80.
sudo iptables -D OUTPUT 1
```


TODO
----

See [the issues list](https://github.com/letsencrypt/boulder/issues)
