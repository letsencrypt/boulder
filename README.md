# Boulder - An ACME CA

[![Build Status](https://travis-ci.org/letsencrypt/boulder.svg)](https://travis-ci.org/letsencrypt/boulder)
[![Coverage Status](https://coveralls.io/repos/letsencrypt/boulder/badge.svg)](https://coveralls.io/r/letsencrypt/boulder)

This is an implementation of an ACME-based CA. The [ACME protocol](https://github.com/ietf-wg-acme/acme/) allows the CA to automatically verify that an applicant for a certificate actually controls an identifier, and allows domain holders to issue and revoke certificates for their domains. Boulder is the software that runs [Let's Encrypt](https://letsencrypt.org).

## Contents

* [Overview](#overview)
* [Setting up Boulder](#setting-up-boulder)
  * [Development](#development)
  * [Working with Certbot](#working-with-certbot)
  * [Working with another ACME Client](#working-with-another-acme-client)
  * [Production](#production)
* [Contributing](#contributing)
* [License](#license)

## Overview

Boulder is divided into the following main components:

1. Web Front Ends (one per API version)
2. Registration Authority
3. Validation Authority
4. Certificate Authority
5. Storage Authority
6. Publisher
7. OCSP Updater
8. OCSP Responder

This component model lets us separate the function of the CA by security context.  The Web Front End, Validation Authority, and Publisher need access to the Internet, which puts them at greater risk of compromise.  The Registration Authority can live without Internet connectivity, but still needs to talk to the Web Front End and Validation Authority.  The Certificate Authority need only receive instructions from the Registration Authority. All components talk to the SA for storage, so lines indicating SA RPCs are not shown here.

```
                             +--------- OCSP Updater
                             |               |
                             v               |
                            CA -> Publisher  |
                             ^               |
                             |               v
       Subscriber -> WFE --> RA --> SA --> MariaDB
                             |               ^
Subscriber server <- VA <----+               |
                                             |
          Browser ------------------>  OCSP Responder

```

Internally, the logic of the system is based around five types of objects: accounts, authorizations, challenges, orders (for ACME v2) and certificates, mapping directly to the resources of the same name in ACME.

We run two Web Front Ends, one for each ACME API version. Only the front end components differentiate between API version. Requests from ACME clients result in new objects and changes to objects.  The Storage Authority maintains persistent copies of the current set of objects.

Objects are also passed from one component to another on change events.  For example, when a client provides a successful response to a validation challenge, it results in a change to the corresponding validation object.  The Validation Authority forwards the new validation object to the Storage Authority for storage, and to the Registration Authority for any updates to a related Authorization object.

Boulder uses gRPC for inter-component communication.  For components that you want to be remote, it is necessary to instantiate a "client" and "server" for that component.  The client implements the component's Go interface, while the server has the actual logic for the component. A high level overview for this communication model can be found in the [gRPC documentation](http://www.grpc.io/docs/).

The full details of how the various ACME operations happen in Boulder are laid out in [DESIGN.md](https://github.com/letsencrypt/boulder/blob/master/docs/DESIGN.md).

## Setting up Boulder

### Development

Boulder has a Dockerfile and uses Docker Compose to make it easy to install and set up all its dependencies. This is how the maintainers work on Boulder, and is our main recommended way to run it for development/experimentation. It is not suitable for use as a production environment.

While we aim to make Boulder easy to setup ACME client developers may find [Pebble](https://github.com/letsencrypt/pebble), a miniature version of Boulder, to be better suited for continuous integration and quick experimentation.

We recommend setting git's [fsckObjects setting](https://groups.google.com/forum/#!topic/binary-transparency/f-BI4o8HZW0/discussion) before getting a copy of Boulder to have better integrity guarantees for updates.

Make sure you have a local copy of Boulder in your [`$GOPATH`](https://golang.org/doc/code.html#GOPATH), and that you are in that directory:

    export GOPATH=~/gopath
    git clone https://github.com/letsencrypt/boulder/ $GOPATH/src/github.com/letsencrypt/boulder
    cd $GOPATH/src/github.com/letsencrypt/boulder

Additionally, make sure you have Docker Engine 1.10.0+ and Docker Compose 1.6.0+ installed. If you do not, you can follow Docker's [installation instructions](https://docs.docker.com/compose/install/).

We recommend having **at least 2GB of RAM** available on your Docker host. In practice using less RAM may result in the MariaDB container failing in non-obvious ways.

To start Boulder in a Docker container, run:

    docker-compose up

To run tests:

    docker-compose run --use-aliases boulder ./test.sh

To run a specific unittest:

    docker-compose run --use-aliases boulder go test ./ra

The configuration in docker-compose.yml mounts your `$GOPATH` on top of its own `$GOPATH` so you can edit code on your host and it will be immediately reflected inside the Docker containers run with docker-compose.

If docker-compose fails with an error message like "Cannot start service boulder: oci runtime error: no such file or directory" or "Cannot create container for service boulder" you should double check that your `$GOPATH` exists and doesn't contain any characters other than letters, numbers, `-` and `_`, and that it doesn't contain any dangling symlinks.

If you have problems with Docker, you may want to try [removing all containers and volumes](https://www.digitalocean.com/community/tutorials/how-to-remove-docker-images-containers-and-volumes).

By default, Boulder uses a fake DNS resolver that resolves all hostnames to 127.0.0.1. This is suitable for running integration tests inside the Docker container. If you want Boulder to be able to communicate with a client running on your host instead, you should find your host's Docker IP with:

    ifconfig docker0 | grep "inet addr:" | cut -d: -f2 | awk '{ print $1}'

And edit docker-compose.yml to change the FAKE_DNS environment variable to match. This will cause Boulder to use the local system resolver available on your host if one is available.

Alternatively, you can override the docker-compose.yml default with an environmental variable using -e (replace 172.17.0.1 with the host IPv4 address found in the command above)

    docker-compose run --use-aliases -e FAKE_DNS=172.17.0.1 --service-ports boulder ./start.py

Boulder's default VA configuration (`test/config/va.json`) is configured to connect to port 5002 to validate HTTP-01 challenges and port 5001 to validate TLS-SNI-01/TLS-ALPN-01 challenges. If you want to solve challenges with a client running on your host you should make sure it uses these ports to respond to validation requests, or update the VA configuration's `portConfig` to use ports 80 and 443 to match how the VA operates in production and staging environments. If you use a host-based firewall (e.g. `ufw` or `iptables`) make sure you allow connections from the Docker instance to your host on the required ports.

If a base image changes (i.e. `letsencrypt/boulder-tools`) you will need to rebuild images for both the boulder and bhsm containers and re-create them. The quickest way to do this is with this command:

    ./docker-rebuild.sh


### Working with Certbot

Check out the Certbot client from https://github.com/certbot/certbot and follow their setup instructions. Once you've got the client set up, you'll probably want to run it against your local Boulder. There are a number of command line flags that are necessary to run the client against a local Boulder, and without root access. The simplest way to run the client locally is to source a file that provides an alias for certbot (`certbot_test`) that has all those flags:

    source ~/certbot/tests/integration/_common.sh
    certbot_test certonly -a standalone -d example.com

Your local Boulder instance uses a fake DNS resolver that returns 127.0.0.1 for any query, so you can use any value for the -d flag. If you want to use another DNS resolver you can by setting the environment variable FAKE_DNS=1.2.3.4.

By default Certbot will connect to the ACME v2 API over HTTP. You can customize the `SERVER` environment variable with an alternative ACME directory URL if required.

### Working with another ACME Client

Once you have followed the Boulder development environment instructions and have
started the containers you will find the ACME endpoints exposed to your host at
the following URLs:

* ACME v1, HTTP: `http://localhost:4000/directory`
* ACME v2, HTTP: `http://localhost:4001/directory`
* ACME v1, HTTPS: `https://localhost:4430/directory`
* ACME v2, HTTPS: `https://localhost:4431/directory`

To access the HTTPS versions of the endpoints you will need to configure your ACME client software to use a CA truststore that contains the `test/wfe-tls/minica.pem` CA certificate. See [the `test/wfe-tls` README](https://github.com/letsencrypt/boulder/master/test/wfe-tls/README) for more information.

Your local Boulder instance uses a fake DNS resolver that returns 127.0.0.1 for any query, allowing you to issue certificates for any domain as if it resolved to your localhost. If you want to use another DNS resolver you can by setting the environment variable FAKE_DNS=1.2.3.4.

Most often you will want to configure FAKE_DNS to point to your host machine where you run an ACME client. Remember to also configure the ACME client to use ports 5002 and 5001 instead of 80 and 443 for HTTP-01 and TLS-ALPN-01 challenge servers (or customize the Boulder VA configuration to match your port choices).

### Production

Boulder is custom built for Let's Encrypt and is intended only to support the
Web PKI and the CA/Browser forum's baseline requirements. In our experience
often Boulder is not the right fit for organizations that are evaluating it for
production usage. In most cases a centrally managed PKI that doesn't require
domain-authorization with ACME is a better choice. For this environment we
recommend evaluating [cfssl](https://github.com/cloudflare/cfssl) or a project
other than Boulder.

We offer a brief [deployment and implementation
guide](https://github.com/letsencrypt/boulder/wiki/Deployment-&-Implementation-Guide)
that describes some of the required work and security considerations involved in
using Boulder in a production environment. As-is the docker based Boulder development environment is **not suitable for
production usage**. It uses private key material that is publicly available,
exposes debug ports and is brittle to component failure.

While we are supportive of other organization's deploying Boulder in
a production setting we prioritize support and development work that favors
Let's Encrypt's mission. This means we may not be able to provide timely support
or accept pull-requests that deviate significantly from our first line goals. We
will try our best to engage with folks who have done their homework and need
a helping hand.

## Contributing

Please take a look at
[CONTRIBUTING.md](https://github.com/letsencrypt/boulder/blob/master/CONTRIBUTING.md)
for our guidelines on submitting patches, code review process, code of conduct,
and various other tips related to working on the codebase.

## License

This project is licensed under the Mozilla Public License 2.0, the full text of which can be found in the [LICENSE.txt](https://github.com/letsencrypt/boulder/blob/master/LICENSE.txt) file.
