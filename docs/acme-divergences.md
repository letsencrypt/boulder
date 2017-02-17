# Boulder divergences from ACME

While Boulder attempts to implement the ACME specification as strictly as possible there are places at which we will diverge from the letter of the specification for various reasons.

This document details these differences, since ACME is not yet finalized it will be updated as numbered drafts are published.

Current draft: [`draft-ietf-acme-acme-04`](https://tools.ietf.org/html/draft-ietf-acme-acme-04).

## [Section 5](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-5)

Boulder does not implement the [general JWS syntax](https://tools.ietf.org/html/rfc7515#page-20), but only accepts the [flattened syntax](https://tools.ietf.org/html/rfc7515#page-21).

## [Section 5.2](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-5.2)

Boulder enforces the presence of the `jwk` field in JWS objects, and does not support the `kid` field.

## [Section 5.4.1](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-5.4.1)

Boulder does not use the `url` field from the JWS protected resource. Instead Boulder will validate the `resource` field from the JWS payload matches the resource being requested. Boulder implements the resource types described in [draft-ietf-acme-02 Section 6.1](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.1) plus the additional "KeyChange" resource. Boulder verifies the `resource` field contains the `/directory` URI for the requested resource.

## [Section 5.6.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-5.6)

Boulder does not provide a `Retry-After` header when a user hits a rate-limit, nor does it provide `Link` headers to further documentation on rate-limiting.

## [Section 5.7.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-5.7)

Boulder doesn't return errors under the `urn:ietf:params:acme:error:` namespace but instead uses the `urn:acme:error:` namespace from [draft-ietf-acme-01 Section 5.4](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.4).

Boulder uses `invalidEmail` in place of the error `invalidContact` defined in [draft-ietf-acme-01 Section 5.4](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.4).

Boulder does not implement the `caa` and `dnssec` errors.

## [Section 6.1.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.1)

Boulder does not implement the `new-application` resource. Instead of `new-application` Boulder implements the `new-cert` resource that is defined in [draft-ietf-acme-02 Section 6.5](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.5). Boulder also doesn't implement the `new-nonce` endpoint.

## [Section 6.1.1.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.1.1)

Boulder does not implement the `meta` field returned by the `directory` endpoint.

## [Section 6.1.2.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.1.2)

Boulder does not implement the `terms-of-service-agreed` or `applications` fields in the registration object (nor the endpoints the latter links to).

## [Section 6.1.3.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.1.3)

Boulder does not implement applications, instead it implements the `new-cert` flow from [draft-ietf-acme-02 Section 6.5](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.5). Instead of application requirements Boulder currently uses authorizations that are created using the `new-authz` flow from [draft-ietf-acme-02 Section 6.4](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.4).

## [Section 6.1.4.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.1.4)

Boulder does not implement the `scope` field in authorization objects.

## [Section 6.2.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.2)

Boulder doesn't implement the `new-nonce` endpoint, instead it responds to `HEAD` requests with a valid `Replay-Nonce` header per [draft-ietf-acme-03 Section 5.4](https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-5.4).

## [Section 6.3.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.3)

Boulder only allows `mailto` URIs in the registrations `contact` list.

Boulder uses a HTTP status code 409 (Conflict) response for an already existing registration instead of 200 (OK). Boulder returns the URI of the already existing registration in a `Location` header field instead of a `Content-Location` header field.

## [Section 6.3.2.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.3.2)

Boulder implements draft-04 style key roll-over with a few divergences. Since Boulder doesn't currently use the registration URL to identify users we do not check for that field in the JWS protected headers but do check for it in the inner payload. Boulder also requires the outer JWS payload contains the `"resource": "key-change"` field.

## [Section 6.4.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.4)

Boulder does not implement applications, instead it implements the `new-cert` flow from [draft-ietf-acme-02 Section 6.5](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.5). Instead of application requirements Boulder currently uses authorizations that are created using the `new-authz` flow from [draft-ietf-acme-02 Section 6.4](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.4). Certificates are not proactively issued, a user must request issuance via the `new-cert` endpoint instead of assuming a certificate will be created once all required authorizations are validated.

## [Section 6.4.1.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.4.1)

Boulder ignores the `existing` field in authorization request objects.

## [Section 7.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-7)

Boulder returns an `uri` instead of an `url` field in challenge objects.

## [Section 7.3.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-7.3)

Boulder implements `tls-sni-01` from [draft-ietf-acme-01 Section 7.3](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-7.3) instead of the `tls-sni-02` validation method.

## [Section 7.5.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-7.5)

Boulder does not implement the `oob-01` validation method.

## [Section 8.5.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-8.5)

Boulder uses the `urn:acme:` namespace from [draft-ietf-acme-01 Section 5.4](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.4) for errors instead of `urn:ietf:params:acme:`.
