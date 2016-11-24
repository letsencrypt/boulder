# Boulder divergences from ACME

While Boulder attempts to implement the ACME specification as strictly as possible there are places at which we will diverge from the letter of the specification for various reasons.

This document details these differences, since ACME is not yet finalized it will be updated as numbered drafts are published.

Current draft: [`draft-ietf-acme-acme-04`](https://tools.ietf.org/html/draft-ietf-acme-acme-04).

## [Section 5.5.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-5.6)

Boulder does not provide a `Retry-After` header when a user hits a rate-limit, nor does it provide `Link` headers to further documentation on rate-limiting.

## [Section 5.6.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-5.7)

Boulder doesn't return errors under the `urn:ietf:params:acme:error:` namespace but instead uses the `urn:acme:error:` namespace from [draft-ietf-acme-01 Section 5.4](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.4).

Boulder uses `invalidEmail` in place of the error `invalidContact` defined in [draft-ietf-acme-01 Section 5.4](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.4).

Boulder does not implement the `caa` and `dnssec` errors.

## [Section 6.1.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.1)

Boulder does not implement the `new-application` resource. Instead of `new-application` Boulder implements the `new-cert` resource that is defined in [draft-ietf-acme-02 Section 6.5](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.5).

## [Section 6.1.1.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.1.1)

Boulder does not implement the `meta` field returned by the `directory` endpoint.

## [Section 6.1.2.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.1.2)

Boulder does not implement the `terms-of-service-agreed`, `applications`, or `certificates` fields
in the registration object (nor the endpoints the latter two link to).

## [Section 6.1.3.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.1.3)

Boulder does not implement applications, instead it implements the `new-cert` flow from [draft-ietf-acme-02 Section 6.5](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.5). Instead of application requirements Boulder currently uses authorizations that are created using the `new-authz` flow from [draft-ietf-acme-02 Section 6.4](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.4).

## [Section 6.1.4.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.1.4)

Boulder does not implement the `scope` field in authorization objects.

## [Section 6.2.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.3)

Boulder only allows `mailto` URIs in the registrations `contact` list.

## [Section 6.2.1.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.3.1)

Boulder implements draft-04 style key roll-over with a few divergences. Since Boulder doesn't currently use the registration URL to identify users we do not check for that field in the JWS protected headers but do check for it in the inner payload. Boulder also requires the outer JWS payload contains the `"resource": "key-change"` field.

## [Section 6.3.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-6.4)

Boulder does not implement applications, instead it implements the `new-cert` flow from [draft-ietf-acme-02 Section 6.5](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.5). Instead of application requirements Boulder currently uses authorizations that are created using the `new-authz` flow from [draft-ietf-acme-02 Section 6.4](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.4).

## [Section 7.3.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-7.3)

Boulder implements `tls-sni-01` from [draft-ietf-acme-01 Section 7.3](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-7.3) instead of the `tls-sni-02` validation method.

## [Section 7.5.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-7.5)

Boulder does not implement the `oob-01` validation method.

## [Section 8.5.](https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-8.5)

Boulder uses the `urn:acme:` namespace from [draft-ietf-acme-01 Section 5.4](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.4) for errors instead of `urn:ietf:params:acme:`.
