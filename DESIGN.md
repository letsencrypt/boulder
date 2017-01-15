# Boulder flow diagrams

Boulder is built in a rather decentralized way in order to enable different
parts to be deployed in different security contexts.

In order for you to understand how boulder works and ensure it's working correctly,
this document lays out how various operations flow through boulder.  We show a
diagram of how calls go between components, and provide notes on what each
component does to help the process along.  Each step is in its own subsection
below, in roughly the order that they happen in certificate issuance.

A couple of notes:

* For simplicity, we do not show interactions with the Storage Authority.
  The SA simply acts as a common data store for the various components.  It
  is written to by the RA (registrations and authorizations) and the CA
  (certificates), and read by WFE, RA, and CA.

* The interactions shown in the diagrams are the calls that go between
  components.  These calls are done via the AMQP-based RPC code in `./rpc/`.

* In various places the Boulder implementation of ACME diverges from the current
  RFC draft. These divergences are documented in [docs/acme-divergences.md](https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md).


## New Registration

```
1: Client ---new-reg--> WFE
2:                      WFE ---NewRegistration--> RA
3:                      WFE <-------return------- RA
4: Client <------------ WFE
```

Notes:

* 1-2: WFE does the following:
  * Verify that the request is a POST
  * Verify the JWS signature on the POST body
  * Parse the registration object
  * Filters illegal fields from the registration object

* 2-3: RA does the following:
  * Verify that the registered account key is acceptable
  * Create a new registration and add the client's information
  * Store the registration (which gives it an ID)
  * Return the registration as stored

* 3-4: WFE does the following:
  * Return the registration, with a unique URL


## Updated Registration

```
1: Client ---reg--> WFE
2:                  WFE ---UpdateRegistration--> RA
3:                  WFE <--------return--------- RA
4: Client <-------- WFE
```

* 1-2: WFE does the following:
  * Verify that the request is a POST
  * Verify the JWS signature on the POST body
  * Verify that the JWS signature is by a registered key
  * Verify that the JWS key matches the registration for the URL
  * Parse the registration object
  * Filter illegal fields from the registration object

* 2-3: RA does the following:
  * Merge the update into the existing registration
  * Store the updated registration
  * Return the updated registration

* 3-4: WFE does the following:
  * Return the updated registration

## New Authorization

```
1: Client ---new-authz--> WFE
2:                        WFE ---NewAuthorization--> RA
3:                        WFE <-------return-------- RA
4: Client <-------------- WFE
```

* 1-2: WFE does the following:
  * Verify that the request is a POST
  * Verify the JWS signature on the POST body
  * Verify that the JWS signature is by a registered key
  * Verify that the client has indicated agreement to terms
  * Parse the initial authorization object

* 2-3: RA does the following:
  * Verify that the requested identifier is allowed by policy
  * Create challenges as required by policy
  * Construct URIs for the challenges
  * Store the authorization

* 3-4: WFE does the following:
  * Return the authorization, with a unique URL



## Challenge Response

```
1: Client ---chal--> WFE
2:                   WFE ---UpdateAuthorization--> RA
3:                                                 RA ---PerformValidation--> VA
4: Client <~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~> VA
5:                                                 RA <-------return--------- VA
6:                   WFE <--------return---------- RA
7: Client <--------- WFE
```

* 1-2: WFE does the following:
  * Look up the referenced authorization object
  * Look up the referenced challenge within the authorization object
  * Verify that the request is a POST
  * Verify the JWS signature on the POST body
  * Verify that the JWS signature is by a registered key
  * Verify that the JWS key corresponds to the authorization
  * Verify that the client has indicated agreement to terms
  * Parse the challenge object (i.e., the response)

* 2-3: RA does the following:
  * Merge the response with the challenge in the authorization object
  * Store the updated authorization object

* 3-4: VA does the following:
  * Dispatch a goroutine to do validation

* 4-5: RA does the following:
  * Return the updated authorization object

* 5-6: WFE does the following:
  * Return the updated authorization object

* 7: VA does the following:
  * Validate domain control according to the challenge responded to
  * Notify the RA of the result

* 8-9: RA does the following:
  * Check that a sufficient set of challenges has been validated
  * Mark the authorization as valid or invalid
  * Store the updated authorization object


## Authorization Poll

```
1: Client ---authz--> WFE
2: Client <---------- WFE
```

* 1-2: WFE does the following:
  * Look up the referenced authorization
  * Verify that the request is a GET
  * Return the authorization object


## New Certificate

```
1: Client ---new-cert--> WFE
2:                       WFE ---NewCertificate--> RA
3:                                                RA ---IssueCertificate--> CA
5:                                                RA <------return--------- CA
5:                       WFE <------return------- RA
6: Client <------------- WFE
```

* 1-2: WFE does the following:
  * Verify that the request is a POST
  * Verify the JWS signature on the POST body
  * Verify that the JWS signature is by a registered key
  * Verify that the client has indicated agreement to terms
  * Parse the certificate request object

* 2-3: RA does the following:
  * Verify the PKCS#10 CSR in the certificate request object
  * Verify that the CSR has a non-zero number of domain names
  * Verify that the public key in the CSR is different from the account key
  * For each authorization referenced in the certificate request
    * Retrieve the authorization from the database
    * Verify that the authorization corresponds to the account key
    * Verify that the authorization is valid
    * Verify that the authorization is still valid
  * Verify that all domains in the CSR are covered by authorizations
  * Compute the earliest expiration date among the authorizations

* 3-4: CA does the following:
  * Verify that the public key in the CSR meets quality requirements
    * RSA only for the moment
    * Modulus >= 2048 bits and not divisible by small primes
    * Exponent > 2^16
  * Remove any duplicate names in the CSR
  * Verify that all names are allowed by policy (also checked at new-authz time)
  * Verify that the issued cert will not be valid longer than the CA cert
  * Verify that the issued cert will not be valid longer than the underlying authorizations
  * Open a CA DB transaction and allocate a new serial number
  * Create the first OCSP response
  * Sign the certificate and the first OCSP response with the CFSSL library

* 5-6: CA does the following:
  * Store the certificate
  * Commit the CA DB transaction if everything worked
  * ... otherwise return the serial number

* 6-7: RA does the following:
  * Log the success or failure of the request
  * Return the certificate object

* 7-8: WFE does the following:
  * Create a URL from the certificate's serial number
  * Return the certificate with its URL


## Revoke Certificate

```
1: Client ---cert--> WFE
2:                   WFE ---NewCertificate--> RA
3:                                            RA ---IssueCertificate--> CA
4:                                            RA <------return--------- CA
5:                   WFE <------return------- RA
6: Client <--------- WFE
```

* 1-2: WFE does the following:
  * Verify that the request is a POST
  * Verify the JWS signature on the POST body
  * Verify that the JWS signature is either:
    * The account key for the certificate, or
    * The public key from the certificate
  * Parse the certificate request object

* 3-4: CA does the following:
  * Sign an OCSP response indicating revoked status for this certificate
  * Store the OCSP response in the database

* 4-5: RA does the following:
  * Log the success or failure of the revocation

* 5-6: WFE does the following:
  * Return an indication of the success or failure of the revocation
