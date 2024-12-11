# Configuring and Storing Key-Value Rate Limits

## Rate Limit Structure

All rate limits use a token-bucket model. The metaphor is that each limit is
represented by a bucket which holds tokens. Each request removes some number of
tokens from the bucket, or is denied if there aren't enough tokens to remove.
Over time, new tokens are added to the bucket at a steady rate, until the bucket
is full. The _burst_ parameter of a rate limit indicates the maximum capacity of
a bucket: how many tokens can it hold before new ones stop being added.
Therefore, this also indicates how many requests can be made in a single burst
before a full bucket is completely emptied. The _count_ and _period_ parameters
indicate the rate at which new tokens are added to a bucket: every period, count
tokens will be added. Therefore, these also indicate the steady-state rate at
which a client which has exhausted its quota can make requests: one token every
(period / count) duration.

## Default Limit Settings

Each key directly corresponds to a `Name` enumeration as detailed in `//ratelimits/names.go`.
The `Name` enum is used to identify the particular limit. The parameters of a
default limit are the values that will be used for all buckets that do not have
an explicit override (see below).

```yaml
NewRegistrationsPerIPAddress:
  burst: 20
  count: 20
  period: 1s
NewOrdersPerAccount:
  burst: 300
  count: 300
  period: 180m
```

## Override Limit Settings

Each entry in the override list is a map, where the key is a limit name,
corresponding to the `Name` enum of the limit, and the value is a set of
overridden parameters. These parameters are applicable to a specific list of IDs
included in each entry. It's important that the formatting of these IDs matches
the ID format associated with their respective limit's `Name`. For more details on
the relationship of ID format to limit `Name`s, please refer to the documentation
of each `Name` in the `//ratelimits/names.go` file or the [ratelimits package
documentation](https://pkg.go.dev/github.com/letsencrypt/boulder/ratelimits#Name).

```yaml
- NewRegistrationsPerIPAddress:
    burst: 20
    count: 40
    period: 1s
    ids:
      - 10.0.0.2
      - 10.0.0.5
- NewOrdersPerAccount:
    burst: 300
    count: 600
    period: 180m
    ids:
      - 12345678
      - 87654321
```

The above example overrides the default limits for specific subscribers. In both
cases the count of requests per period are doubled, but the burst capacity is
explicitly configured to match the default rate limit.

### Id Formats in Limit Override Settings

Id formats vary based on the `Name` enumeration. Below are examples for each
format:

#### ipAddress

A valid IPv4 or IPv6 address.

Examples:
  - `10.0.0.1`
  - `2001:0db8:0000:0000:0000:ff00:0042:8329`

#### ipv6RangeCIDR

A valid IPv6 range in CIDR notation with a /48 mask. A /48 range is typically
assigned to a single subscriber.

Example: `2001:0db8:0000::/48`

#### regId

An ACME account registration ID.

Example: `12345678`

#### domain

A valid eTLD+1 domain name.

Example: `example.com`

#### fqdnSet

A comma-separated list of domain names.

Example: `example.com,example.org`

## Bucket Key Definitions

A bucket key is used to lookup the bucket for a given limit and
subscriber. Bucket keys are formatted similarly to the overrides but with a
slight difference: the limit Names do not carry the string form of each limit.
Instead, they apply the `Name` enum equivalent for every limit.

So, instead of:

```
NewOrdersPerAccount:12345678
```

The corresponding bucket key for regId 12345678 would look like this:

```
6:12345678
```

When loaded from a file, the keys for the default/override limits undergo the
same interning process as the aforementioned subscriber bucket keys. This
eliminates the need for redundant conversions when fetching each
default/override limit.

## How Limits are Applied

Although rate limit buckets are configured in terms of tokens, we do not
actually keep track of the number of tokens in each bucket, because that would
require constantly updating many buckets.

Instead, we use the [Generic Cell Rate Algorithm (GCRA)][GCRA]. "Cell" is a term
of art from the obsolete ATM networking standard, equivalent to a "request" for
us.  This algorithm is equivalent to the token bucket metaphor, but in
implementation it has the significant advantage that it only requires keeping
track of a single number which only increases when there are actual requests
being made, and never decreases[^1].

[GCRA]: https://en.wikipedia.org/wiki/Generic_cell_rate_algorithm)
[^1]: In the case of certain internal errors, we do "refund" limits, decreasing the TAT.

For each relevant key (e.g. requester id, registered domain, or IP address) we track
the Theoretical Arrival Time (TAT). It's the time the next request would arrive,
in the theoretical world where requests arrive at exactly the steady allowed
rate. The TAT can be either in the past or in the future.  When a request is accepted,
we increase the stored TAT.

A TAT in the past is equivalent to a TAT of "now".

If the TAT is "now" or somewhat in the future (by less than an tolerated burstiness τ
seconds), a request right now would also be accepted. If the TAT is more than τ seconds
in the future, a request right now would be rejected.

```
TAT: -------------------------^------------------------^-----------------
      accept and set to "now" |    accept (burst)      |      reject
                              |                        |
                             now                     now + τ
```

Additional terminology:

  - **emission period** is the period at which requests can be made without
    being denied even once the burst has been exhausted.
    Equal to `period / count`.
  - **tolerance** (τ) is how far in the future the TAT can be before a request
    is denied. Equal to `burst * (period / count)`.
  - **cost** for a specific request is a positive integer indicating how
    expensive a request is, with most requests having a cost of 1.
  - **cost increment** is the duration of time the TAT is advanced to account
    for the cost of the request (`cost * emission interval`).

For the purposes of this example, subscribers originating from a specific IPv4
address are allowed 20 requests to the newFoo endpoint per second, with a
maximum burst of 20 requests at any point-in-time, or:

```yaml
- NewFoosPerIPAddress:
    burst: 20
    count: 20
    period: 1s
    ids:
      - 172.23.45.22
```

A subscriber calls the newFoo endpoint for the first time with an IP address of
172.23.45.22. Here's what happens:

1. The subscriber's IP address is used to generate a bucket key in the form of
   'NewFoosPerIPAddress:172.23.45.22'.

2. The request is approved and the 'NewFoosPerIPAddress:172.23.45.22' bucket is
   initialized with a TAT of the current time (t₀) plus the _cost increment_. We
   happen to treat the request as having a cost of 1, and the _emission period_
   is 1/20th of a second, so the _cost increment_ is 1/20th of a second.

3. Bucket 'NewFoosPerIPAddress:172.23.45.22':
    - will allow another newFoo request immediately,
    - will allow 19 more requests in the next 50ms,
    - will reject the 20th request made in the next 50ms,
    - and will allow 1 request every 50ms, indefinitely.
    - will act like an uninitialized bucket (allowing the full 20 request burst)
      if 50ms pass with no more requests.

The subscriber makes another request 5ms later:

4. The TAT at bucket key 'NewFoosPerIPAddress:172.23.45.22' is compared against
   the current time and the _tolerance_ of 1000ms. The TAT is less than current
   time plus the tolerance. Therefore, the request is approved.

5. The TAT at bucket key 'NewFoosPerIPAddress:172.23.45.22' is again advanced by the
   _cost increment_ to account for the cost of the request.

The subscriber makes a total of 19 more requests over the next 44ms:

6. The TAT has now been advanced by the _cost increment_ a total of 21 times,
   for a total of 1050ms. The current time is t₀+49ms, and the TAT is
   t₀+1050ms.

The subscriber makes another request with no delay:

7. The current time plus the tolerance (1000ms) is t₀+1049ms. The TAT of t₀+1050
   is greater than that, so the request is denied. The TAT is not modified.

The subscriber makes another request 2ms later:

8. The current time plus the tolerance (1000ms) is t₀+1051 ms. The TAT of
   t₀+1050 is now _less_ than that, so the request is accepted and the TAT is
   increased by the _cost increment_ again.

The subscriber shuts down their server and takes a vacation. Two weeks later,
they boot it back up and make another request:

9. The TAT is less than the current time. If we simply increased the TAT by the
   _cost increment_, it would be as if the subscriber saved up a huge burst.
   Instead, we set the TAT to the current time plus the _cost increment_.

This mechanism allows for bursts of traffic but also ensures that the average
rate of requests stays within the prescribed limits over time.
