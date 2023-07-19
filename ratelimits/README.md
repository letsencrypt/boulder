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

Each override key represents a specific bucket, consisting of two elements:
_name_ and _id_. The name here refers to the Name of the particular limit, while
the id is a client identifier. The format of the id is dependent on the limit.
For example, the id for 'NewRegistrationsPerIPAddress' is a subscriber IP
address, while the id for 'NewOrdersPerAccount' is the subscriber's registration
ID.

```yaml
NewRegistrationsPerIPAddress:10.0.0.2:
  burst: 20
  count: 40
  period: 1s
NewOrdersPerAccount:12345678:
  burst: 300
  count: 600
  period: 180m
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
  - `NewRegistrationsPerIPAddress:10.0.0.1`
  - `NewRegistrationsPerIPAddress:2001:0db8:0000:0000:0000:ff00:0042:8329`

#### ipv6RangeCIDR

A valid IPv6 range in CIDR notation with a /48 mask. A /48 range is typically
assigned to a single subscriber.

Example: `NewRegistrationsPerIPv6Range:2001:0db8:0000::/48`

#### regId

The registration ID of the account.

Example: `NewOrdersPerAccount:12345678`

#### regId:domain

A combination of registration ID and domain, formatted 'regId:domain'.

Example: `CertificatesPerDomainPerAccount:12345678:example.com`

#### regId:fqdnSet

A combination of registration ID and a comma-separated list of domain names,
formatted 'regId:fqdnSet'.

Example: `CertificatesPerFQDNSetPerAccount:12345678:example.com,example.org`

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
actually keep track of the number of tokens in each bucket. Instead, we track
the Theoretical Arrival Time (TAT) at which the bucket will be full again. If
the TAT is in the past, the bucket is full. If the TAT is in the future, some
number of tokens have been spent and the bucket is slowly refilling. If the TAT
is far enough in the future (specifically, more than `burst * (period / count)`)
in the future), then the bucket is completely empty and requests will be denied.

Additional terminology:

  - **burst offset** is the duration of time it takes for a bucket to go from
    empty to full (`burst * (period / count)`).
  - **emission interval** is the interval at which tokens are added to a bucket
    (`period / count`). This is also the steady-state rate at which requests can
    be made without being denied even once the burst has been exhausted.
  - **cost** is the number of tokens removed from a bucket for a single request.
  - **cost increment** is the duration of time the TAT is advanced to account
    for the cost of the request (`cost * emission interval`).

For the purposes of this example, subscribers originating from a specific IPv4
address are allowed 20 requests to the newFoo endpoint per second, with a
maximum burst of 20 requests at any point-in-time, or:

```yaml
NewFoosPerIPAddress:172.23.45.22:
  burst: 20
  count: 20
  period: 1s
```

A subscriber calls the newFoo endpoint for the first time with an IP address of
172.23.45.22. Here's what happens:

1. The subscriber's IP address is used to generate a bucket key in the form of
   'NewFoosPerIPAddress:172.23.45.22'.

2. The request is approved and the 'NewFoosPerIPAddress:172.23.45.22' bucket is
   initialized with 19 tokens, as 1 token has been removed to account for the
   cost of the current request. To accomplish this, the initial TAT is set to
   the current time plus the _cost increment_ (which is 1/20th of a second if we
   are limiting to 20 requests per second).

3. Bucket 'NewFoosPerIPAddress:172.23.45.22':
    - will reset to full in 50ms (1/20th of a second),
    - will allow another newFoo request immediately,
    - will allow between 1 and 19 more requests in the next 50ms,
    - will reject the 20th request made in the next 50ms,
    - and will allow 1 request every 50ms, indefinitely.

The subscriber makes another request 5ms later:

4. The TAT at bucket key 'NewFoosPerIPAddress:172.23.45.22' is compared against
   the current time and the _burst offset_. The current time is greater than the
   TAT minus the cost increment. Therefore, the request is approved.

5. The TAT at bucket key 'NewFoosPerIPAddress:172.23.45.22' is advanced by the
   cost increment to account for the cost of the request.

The subscriber makes a total of 18 requests over the next 44ms:

6. The current time is less than the TAT at bucket key
   'NewFoosPerIPAddress:172.23.45.22' minus the burst offset, thus the request
   is rejected.

This mechanism allows for bursts of traffic but also ensures that the average
rate of requests stays within the prescribed limits over time.
