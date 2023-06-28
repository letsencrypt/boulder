# Configuring and Storing Key-Value Rate Limits

## Default Limit Settings

Each root key directly corresponds to a `Name` enumeration as detailed in
`name.go`. The `Name` enum is used to identify the particular limit. The `count`
value is used to determine the maximum number of requests allowed, within the
given `period` of time. The `burst` value is used to determine the maximum
number of requests allowed, at any given time.

```yaml
NewRegistrationsPerIPAddress:
  burst: 20
  count: 20
  period: 1s
NewRegistrationsPerIPv6Range:
  burst: 20
  count: 20
  period: 1s
NewOrdersPerAccount:
  burst: 300
  count: 300
  period: 180m
```

## Override Limit Settings

Each root key represents a specific bucket, consisting of two elements: `name`
and `id`. The `name` here refers to the `Name` of the particular limit, while
the `id` is the client's identifier. The format of the `id` is dependent on the
limit. For example, the `id` for 'NewRegistrationsPerIPAddress' is a subscriber
IP address, while the `id` for 'NewOrdersPerAccount' is the subscriber's
registration ID.

```yaml
NewRegistrationsPerIPAddress:10.0.0.2:
  burst: 40
  count: 40
  period: 1s
NewOrdersPerAccount:12345678
  burst: 600
  count: 600
  period: 180m
```

### Id Formats in Limit Override Settings

Id formats vary based on the 'Name' enumeration. Below are examples for each
format:

#### ipAddress

A valid IPv4 or IPv6 address.

Example: `NewRegistrationsPerIPAddress:10.0.0.1:`

#### ipv6RangeCIDR

A valid IPv6 range in CIDR notation with a /48 mask.

Example: `NewRegistrationsPerIPv6Range:2001:0db8:0000::/48:`

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

Bucket keys are the key used to lookup the bucket for a given limit and
subscriber. Bucket keys are formatted similarly to the overrides but with a
slight difference: the limit `Names` do not carry the string form of each limit.
Instead, they apply the Name enum equivalent for every limit.

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

For the purposes of this example, subscribers originating from a specific IPv4
address are allowed 20 requests to the newFoo endpoint per second, with a
maximum burst of 20 requests at any point-in-time.

A subscriber calls the newFoo endpoint for the first time with an IP address of
172.23.45.22. Here's what happens:

1. The subscriber's IP address is used to generate a bucket key in the form of
   `NewFoosPerIPAddress:172.23.45.22`. The Theoretical Arrival Time (TAT) for
   this bucket is set to the current time.

2. The subscriber's bucket is initialized with 19 tokens, as 1 token is removed
   to account for the current request. The request is approved, and the TAT is
   updated. The TAT is set to the current time, plus the inter-request time
   (which would be 1/20th of a second if we are limiting to 20 requests per
   second).

3. The subscriber is informated that their request was successful. Their bucket:
  - will reset to full in 50ms (1/20th of a second),
  - they can make another newFoo request immediately,
  - they can make 19 more requests in the next 50ms,
  - they do not need to wait between requests,
  - if they make 20 requests in the next 50ms they will need to wait 50ms before
    making another request,
  - if they wait 1s they can make 20 more requests,
  - thus if they make 1 request every 50ms, they will never be denied.

Now, the subscriber makes another request immediately:

4. The TAT at bucket key `NewFoosPerIPAddress:172.23.45.22` is compared against
   the current time and the burst offset. If the current time is less than the
   TAT minus the burst offset, this implies the request would surpass the rate
   limit and thus, it's rejected. If the current time is equal to or greater
   than the TAT minus the burst offset, the request is allowed.

5. A token is deducted from the subscriber's bucket and the TAT is updated
   similarly to the first request.

If the subscriber makes requests rapidly, causing the token count to hit 0
before 50ms has passed, here's what would happen during their next request:

6. The rate limiter checks the TAT. If the current time is less than (TAT -
   burst offset), the request is rejected. Since the subscriber has already
   exhausted their 20 requests in <50ms, the current time is indeed less than
   (TAT - burst offset). Therefore, the request is rejected to maintain the rate
   limit.

This mechanism allows for bursts of traffic but also ensures that the average
rate of requests stays within the prescribed limits over time.
