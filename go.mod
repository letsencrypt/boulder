module github.com/letsencrypt/boulder

go 1.12

require (
	github.com/beeker1121/goque v1.0.3-0.20191103205551-d618510128af
	github.com/eggsampler/acme/v3 v3.0.0
	github.com/go-gorp/gorp/v3 v3.0.2
	github.com/go-redis/redis v6.15.9+incompatible // indirect
	github.com/go-redis/redis/v8 v8.11.4
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/certificate-transparency-go v1.0.22-0.20181127102053-c25855a82c75
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/honeycombio/beeline-go v1.1.1
	github.com/hpcloud/tail v1.0.0
	github.com/jmhodges/clock v0.0.0-20160418191101-880ee4c33548
	github.com/letsencrypt/challtestsrv v1.2.0
	github.com/letsencrypt/pkcs11key/v4 v4.0.0
	github.com/miekg/dns v1.1.30
	github.com/miekg/pkcs11 v1.0.3
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/client_model v0.2.0
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399
	github.com/weppos/publicsuffix-go v0.15.1-0.20211029155132-7594db4f858a
	github.com/zmap/zcrypto v0.0.0-20210811211718-6f9bc4aff20f
	github.com/zmap/zlint/v3 v3.3.1-0.20211019173530-cb17369b4628
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/net v0.0.0-20211029224645-99673261e6eb
	golang.org/x/text v0.3.6
	google.golang.org/grpc v1.36.1
	google.golang.org/protobuf v1.27.1
	gopkg.in/square/go-jose.v2 v2.4.1
	gopkg.in/yaml.v2 v2.4.0
)

// This version is required by parts of the honeycombio/beeline-go package
// that we do not rely upon. It appears to introduce performance regressions
// for us.
exclude github.com/go-sql-driver/mysql v1.6.0
