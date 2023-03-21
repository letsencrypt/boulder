module github.com/letsencrypt/boulder

go 1.20

require (
	github.com/aws/aws-sdk-go-v2 v1.17.5
	github.com/aws/aws-sdk-go-v2/config v1.18.12
	github.com/aws/aws-sdk-go-v2/service/s3 v1.30.5
	github.com/aws/smithy-go v1.13.5
	github.com/beeker1121/goque v1.0.3-0.20191103205551-d618510128af
	github.com/eggsampler/acme/v3 v3.3.0
	github.com/go-gorp/gorp/v3 v3.1.0
	github.com/go-redis/redis/v8 v8.11.5
	github.com/go-sql-driver/mysql v1.5.0
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da
	github.com/google/certificate-transparency-go v1.0.22-0.20181127102053-c25855a82c75
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/hpcloud/tail v1.0.0
	github.com/jmhodges/clock v0.0.0-20160418191101-880ee4c33548
	github.com/letsencrypt/challtestsrv v1.2.1
	github.com/letsencrypt/pkcs11key/v4 v4.0.0
	github.com/miekg/dns v1.1.50
	github.com/miekg/pkcs11 v1.1.1
	github.com/prometheus/client_golang v1.14.0
	github.com/prometheus/client_model v0.3.0
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399
	github.com/weppos/publicsuffix-go v0.30.0
	github.com/zmap/zcrypto v0.0.0-20220402174210-599ec18ecbac
	github.com/zmap/zlint/v3 v3.4.0
	golang.org/x/crypto v0.1.0
	golang.org/x/exp v0.0.0-20230118134722-a68e582fa157
	golang.org/x/net v0.7.0
	golang.org/x/sync v0.1.0
	golang.org/x/term v0.6.0
	golang.org/x/text v0.8.0
	google.golang.org/grpc v1.53.0
	google.golang.org/protobuf v1.28.1
	gopkg.in/go-jose/go-jose.v2 v2.6.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.10 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.13.12 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.22 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.13.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.18.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.0-20180518054509-2e65f85255db // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/pelletier/go-toml v1.9.3 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/syndtr/goleveldb v1.0.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
)

// This version is required by parts of the honeycombio/beeline-go package
// that we do not rely upon. It appears to introduce performance regressions
// for us.
exclude github.com/go-sql-driver/mysql v1.6.0
