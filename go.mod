module github.com/letsencrypt/boulder

go 1.12

require (
	github.com/beeker1121/goque v0.0.0-20170321141813-4044bc29b280
	github.com/cloudflare/cfssl v1.4.2-0.20200324225241-abef926615f4
	github.com/eggsampler/acme/v3 v3.0.0
	github.com/go-gorp/gorp/v3 v3.0.2
	github.com/go-sql-driver/mysql v1.5.0
	github.com/golang/mock v1.3.1
	github.com/golang/protobuf v1.4.0-rc.4.0.20200313231945-b860323f09d0
	github.com/golang/snappy v0.0.0-20170215233205-553a64147049 // indirect
	github.com/google/certificate-transparency-go v1.0.22-0.20181127102053-c25855a82c75
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/hpcloud/tail v1.0.0
	github.com/jmhodges/clock v0.0.0-20160418191101-880ee4c33548
	github.com/letsencrypt/challtestsrv v1.0.2
	github.com/letsencrypt/pkcs11key/v4 v4.0.0
	github.com/miekg/dns v1.1.30
	github.com/miekg/pkcs11 v1.0.3
	github.com/onsi/ginkgo v1.8.0 // indirect
	github.com/onsi/gomega v1.5.0 // indirect
	github.com/prometheus/client_golang v1.2.1
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4
	github.com/syndtr/goleveldb v0.0.0-20180331014930-714f901b98fd // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399
	github.com/weppos/publicsuffix-go v0.13.1-0.20200721065424-2c0d957a7459
	github.com/zmap/zcrypto v0.0.0-20191112190257-7f2fe6faf8cf
	github.com/zmap/zlint/v2 v2.1.0
	golang.org/x/crypto v0.0.0-20200124225646-8b5121be2f68
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	golang.org/x/text v0.3.3
	google.golang.org/grpc v1.29.0
	google.golang.org/protobuf v1.21.0
	gopkg.in/square/go-jose.v2 v2.4.1
	gopkg.in/yaml.v2 v2.2.5
)
