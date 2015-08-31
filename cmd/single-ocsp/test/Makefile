single-ocsp: ../main.go
	go build ..

gentest: gentest.go
	go run gentest.go
	openssl verify -CAfile ca-cert.pem ee-cert.pem
	openssl verify -CAfile ca-cert.pem ocsp-cert.pem

ocsp-good.der: single-ocsp gentest template-good.json pkcs11.json
	./single-ocsp -issuer ca-cert.der \
		      -responder ocsp-cert.der \
		      -target ee-cert.der \
		      -template template-good.json \
		      -pkcs11 pkcs11.json \
		      -out ocsp-good.der

ocsp-revoked.der: single-ocsp gentest template-revoked.json pkcs11.json
	./single-ocsp -issuer ca-cert.der \
		      -responder ocsp-cert.der \
		      -target ee-cert.der \
		      -template template-revoked.json \
		      -pkcs11 pkcs11.json \
		      -out ocsp-revoked.der

test: ocsp-good.der ocsp-revoked.der
	openssl ocsp -respin ocsp-good.der -CAfile ca-cert.pem -resp_text | grep "Cert Status"
	openssl ocsp -respin ocsp-revoked.der -CAfile ca-cert.pem -resp_text | grep "Cert Status"

test-details: ocsp-good.der ocsp-revoked.der
	openssl ocsp -respin ocsp-good.der -CAfile ca-cert.pem -resp_text
	openssl ocsp -respin ocsp-revoked.der -CAfile ca-cert.pem -resp_text

clean:
	rm -f gentest
	rm -f single-ocsp
	rm -f *.der
	rm -f *.pem
