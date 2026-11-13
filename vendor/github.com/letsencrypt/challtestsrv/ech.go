package challtestsrv

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// newECHKey generates an ECH key whose config advertises the given public
// name, and returns it along with a serialized ECHConfigList containing only
// that config.
func newECHKey(publicName string) (tls.EncryptedClientHelloKey, []byte, error) {
	if len(publicName) == 0 || len(publicName) > 255 {
		return tls.EncryptedClientHelloKey{}, nil, errors.New("ECH public name must be 1 to 255 bytes")
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return tls.EncryptedClientHelloKey{}, nil, err
	}

	// This code is borrowed from marshalECHConfig, in upstream Go's tls_test.go
	// https://cs.opensource.google/go/go/+/master:src/crypto/tls/tls_test.go;l=2645;drc=a58ac9ec4a2fc8af8f7a8d77324c46d6246376ec
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(0xfe0d) // Version, the TLS extension number for Encrypted Client Hello
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddUint8(0)       // Config ID
		builder.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes(priv.PublicKey().Bytes())
		})
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddUint16(0x0001) // HKDF-SHA256
			builder.AddUint16(0x0001) // AES-128-GCM
		})
		builder.AddUint8(0) // No maximum name length
		builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes([]byte(publicName))
		})
		builder.AddUint16(0) // No extensions
	})
	config, err := builder.Bytes()
	if err != nil {
		return tls.EncryptedClientHelloKey{}, nil, err
	}

	builder = cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(config)
	})
	configList, err := builder.Bytes()
	if err != nil {
		return tls.EncryptedClientHelloKey{}, nil, err
	}

	key := tls.EncryptedClientHelloKey{
		Config:      config,
		PrivateKey:  priv.Bytes(),
		SendAsRetry: true,
	}
	return key, configList, nil
}

// ECHConfigList returns the serialized ECHConfigList, suitable for the "ech"
// SvcParam of an HTTPS record, accepted by the TLS-ALPN-01 and HTTPS HTTP-01
// servers. It returns nil if Config.ECHPublicName was not set. This is useful
// for integration tests which need to know what value to tell challtestsrv to
// set in an HTTPS record.
func (s *ChallSrv) ECHConfigList() []byte {
	return s.echConfigList
}
