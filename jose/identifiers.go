package jose

type JoseAlgorithm string

const (
	RSAPKCS1WithSHA256 = JoseAlgorithm("RS256")
	RSAPKCS1WithSHA384 = JoseAlgorithm("RS384")
	RSAPKCS1WithSHA512 = JoseAlgorithm("RS512")
	ECDSAWithSHA256    = JoseAlgorithm("ES256")
	ECDSAWithSHA384    = JoseAlgorithm("ES384")
	ECDSAWithSHA512    = JoseAlgorithm("ES512")
	RSAPSSWithSHA256   = JoseAlgorithm("PS256")
	RSAPSSWithSHA384   = JoseAlgorithm("PS384")
	RSAPSSWithSHA512   = JoseAlgorithm("PS512")
)

type JoseCurve string

const (
	CurveP256 = JoseCurve("P-256")
	CurveP384 = JoseCurve("P-384")
	CurveP512 = JoseCurve("P-512")
)

type JoseKeyType string

const (
	KeyTypeSymmetric = JoseKeyType("oct")
	KeyTypeRSA       = JoseKeyType("RSA")
	KeyTypeEC        = JoseKeyType("EC")
)
