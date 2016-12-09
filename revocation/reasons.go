package revocation

// Reason is used to specify a certificate revocation reason
type Reason int

const (
	// Definitions for these codes can be found in Section 8.5.3.1 of ITU-T X.509
	// http://www.itu.int/rec/T-REC-X.509-201210-I/en
	Unspecified          = 0
	KeyCompromise        = 1
	CACompromise         = 2
	AffiliationChanged   = 3
	Superseded           = 4
	CessationOfOperation = 5
	CertificateHold      = 6
	// 7 is unused
	RemoveFromCRL      = 8
	PrivilegeWithdrawn = 9
	AACompromise       = 10
)

// RevocationReasons provides a map from reason code to string explaining the
// code
var ReasonToString = map[Reason]string{
	Unspecified:          "unspecified",
	KeyCompromise:        "keyCompromise",
	CACompromise:         "cACompromise",
	AffiliationChanged:   "affiliationChanged",
	Superseded:           "superseded",
	CessationOfOperation: "cessationOfOperation",
	CertificateHold:      "certificateHold",
	// 7 is unused
	RemoveFromCRL:      "removeFromCRL",
	PrivilegeWithdrawn: "privilegeWithdrawn",
	AACompromise:       "aAcompromise",
}

// UserAllowedReasons contains the subset of Reasons which users are
// allowed to use
var UserAllowedReasons = map[Reason]struct{}{
	Unspecified:          {}, // unspecified
	KeyCompromise:        {}, // keyCompromise
	AffiliationChanged:   {}, // affiliationChanged
	Superseded:           {}, // superseded
	CessationOfOperation: {}, // cessationOfOperation
}
