package all

import (
	// Import all default checks
	_ "github.com/globalsign/certlint/checks/certificate/aiaissuers"
	_ "github.com/globalsign/certlint/checks/certificate/basicconstraints"
	_ "github.com/globalsign/certlint/checks/certificate/extensions"
	_ "github.com/globalsign/certlint/checks/certificate/extkeyusage"
	_ "github.com/globalsign/certlint/checks/certificate/internal"
	_ "github.com/globalsign/certlint/checks/certificate/issuerdn"
	_ "github.com/globalsign/certlint/checks/certificate/keyusage"
	_ "github.com/globalsign/certlint/checks/certificate/publickey"
	_ "github.com/globalsign/certlint/checks/certificate/publicsuffix"
	_ "github.com/globalsign/certlint/checks/certificate/revocation"
	_ "github.com/globalsign/certlint/checks/certificate/serialnumber"
	_ "github.com/globalsign/certlint/checks/certificate/signaturealgorithm"
	_ "github.com/globalsign/certlint/checks/certificate/subject"
	_ "github.com/globalsign/certlint/checks/certificate/subjectaltname"
	_ "github.com/globalsign/certlint/checks/certificate/validity"
	_ "github.com/globalsign/certlint/checks/certificate/version"
	_ "github.com/globalsign/certlint/checks/certificate/wildcard"
)
