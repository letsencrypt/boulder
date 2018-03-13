package all

import (
	// Import all default extensions
	_ "github.com/globalsign/certlint/checks/extensions/adobetimestamp"
	_ "github.com/globalsign/certlint/checks/extensions/authorityinfoaccess"
	_ "github.com/globalsign/certlint/checks/extensions/authoritykeyid"
	_ "github.com/globalsign/certlint/checks/extensions/basicconstraints"
	_ "github.com/globalsign/certlint/checks/extensions/crldistributionpoints"
	_ "github.com/globalsign/certlint/checks/extensions/ct"
	_ "github.com/globalsign/certlint/checks/extensions/extkeyusage"
	_ "github.com/globalsign/certlint/checks/extensions/keyusage"
	_ "github.com/globalsign/certlint/checks/extensions/nameconstraints"
	_ "github.com/globalsign/certlint/checks/extensions/ocspnocheck"
	_ "github.com/globalsign/certlint/checks/extensions/pdfrevocation"
	_ "github.com/globalsign/certlint/checks/extensions/policyidentifiers"
	_ "github.com/globalsign/certlint/checks/extensions/smimecapabilities"
	_ "github.com/globalsign/certlint/checks/extensions/subjectaltname"
	_ "github.com/globalsign/certlint/checks/extensions/subjectkeyid"
)
