package vars

import "fmt"

const (
	dbURL = "%s@tcp(boulder-mysql:3306)/%s"
)

var (
	// DBConnPolicy is the policy database connection
	DBConnPolicy = fmt.Sprintf(dbURL, "policy", "boulder_policy_test")
	// DBConnPolicyIntegration is the policy integration database connection
	DBConnPolicyIntegration = fmt.Sprintf(dbURL, "policy", "boulder_policy_integration")
	// DBConnSA is the sa database connection
	DBConnSA = fmt.Sprintf(dbURL, "sa", "boulder_sa_test")
	// DBConnSAIntegration is the sa integration database connection
	DBConnSAIntegration = fmt.Sprintf(dbURL, "sa", "boulder_sa_integration")
	// DBConnSAMailer is the sa mailer database connection
	DBConnSAMailer = fmt.Sprintf(dbURL, "mailer", "boulder_sa_test")
	// DBConnSAFullPerms is the sa database connection with full perms
	DBConnSAFullPerms = fmt.Sprintf(dbURL, "test_setup", "boulder_sa_test")
	// DBConnSAOcspResp is the sa ocsp_resp database connection
	DBConnSAOcspResp = fmt.Sprintf(dbURL, "ocsp_resp", "boulder_sa_test")
)
