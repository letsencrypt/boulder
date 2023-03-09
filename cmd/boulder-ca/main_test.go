package notmain

import (
	"testing"

	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/test"
)

func Test_loadBoulderIssuers(t *testing.T) {
	type args struct {
		profileConfig issuance.ProfileConfig
		issuerConfigs []issuance.IssuerConfig
		ignoredLints  []string
	}
	tests := []struct {
		name    string
		args    args
		want    []*issuance.Issuer
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadBoulderIssuers(tt.args.profileConfig, tt.args.issuerConfigs, tt.args.ignoredLints)
			test.AssertNotError(t, err, "loadBoulderIssuers() error")
			test.AssertDeepEquals(t, got, tt.want)
		})
	}
}
