package sagoodkey

import (
	"context"

	"github.com/letsencrypt/boulder/goodkey"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"google.golang.org/grpc"
)

// BlockedKeyCheckFunc is used to pass in the sa.BlockedKey method to KeyPolicy,
// rather than storing a full sa.SQLStorageAuthority. This makes testing
// significantly simpler.
type BlockedKeyCheckFunc func(context.Context, *sapb.KeyBlockedRequest, ...grpc.CallOption) (*sapb.Exists, error)

// NewKeyPolicy returns a KeyPolicy that uses a sa.BlockedKey method.
// See goodkey.NewKeyPolicy for more details about the policy itself.
func NewKeyPolicy(config *goodkey.Config, bkc BlockedKeyCheckFunc) (goodkey.KeyPolicy, error) {
	var genericCheck goodkey.BlockedKeyCheckFunc
	if bkc != nil {
		genericCheck = func(ctx context.Context, keyHash []byte) (bool, error) {
			exists, err := bkc(ctx, &sapb.KeyBlockedRequest{KeyHash: keyHash})
			if err != nil {
				return false, err
			}
			return exists.Exists, nil
		}
	}

	return goodkey.NewKeyPolicy(config, genericCheck)
}
