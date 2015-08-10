package sa

import (
	"encoding/json"
	"fmt"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/core"
)

// regModel is the description of a core.Registration in the database.
type regModel struct {
	ID        int64           `db:"id"`
	Key       []byte          `db:"jwk"`
	KeySHA256 string          `db:"jwk_sha256"`
	Contact   []*core.AcmeURL `db:"contact"`
	Agreement string          `db:"agreement"`
	LockCol   int64
}

// newReg creates a reg model object from a core.Registration
func registrationToModel(r *core.Registration) (*regModel, error) {
	key, err := json.Marshal(r.Key)
	if err != nil {
		return nil, err
	}

	sha, err := core.KeyDigest(r.Key)
	if err != nil {
		return nil, err
	}
	rm := &regModel{
		ID:        r.ID,
		Key:       key,
		KeySHA256: sha,
		Contact:   r.Contact,
		Agreement: r.Agreement,
	}
	return rm, nil
}

func modelToRegistration(rm *regModel) (core.Registration, error) {
	k := &jose.JsonWebKey{}
	err := json.Unmarshal(rm.Key, k)
	if err != nil {
		err = fmt.Errorf("unable to unmarshal JsonWebKey in db: %s", err)
		return core.Registration{}, err
	}
	r := core.Registration{
		ID:        rm.ID,
		Key:       *k,
		Contact:   rm.Contact,
		Agreement: rm.Agreement,
	}
	return r, nil
}
