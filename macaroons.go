package minimalsigner

import (
	"context"
)

var defaultRootKeyID = []byte("0")

type assignedRootKeyStore struct {
	key []byte
}

func (s *assignedRootKeyStore) Get(ctx context.Context, id []byte) ([]byte,
	error) {

	return s.key, nil
}

func (s *assignedRootKeyStore) RootKey(ctx context.Context) ([]byte, []byte,
	error) {

	return s.key, defaultRootKeyID, nil
}

// check is a caveat checker. It does nothing for now, except a bit of logging.
func check(caveat string) error {
	signerLog.Tracef("checking caveat: %s", caveat)
	return nil
}
