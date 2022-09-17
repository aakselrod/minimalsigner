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
