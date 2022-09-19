package minimalsigner

import (
	"github.com/go-errors/errors"
)

var (
	// ErrServerShuttingDown indicates that the server is in the process of
	// gracefully exiting.
	ErrServerShuttingDown = errors.New("server is shutting down")
)

// server is the main server of the Lightning Network Daemon. The server houses
// global state pertaining to the wallet, database, and the rpcserver.
// Additionally, the server is also used as a central messaging bus to interact
// with any of its companion objects.
type server struct {
	// keyRing is a SecretKeyRing backed by the seed passed in from the
	// environment.
	keyRing *KeyRing
}

// newServer creates a new instance of the server which is to listen using the
// passed listener address.
func newServer(keyRing *KeyRing) *server {

	s := &server{
		keyRing: keyRing,
	}

	return s
}
