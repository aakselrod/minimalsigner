package minimalsigner

import (
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/keychain"
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
	cfg *Config

	// identityECDH is an ECDH capable wrapper for the private key used
	// to authenticate any incoming connections.
	identityECDH keychain.SingleKeyECDH

	// identityKeyLoc is the key locator for the above wrapped identity key.
	identityKeyLoc keychain.KeyLocator

	// nodeSigner is an implementation of the MessageSigner implementation
	// that's backed by the identity private key of the running lnd node.
	nodeSigner keychain.SingleKeyMessageSigner

	// keyRing is a SecretKeyRing backed by the seed passed in from the
	// environment.
	keyRing keychain.SecretKeyRing

	// macRootKey is a macaroon root key used by the macaroon service.
	macRootKey []byte
}

// newServer creates a new instance of the server which is to listen using the
// passed listener address.
func newServer(cfg *Config, keyRing keychain.SecretKeyRing,
	nodeKeyDesc *keychain.KeyDescriptor) *server {

	var (
		nodeKeyECDH = keychain.NewPubKeyECDH(*nodeKeyDesc, keyRing)

		// We just derived the full descriptor, so we know the public
		// key is set on it.
		nodeKeySigner = keychain.NewPubKeyMessageSigner(
			nodeKeyDesc.PubKey, nodeKeyDesc.KeyLocator, keyRing,
		)
	)

	var serializedPubKey [33]byte
	copy(serializedPubKey[:], nodeKeyDesc.PubKey.SerializeCompressed())

	s := &server{
		cfg: cfg,

		identityECDH:   nodeKeyECDH,
		identityKeyLoc: nodeKeyDesc.KeyLocator,
		nodeSigner:     nodeKeySigner,
		keyRing:        keyRing,
	}

	return s
}
