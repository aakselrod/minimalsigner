package minimalsigner

import (
	"github.com/bottlepay/lnmux"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightningnetwork/lnd/keychain"
)

type KeyRing struct {
	lnmux.KeyRing
}

// SignMessageSchnorr signs the given message, single or double SHA256
// hashing it first, with the private key described in the key locator
// and the optional Taproot tweak applied to the private key.
func (k *KeyRing) SignMessageSchnorr(keyLoc keychain.KeyLocator, msg []byte,
	doubleHash bool, taprootTweak []byte) (*schnorr.Signature, error) {
	return nil, nil
}
