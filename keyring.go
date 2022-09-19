package minimalsigner

import (
	"crypto/sha256"
	"errors"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/keychain"
)

// maxAccts is the number of accounts/key families to create on initialization.
const maxAcctID = 16

type acct struct {
	xPub     *hdkeychain.ExtendedKey
	extXPriv *hdkeychain.ExtendedKey
}

// KeyRing is an implementation of the keychain.SecretKeyRing backed by
// in-memory keys.
type KeyRing struct {
	coin  string
	accts map[keychain.KeyFamily]acct
}

// NewKeyRing returns an in-memory key ring.
// TODO(aakselrod): zero seed bytes (?) and unneeded keys.
func NewKeyRing(seed []byte, net *chaincfg.Params) (*KeyRing, error) {
	rootKey, err := hdkeychain.NewMaster(seed, net)
	if err != nil {
		return nil, err
	}

	// Derive purpose.
	rootKey, err = rootKey.DeriveNonStandard(
		keychain.BIP0043Purpose + hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		return nil, err
	}

	// Derive coin.
	rootKey, err = rootKey.DeriveNonStandard(
		net.HDCoinType + hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		return nil, err
	}

	k := KeyRing{
		coin:  strconv.FormatUint(uint64(net.HDCoinType), 10),
		accts: make(map[keychain.KeyFamily]acct),
	}

	deriveAcct := func(act uint32) error {

		// Derive family/account.
		subKey, err := rootKey.DeriveNonStandard(
			act + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return err
		}

		// Get account watch-only pubkey.
		var account acct

		account.xPub, err = subKey.Neuter()
		if err != nil {
			return err
		}

		// Derive external branch only for faster derivation by index.
		account.extXPriv, err = subKey.DeriveNonStandard(0)
		if err != nil {
			return err
		}

		k.accts[keychain.KeyFamily(act)] = account

		return nil
	}

	// Populate Lightning-related families/accounts.
	for i := uint32(0); i <= maxAcctID; i++ {
		if err := deriveAcct(i); err != nil {
			return nil, err
		}
	}

	return &k, nil
}

// DeriveNextKey requires state to know what keys have already been derived.
// We don't support state (yet) 'round these parts.
//
// NOTE: This is part of the keychain.MessageSignerRing interface.
func (k *KeyRing) DeriveNextKey(keyFam keychain.KeyFamily) (
	keychain.KeyDescriptor, error) {

	// TODO(aakselrod): should this panic instead?
	return keychain.KeyDescriptor{},
		errors.New("DeriveNextKey unimplemented: requires state")
}

// DeriveKey attempts to derive an arbitrary key specified by the passed
// KeyLocator. This may be used in several recovery scenarios, or when manually
// rotating something like our current default node key.
//
// NOTE: This is part of the keychain.KeyRing interface.
func (k *KeyRing) DeriveKey(keyLoc keychain.KeyLocator) (
	keychain.KeyDescriptor, error) {

	var keyDesc keychain.KeyDescriptor
	keyDesc.KeyLocator = keyLoc

	privKey, err := k.DerivePrivKey(keyDesc)
	if err != nil {
		return keychain.KeyDescriptor{}, err
	}

	keyDesc.PubKey = privKey.PubKey()

	return keyDesc, nil
}

// DerivePrivKey attempts to derive the private key that corresponds to
// the passed key descriptor. It does not attempt to scan for a public key
// but only uses the key locator.
func (k *KeyRing) DerivePrivKey(keyDesc keychain.KeyDescriptor) (
	*btcec.PrivateKey, error) {

	key, ok := k.accts[keyDesc.Family]
	if !ok {
		return nil, errors.New("DerivePrivKey failed: account not found")
	}

	privKey, err := key.extXPriv.DeriveNonStandard(keyDesc.Index)
	if err != nil {
		return nil, err
	}

	// If we're looking for a specific pubkey, make sure the derived
	// pubkey matches it. Otherwise, the user is looking for us to scan
	// and we don't do that here.
	if keyDesc.PubKey != nil {
		pubKey, err := privKey.ECPubKey()
		if err != nil {
			return nil, err
		}

		if !keyDesc.PubKey.IsEqual(pubKey) {
			return nil, errors.New("DerivePrivKey failed: unsupported scan requested")
		}
	}

	return privKey.ECPrivKey()
}

// ECDH performs a scalar multiplication (ECDH-like operation) between the
// target key descriptor and remote public key. The output returned will be
// the sha256 of the resulting shared point serialized in compressed format. If
// k is our private key, and P is the public key, we perform the following
// operation:
//
//	sx := k*P s := sha256(sx.SerializeCompressed())
//
// NOTE: This is part of the keychain.ECDHRing interface.
func (k *KeyRing) ECDH(keyDesc keychain.KeyDescriptor,
	pub *btcec.PublicKey) ([32]byte, error) {

	privKey, err := k.DerivePrivKey(keyDesc)
	if err != nil {
		return [32]byte{}, err
	}

	var (
		pubJacobian btcec.JacobianPoint
		s           btcec.JacobianPoint
	)
	pub.AsJacobian(&pubJacobian)

	btcec.ScalarMultNonConst(&privKey.Key, &pubJacobian, &s)
	s.ToAffine()
	sPubKey := btcec.NewPublicKey(&s.X, &s.Y)
	h := sha256.Sum256(sPubKey.SerializeCompressed())

	return h, nil
}

// SignMessage signs the given message, single or double SHA256 hashing it
// first, with the private key described in the key locator.
//
// NOTE: This is part of the keychain.MessageSignerRing interface.
func (k *KeyRing) SignMessage(keyLoc keychain.KeyLocator,
	msg []byte, doubleHash bool) (*ecdsa.Signature, error) {

	privKey, err := k.DerivePrivKey(keychain.KeyDescriptor{
		KeyLocator: keyLoc,
	})
	if err != nil {
		return nil, err
	}

	var digest []byte
	if doubleHash {
		digest = chainhash.DoubleHashB(msg)
	} else {
		digest = chainhash.HashB(msg)
	}
	return ecdsa.Sign(privKey, digest), nil
}

// SignMessageCompact signs the given message, single or double SHA256 hashing
// it first, with the private key described in the key locator and returns
// the signature in the compact, public key recoverable format.
//
// NOTE: This is part of the keychain.MessageSignerRing interface.
func (k *KeyRing) SignMessageCompact(keyLoc keychain.KeyLocator, msg []byte,
	doubleHash bool) ([]byte, error) {

	privKey, err := k.DerivePrivKey(keychain.KeyDescriptor{
		KeyLocator: keyLoc,
	})
	if err != nil {
		return nil, err
	}

	var digest []byte
	if doubleHash {
		digest = chainhash.DoubleHashB(msg)
	} else {
		digest = chainhash.HashB(msg)
	}
	return ecdsa.SignCompact(privKey, digest, true)
}

// SignMessageSchnorr signs the given message, single or double SHA256
// hashing it first, with the private key described in the key locator
// and the optional Taproot tweak applied to the private key.
func (k *KeyRing) SignMessageSchnorr(keyLoc keychain.KeyLocator, msg []byte,
	doubleHash bool, taprootTweak []byte) (*schnorr.Signature, error) {
	privKey, err := k.DerivePrivKey(keychain.KeyDescriptor{
		KeyLocator: keyLoc,
	})
	if err != nil {
		return nil, err
	}

	if len(taprootTweak) > 0 {
		privKey = txscript.TweakTaprootPrivKey(privKey, taprootTweak)
	}

	var digest []byte
	if doubleHash {
		digest = chainhash.DoubleHashB(msg)
	} else {
		digest = chainhash.HashB(msg)
	}
	return schnorr.Sign(privKey, digest)
}

func (k *KeyRing) ListAccounts() []byte {
	acctList := "{\n    \"accounts\": [\n"

	for act := uint32(0); act <= maxAcctID; act++ {
		account := k.accts[keychain.KeyFamily(act)]

		strAct := strconv.FormatUint(uint64(act), 10)

		acctList += "        {\n"

		acctList += "            \"name\": \""
		if act == 0 {
			acctList += "default"
		} else {
			acctList += "act:" + strAct
		}
		acctList += "\",\n"

		acctList += "            \"address_type\": \"WITNESS_PUBKEY_HASH\",\n"

		acctList += "            \"extended_public_key\": \"" +
			account.xPub.String() + "\",\n"

		acctList += "            \"master_key_fingerprint\": null,\n"

		acctList += "            \"derivation_path\": \"m/1017'/" +
			k.coin + "'/" + strAct + "'\",\n"

		acctList += "            \"external_key_count\": 0,\n"

		acctList += "            \"internal_key_count\": 0,\n"

		acctList += "            \"watch_only\": false\n"

		acctList += "        }"

		if act < maxAcctID {
			acctList += ","
		}
		acctList += "\n"
	}

	acctList += "    ]\n}"

	return []byte(acctList)
}
