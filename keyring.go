package minimalsigner

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
)

// maxAccts is the number of accounts/key families to create on initialization.
const (
	maxAcctID      = 16
	nodeKeyAcct    = 6
	bip0043purpose = 1017
)

var (
	// PsbtKeyTypeInputSignatureTweakSingle is a custom/proprietary PSBT key
	// for an input that specifies what single tweak should be applied to
	// the key before signing the input. The value 51 is leet speak for
	// "si", short for "single".
	PsbtKeyTypeInputSignatureTweakSingle = []byte{0x51}

	// PsbtKeyTypeInputSignatureTweakDouble is a custom/proprietary PSBT key
	// for an input that specifies what double tweak should be applied to
	// the key before signing the input. The value d0 is leet speak for
	// "do", short for "double".
	PsbtKeyTypeInputSignatureTweakDouble = []byte{0xd0}
)

type KeyLocator struct {
	// Family is the family of key being identified.
	Family uint32

	// Index is the precise index of the key being identified.
	Index uint32
}

type KeyDescriptor struct {
	// KeyLocator is the internal KeyLocator of the descriptor.
	KeyLocator

	// PubKey is an optional public key that fully describes a target key.
	// If this is nil, the KeyLocator MUST NOT be empty.
	PubKey *btcec.PublicKey
}

type acct struct {
	xPub     *hdkeychain.ExtendedKey
	extXPriv *hdkeychain.ExtendedKey
}

// KeyRing is an HD keyring backed by pre-derived in-memory account keys from
// which index keys can be quickly derived on demand.
type KeyRing struct {
	coin  uint32
	accts map[uint32]acct
}

// NewKeyRing returns an in-memory key ring.
//
// TODO(aakselrod): zero seed bytes (?) and unneeded keys.
func NewKeyRing(seed []byte, net *chaincfg.Params) (*KeyRing, error) {
	rootKey, err := hdkeychain.NewMaster(seed, net)
	if err != nil {
		return nil, err
	}

	// Derive purpose.
	rootKey, err = rootKey.DeriveNonStandard(
		bip0043purpose + hdkeychain.HardenedKeyStart,
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
		coin:  net.HDCoinType,
		accts: make(map[uint32]acct),
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

		k.accts[act] = account

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

// DeriveKey attempts to derive an arbitrary key specified by the passed
// KeyLocator. This may be used in several recovery scenarios, or when manually
// rotating something like our current default node key.
func (k *KeyRing) DeriveKey(keyLoc KeyLocator) (KeyDescriptor, error) {
	var keyDesc KeyDescriptor
	keyDesc.KeyLocator = keyLoc

	privKey, err := k.DerivePrivKey(keyDesc)
	if err != nil {
		return KeyDescriptor{}, err
	}

	keyDesc.PubKey = privKey.PubKey()

	return keyDesc, nil
}

// DerivePrivKey attempts to derive the private key that corresponds to
// the passed key descriptor. It does not attempt to scan for a public key
// but only uses the key locator.
func (k *KeyRing) DerivePrivKey(keyDesc KeyDescriptor) (*btcec.PrivateKey,
	error) {

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
func (k *KeyRing) ECDH(keyDesc KeyDescriptor, pub *btcec.PublicKey) ([32]byte,
	error) {

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
func (k *KeyRing) SignMessage(keyLoc KeyLocator, msg []byte, doubleHash bool) (
	*ecdsa.Signature, error) {

	privKey, err := k.DerivePrivKey(KeyDescriptor{
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
func (k *KeyRing) SignMessageCompact(keyLoc KeyLocator, msg []byte,
	doubleHash bool) ([]byte, error) {

	privKey, err := k.DerivePrivKey(KeyDescriptor{
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
func (k *KeyRing) SignMessageSchnorr(keyLoc KeyLocator, msg []byte,
	doubleHash bool, taprootTweak []byte) (*schnorr.Signature, error) {
	privKey, err := k.DerivePrivKey(KeyDescriptor{
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

// SignPsbt signs all inputs in the PSBT that can be signed by our keyring.
// We have no state information, so we only attempt to derive the appropriate
// keys for each input and sign if we get a match.

func (k *KeyRing) SignPsbt(packet *psbt.Packet) ([]uint32, error) {
	// In signedInputs we return the indices of psbt inputs that were signed
	// by our wallet. This way the caller can check if any inputs were signed.
	var signedInputs []uint32

	// Let's check that this is actually something we can and want to sign.
	// We need at least one input and one output.
	err := psbt.VerifyInputOutputLen(packet, true, true)
	if err != nil {
		return nil, err
	}

	// Go through each input that doesn't have final witness data attached
	// to it already and try to sign it. If there is nothing more to sign or
	// there are inputs that we don't know how to sign, we won't return any
	// error. So it's possible we're not the final signer. We expect all
	// required UTXO data as part of the PSBT packet as we have no state.
	tx := packet.UnsignedTx
	prevOutputFetcher := psbtPrevOutputFetcher(packet)
	sigHashes := txscript.NewTxSigHashes(tx, prevOutputFetcher)
	for idx := range tx.TxIn {
		in := &packet.Inputs[idx]

		// We can only sign if we have UTXO information available. Since
		// we don't finalize, we just skip over any input that we know
		// we can't do anything with. Since we only support signing
		// witness inputs, we only look at the witness UTXO being set.
		if in.WitnessUtxo == nil {
			continue
		}

		// Skip this input if it's got final witness data attached.
		if len(in.FinalScriptWitness) > 0 {
			continue
		}

		// Skip this input if there is no BIP32 derivation info
		// available.
		if len(in.Bip32Derivation) == 0 {
			continue
		}

		// Let's try and derive the key now. This method will decide if
		// it's a BIP49/84 key for normal on-chain funds or a key of the
		// custom purpose 1017 key scope.
		derivationInfo := in.Bip32Derivation[0]
		privKey, err := k.deriveKeyByBIP32Path(derivationInfo.Bip32Path)
		if err != nil {
			signerLog.Warnf("SignPsbt: Skipping input %d, error "+
				"deriving signing key: %v", idx, err)
			continue
		}

		// We need to make sure we actually derived the key that was
		// expected to be derived.
		pubKeysEqual := bytes.Equal(
			derivationInfo.PubKey,
			privKey.PubKey().SerializeCompressed(),
		)
		if !pubKeysEqual {
			signerLog.Warnf("SignPsbt: Skipping input %d, derived "+
				"public key %x does not match bip32 "+
				"derivation info public key %x", idx,
				privKey.PubKey().SerializeCompressed(),
				derivationInfo.PubKey)
			continue
		}

		// Do we need to tweak anything? Single or double tweaks are
		// sent as custom/proprietary fields in the PSBT input section.
		privKey = maybeTweakPrivKeyPsbt(in.Unknowns, privKey)

		// What kind of signature is expected from us and do we have all
		// information we need?
		signMethod, err := validateSigningMethod(in)
		if err != nil {
			return nil, err
		}

		switch signMethod {
		// For p2wkh, np2wkh and p2wsh.
		case input.WitnessV0SignMethod:
			err = signSegWitV0(in, tx, sigHashes, idx, privKey)

		// For p2tr BIP0086 key spend only.
		case input.TaprootKeySpendBIP0086SignMethod:
			rootHash := make([]byte, 0)
			err = signSegWitV1KeySpend(
				in, tx, sigHashes, idx, privKey, rootHash,
			)

		// For p2tr with script commitment key spend path.
		case input.TaprootKeySpendSignMethod:
			rootHash := in.TaprootMerkleRoot
			err = signSegWitV1KeySpend(
				in, tx, sigHashes, idx, privKey, rootHash,
			)

		// For p2tr script spend path.
		case input.TaprootScriptSpendSignMethod:
			leafScript := in.TaprootLeafScript[0]
			leaf := txscript.TapLeaf{
				LeafVersion: leafScript.LeafVersion,
				Script:      leafScript.Script,
			}
			err = signSegWitV1ScriptSpend(
				in, tx, sigHashes, idx, privKey, leaf,
			)

		default:
			err = fmt.Errorf("unsupported signing method for "+
				"PSBT signing: %v", signMethod)
		}
		if err != nil {
			return nil, err
		}
		signedInputs = append(signedInputs, uint32(idx))
	}
	return signedInputs, nil
}

// deriveKeyByBIP32Path derives a key described by a BIP32 path. We expect the
// first three elements of the path to be hardened according to BIP44, so they
// must be a number >= 2^31.
func (k *KeyRing) deriveKeyByBIP32Path(path []uint32) (*btcec.PrivateKey,
	error) {

	// Make sure we get a full path with exactly 5 elements. A path is
	// either custom purpose one with 4 dynamic and one static elements:
	//    m/1017'/coinType'/keyFamily'/0/index
	// Or a default BIP49/89 one with 5 elements:
	//    m/purpose'/coinType'/account'/change/index
	const expectedDerivationPathDepth = 5
	if len(path) != expectedDerivationPathDepth {
		return nil, fmt.Errorf("invalid BIP32 derivation path, "+
			"expected path length %d, instead was %d",
			expectedDerivationPathDepth, len(path))
	}

	// Assert that the first three parts of the path are actually hardened
	// to avoid under-flowing the uint32 type.
	if err := assertHardened(path[0], path[1], path[2]); err != nil {
		return nil, fmt.Errorf("invalid BIP32 derivation path, "+
			"expected first three elements to be hardened: %w", err)
	}

	purpose := path[0] - hdkeychain.HardenedKeyStart
	coinType := path[1] - hdkeychain.HardenedKeyStart
	account := path[2] - hdkeychain.HardenedKeyStart
	change, index := path[3], path[4]

	// Is this a custom lnd internal purpose key?
	if purpose != bip0043purpose {
		return nil, fmt.Errorf("invalid BIP32 derivation path, "+
			"unknown purpose %d", purpose)
	}

	// Make sure it's for the same coin type as our wallet's keychain scope.
	if coinType != k.coin {
		return nil, fmt.Errorf("invalid BIP32 derivation "+
			"path, expected coin type %d, instead was %d",
			k.coin, coinType)
	}

	// We only use external, not change, addresses.
	if change != 0 {
		return nil, fmt.Errorf("change addresses not supported")
	}

	return k.DerivePrivKey(KeyDescriptor{
		KeyLocator: KeyLocator{
			Family: account,
			Index:  index,
		},
	})
}

// assertHardened makes sure each given element is >= 2^31.
func assertHardened(elements ...uint32) error {
	for idx, element := range elements {
		if element < hdkeychain.HardenedKeyStart {
			return fmt.Errorf("element at index %d is not hardened",
				idx)
		}
	}

	return nil
}

// signSegWitV0 attempts to generate a signature for a SegWit version 0 input
// and stores it in the PartialSigs (and FinalScriptSig for np2wkh addresses)
// field.
func signSegWitV0(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int,
	privKey *btcec.PrivateKey) error {

	pubKeyBytes := privKey.PubKey().SerializeCompressed()

	// Extract the correct witness and/or legacy scripts now, depending on
	// the type of input we sign. The txscript package has the peculiar
	// requirement that the PkScript of a P2PKH must be given as the witness
	// script in order for it to arrive at the correct sighash. That's why
	// we call it subScript here instead of witness script.
	subScript := prepareScriptsV0(in)

	// We have everything we need for signing the input now.
	sig, err := txscript.RawTxInWitnessSignature(
		tx, sigHashes, idx, in.WitnessUtxo.Value, subScript,
		in.SighashType, privKey,
	)
	if err != nil {
		return fmt.Errorf("error signing input %d: %v", idx, err)
	}
	in.PartialSigs = append(in.PartialSigs, &psbt.PartialSig{
		PubKey:    pubKeyBytes,
		Signature: sig,
	})

	return nil
}

// signSegWitV1KeySpend attempts to generate a signature for a SegWit version 1
// (p2tr) input and stores it in the TaprootKeySpendSig field.
func signSegWitV1KeySpend(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int, privKey *btcec.PrivateKey,
	tapscriptRootHash []byte) error {

	rawSig, err := txscript.RawTxInTaprootSignature(
		tx, sigHashes, idx, in.WitnessUtxo.Value,
		in.WitnessUtxo.PkScript, tapscriptRootHash, in.SighashType,
		privKey,
	)
	if err != nil {
		return fmt.Errorf("error signing taproot input %d: %v", idx,
			err)
	}

	in.TaprootKeySpendSig = rawSig

	return nil
}

// signSegWitV1ScriptSpend attempts to generate a signature for a SegWit version
// 1 (p2tr) input and stores it in the TaprootScriptSpendSig field.
func signSegWitV1ScriptSpend(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int, privKey *btcec.PrivateKey,
	leaf txscript.TapLeaf) error {

	rawSig, err := txscript.RawTxInTapscriptSignature(
		tx, sigHashes, idx, in.WitnessUtxo.Value,
		in.WitnessUtxo.PkScript, leaf, in.SighashType, privKey,
	)
	if err != nil {
		return fmt.Errorf("error signing taproot script input %d: %v",
			idx, err)
	}

	leafHash := leaf.TapHash()
	in.TaprootScriptSpendSig = append(
		in.TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: in.TaprootBip32Derivation[0].XOnlyPubKey,
			LeafHash:    leafHash[:],
			// We snip off the sighash flag from the end (if it was
			// specified in the first place.)
			Signature: rawSig[:schnorr.SignatureSize],
			SigHash:   in.SighashType,
		},
	)

	return nil
}

// prepareScriptsV0 returns the appropriate witness v0 and/or legacy scripts,
// depending on the type of input that should be signed.
func prepareScriptsV0(in *psbt.PInput) []byte {
	switch {
	// It's a NP2WKH input:
	case len(in.RedeemScript) > 0:
		return in.RedeemScript

	// It's a P2WSH input:
	case len(in.WitnessScript) > 0:
		return in.WitnessScript

	// It's a P2WKH input:
	default:
		return in.WitnessUtxo.PkScript
	}
}

// maybeTweakPrivKeyPsbt examines if there are any tweak parameters given in the
// custom/proprietary PSBT fields and may perform a mapping on the passed
// private key in order to utilize the tweaks, if populated.
func maybeTweakPrivKeyPsbt(unknowns []*psbt.Unknown,
	privKey *btcec.PrivateKey) *btcec.PrivateKey {

	// There can be other custom/unknown keys in a PSBT that we just ignore.
	// Key tweaking is optional and only one tweak (single _or_ double) can
	// ever be applied (at least for any use cases described in the BOLT
	// spec).
	for _, u := range unknowns {
		if bytes.Equal(u.Key, PsbtKeyTypeInputSignatureTweakSingle) {
			return input.TweakPrivKey(privKey, u.Value)
		}

		if bytes.Equal(u.Key, PsbtKeyTypeInputSignatureTweakDouble) {
			doubleTweakKey, _ := btcec.PrivKeyFromBytes(
				u.Value,
			)
			return input.DeriveRevocationPrivKey(
				privKey, doubleTweakKey,
			)
		}
	}

	return privKey
}

// validateSigningMethod attempts to detect the signing method that is required
// to sign for the given PSBT input and makes sure all information is available
// to do so.
func validateSigningMethod(in *psbt.PInput) (input.SignMethod, error) {
	script, err := txscript.ParsePkScript(in.WitnessUtxo.PkScript)
	if err != nil {
		return 0, fmt.Errorf("error detecting signing method, "+
			"couldn't parse pkScript: %v", err)
	}

	switch script.Class() {
	case txscript.WitnessV0PubKeyHashTy, txscript.ScriptHashTy,
		txscript.WitnessV0ScriptHashTy:

		return input.WitnessV0SignMethod, nil

	case txscript.WitnessV1TaprootTy:
		if len(in.TaprootBip32Derivation) == 0 {
			return 0, fmt.Errorf("cannot sign for taproot input " +
				"without taproot BIP0032 derivation info")
		}

		// Currently, we only support creating one signature per input.
		if len(in.TaprootBip32Derivation) > 1 {
			return 0, fmt.Errorf("unsupported multiple taproot " +
				"BIP0032 derivation info found, can only " +
				"sign for one at a time")
		}

		derivation := in.TaprootBip32Derivation[0]
		switch {
		// No leaf hashes means this is the internal key we're signing
		// with, so it's a key spend. And no merkle root means this is
		// a BIP0086 output we're signing for.
		case len(derivation.LeafHashes) == 0 &&
			len(in.TaprootMerkleRoot) == 0:

			return input.TaprootKeySpendBIP0086SignMethod, nil

		// A non-empty merkle root means we committed to a taproot hash
		// that we need to use in the tap tweak.
		case len(derivation.LeafHashes) == 0:
			// Getting here means the merkle root isn't empty, but
			// is it exactly the length we need?
			if len(in.TaprootMerkleRoot) != sha256.Size {
				return 0, fmt.Errorf("invalid taproot merkle "+
					"root length, got %d expected %d",
					len(in.TaprootMerkleRoot), sha256.Size)
			}

			return input.TaprootKeySpendSignMethod, nil

		// Currently, we only support signing for one leaf at a time.
		case len(derivation.LeafHashes) == 1:
			// If we're supposed to be signing for a leaf hash, we
			// also expect the leaf script that hashes to that hash
			// in the appropriate field.
			if len(in.TaprootLeafScript) != 1 {
				return 0, fmt.Errorf("specified leaf hash in " +
					"taproot BIP0032 derivation but " +
					"missing taproot leaf script")
			}

			leafScript := in.TaprootLeafScript[0]
			leaf := txscript.TapLeaf{
				LeafVersion: leafScript.LeafVersion,
				Script:      leafScript.Script,
			}
			leafHash := leaf.TapHash()
			if !bytes.Equal(leafHash[:], derivation.LeafHashes[0]) {
				return 0, fmt.Errorf("specified leaf hash in" +
					"taproot BIP0032 derivation but " +
					"corresponding taproot leaf script " +
					"was not found")
			}

			return input.TaprootScriptSpendSignMethod, nil

		default:
			return 0, fmt.Errorf("unsupported number of leaf " +
				"hashes in taproot BIP0032 derivation info, " +
				"can only sign for one at a time")
		}

	default:
		return 0, fmt.Errorf("unsupported script class for signing "+
			"PSBT: %v", script.Class())
	}
}

// SignSegWitV0 attempts to generate a signature for a SegWit version 0 input
// psbtPrevOutputFetcher returns a txscript.PrevOutFetcher built from the UTXO
// information in a PSBT packet.
func psbtPrevOutputFetcher(packet *psbt.Packet) *txscript.MultiPrevOutFetcher {
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for idx, txIn := range packet.UnsignedTx.TxIn {
		in := packet.Inputs[idx]

		// Skip any input that has no UTXO.
		if in.WitnessUtxo == nil && in.NonWitnessUtxo == nil {
			continue
		}

		if in.NonWitnessUtxo != nil {
			prevIndex := txIn.PreviousOutPoint.Index
			fetcher.AddPrevOut(
				txIn.PreviousOutPoint,
				in.NonWitnessUtxo.TxOut[prevIndex],
			)

			continue
		}

		// Fall back to witness UTXO only for older wallets.
		if in.WitnessUtxo != nil {
			fetcher.AddPrevOut(
				txIn.PreviousOutPoint, in.WitnessUtxo,
			)
		}
	}

	return fetcher
}

func (k *KeyRing) ListAccounts() []byte {
	acctList := "{\n    \"accounts\": [\n"

	strCoin := fmt.Sprintf("%d", k.coin)

	for act := uint32(0); act <= maxAcctID; act++ {
		account := k.accts[act]

		strAct := fmt.Sprintf("%d", act)

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
			strCoin + "'/" + strAct + "'\",\n"

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
