package vault

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/aakselrod/minimalsigner/keyring"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "lnd-nodes/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation:   b.listNodes,
				logical.UpdateOperation: b.createNode,
				logical.CreateOperation: b.createNode,
			},
			HelpSynopsis: "Create and list LND nodes",
			HelpDescription: `

LIST - list all node pubkeys
POST - generate a new node seed and store it indexed by node pubkey

`,
			Fields: map[string]*framework.FieldSchema{
				"network": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: "Network, one of " +
						"'mainnet', 'testnet', " +
						"'simnet', 'signet', or " +
						"'regtest'",
					Default: 1,
				},
			},
		},
		&framework.Path{
			Pattern: "lnd-nodes/sign/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.derivePubKey,
				logical.UpdateOperation: b.deriveAndSign,
				logical.CreateOperation: b.deriveAndSign,
			},
			HelpSynopsis: "Derive pubkeys and sign with privkeys",
			HelpDescription: `

GET  - return the pubkey derived with the submitted path
POST - sign a digest with the method specified using the privkey derived with
the submitted path

`,
			Fields: map[string]*framework.FieldSchema{
				"node": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: "node pubkey, must be " +
						"66 hex characters",
					Default: "",
				},
				"path": &framework.FieldSchema{
					Type: framework.TypeCommaIntSlice,
					Description: "derivation path, with " +
						"the first 3 elements " +
						"being hardened",
					Default: []int{},
				},
				"digest": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: "digest to sign, must " +
						"be hex-encoded 32 bytes",
					Default: "",
				},
				"method": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: "signing method: " +
						"one of: ecdsa, " +
						"ecdsa-compact, or schnorr",
					Default: "",
				},
				"pubkey": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: "optional: pubkey for " +
						"which to sign, checked " +
						"against derived pubkey to " +
						"ensure a match",
					Default: "",
				},
			},
		},
	}
}

func (b *backend) derivePubKey(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	strNode := data.Get("node").(string)

	seed, net, err := b.getNode(ctx, req.Storage, strNode)
	if err != nil {
		b.Logger().Error("Failed to retrieve node info",
			"node", strNode, "error", err)
		return nil, err
	}
	defer zero(seed)

	derivationPathInts := data.Get("path").([]int)
	derivationPath, err := sliceIntToUint32(derivationPathInts)
	if err != nil {
		b.Logger().Error("Failed to parse derivation path",
			"derivation_path", derivationPathInts, "error", err)
		return nil, err
	}

	pubKey, err := derivePubKey(seed, net, derivationPath)
	if err != nil {
		b.Logger().Error("Failed to derive pubkey",
			"node", strNode, "derivation_path", derivationPath,
			"error", err)
		return nil, err
	}

	pubKeyBytes, err := extKeyToPubBytes(pubKey)
	if err != nil {
		b.Logger().Error("derivePubKey: Failed to get pubkey bytes",
			"node", strNode, "derivation_path", derivationPath,
			"error", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"pubKey": hex.EncodeToString(pubKeyBytes),
		},
	}, nil
}

func (b *backend) deriveAndSign(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	strNode := data.Get("node").(string)

	seed, net, err := b.getNode(ctx, req.Storage, strNode)
	if err != nil {
		b.Logger().Error("Failed to retrieve node info",
			"node", strNode, "error", err)
		return nil, err
	}
	defer zero(seed)

	derivationPathInts := data.Get("path").([]int)
	derivationPath, err := sliceIntToUint32(derivationPathInts)
	if err != nil {
		b.Logger().Error("Failed to parse derivation path",
			"derivation_path", derivationPathInts, "error", err)
		return nil, err
	}

	privKey, err := derivePrivKey(seed, net, derivationPath)
	if err != nil {
		b.Logger().Error("Failed to derive privkey",
			"node", strNode, "derivation_path", derivationPath,
			"error", err)
		return nil, err
	}
	defer privKey.Zero()

	ecPrivKey, err := privKey.ECPrivKey()
	if err != nil {
		b.Logger().Error("Failed to derive valid ECDSA privkey",
			"node", strNode, "derivation_path", derivationPath,
			"error", err)
		return nil, err
	}
	defer ecPrivKey.Zero()

	pubKeyBytes, err := extKeyToPubBytes(privKey)
	if err != nil {
		b.Logger().Error("deriveAndSign: Failed to get pubkey bytes",
			"node", strNode, "derivation_path", derivationPath,
			"error", err)
		return nil, err
	}

	reqPubKey := data.Get("pubkey").(string)

	if reqPubKey != "" {
		reqPubBytes, err := hex.DecodeString(reqPubKey)
		if err != nil {
			b.Logger().Error("Failed to decode requested pubkey ",
				"hex", "error", err)
			return nil, err
		}

		// This is expected when we're checking if a PSBT input is ours
		// so the severity is just info.
		if !bytes.Equal(reqPubBytes, pubKeyBytes) {
			b.Logger().Info("Requested pubkey didn't match "+
				"derived pubkey", "requested", reqPubKey)
			return nil, errors.New("pubkey mismatch")
		}
	}

	digest := data.Get("digest").(string)
	if len(digest) != 64 {
		b.Logger().Error("Digest is not hex-encoded 32-byte value")
		return nil, errors.New("invalid digest")
	}

	digestBytes, err := hex.DecodeString(digest)
	if err != nil {
		b.Logger().Error("Failed to decode digest from hex",
			"error", err)
		return nil, err
	}

	var sigBytes []byte

	// TODO(aakselrod): check derivation paths are sane for the type of
	// signature we're requesting.
	signMethod := data.Get("method").(string)
	switch signMethod {
	case "ecdsa":
		sigBytes = ecdsa.Sign(ecPrivKey, digestBytes).Serialize()
	case "ecdsa-compact":
		sigBytes, _ = ecdsa.SignCompact(ecPrivKey, digestBytes, true)
	case "schnorr":
		sig, err := schnorr.Sign(ecPrivKey, digestBytes)
		if err != nil {
			b.Logger().Error("Failed to sign digest using Schnorr",
				"node", strNode,
				"derivation_path", derivationPath,
				"pubkey", reqPubKey, "error", err)
			return nil, err
		}

		sigBytes = sig.Serialize()
	default:
		b.Logger().Info("Requested invalid signing method",
			"method", signMethod)
		return nil, errors.New("invalid signing method")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hex.EncodeToString(sigBytes),
		},
	}, nil
}

func extKeyToPubBytes(key *hdkeychain.ExtendedKey) ([]byte, error) {
	ecPubKey, err := key.ECPubKey()
	if err != nil {
		return nil, err
	}

	return ecPubKey.SerializeCompressed(), nil
}

func (b *backend) getNode(ctx context.Context, storage logical.Storage,
	id string) ([]byte, *chaincfg.Params, error) {

	if len(id) != 2*btcec.PubKeyBytesLenCompressed {
		return nil, nil, errors.New("invalid node id")
	}

	nodePath := "lnd-nodes/" + id
	entry, err := storage.Get(ctx, nodePath)
	if err != nil {
		return nil, nil, err
	}

	if entry == nil {
		return nil, nil, errors.New("node not found")
	}

	if len(entry.Value) <= hdkeychain.RecommendedSeedLen {
		return nil, nil, errors.New("got invalid seed from storage")
	}

	net, err := getNet(string(entry.Value[hdkeychain.RecommendedSeedLen:]))
	if err != nil {
		return nil, nil, err
	}

	return entry.Value[:hdkeychain.RecommendedSeedLen], net, nil
}

func (b *backend) listNodes(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	vals, err := req.Storage.List(ctx, "lnd-nodes/")
	if err != nil {
		b.Logger().Error("Failed to retrieve the list of nodes",
			"error", err)
		return nil, err
	}

	return logical.ListResponse(vals), nil
}

func (b *backend) createNode(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	strNet := data.Get("network").(string)
	net, err := getNet(strNet)
	if err != nil {
		b.Logger().Error("Failed to parse network", "error", err)
		return nil, err
	}

	var seed []byte
	defer zero(seed)

	err = hdkeychain.ErrUnusableSeed
	for err == hdkeychain.ErrUnusableSeed {
		seed, err = hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	}
	if err != nil {
		b.Logger().Error("Failed to generate new LND seed",
			"error", err)
		return nil, err
	}

	nodePubKey, err := derivePubKey(seed, net, []uint32{
		keyring.Bip0043purpose + hdkeychain.HardenedKeyStart,
		net.HDCoinType + hdkeychain.HardenedKeyStart,
		keyring.NodeKeyAcct + hdkeychain.HardenedKeyStart,
		0,
		0,
	})
	if err != nil {
		b.Logger().Error("Failed to derive node pubkey from LND seed",
			"error", err)
		return nil, err
	}

	pubKeyBytes, err := extKeyToPubBytes(nodePubKey)
	if err != nil {
		b.Logger().Error("createNode: Failed to get pubkey bytes",
			"error", err)
		return nil, err
	}

	strPubKey := hex.EncodeToString(pubKeyBytes)
	nodePath := "lnd-nodes/" + strPubKey

	seed = append(seed, []byte(strNet)...)
	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:      nodePath,
		Value:    seed,
		SealWrap: true,
	})
	if err != nil {
		b.Logger().Error("Failed to save seed for node",
			"error", err)
		return nil, err
	}

	b.Logger().Info("Wrote new LND node seed", "pubkey", strPubKey)

	return &logical.Response{
		Data: map[string]interface{}{
			"nodePubKey": strPubKey,
		},
	}, nil
}

func getNet(strNet string) (*chaincfg.Params, error) {
	switch strNet {
	case "mainnet":
		return &chaincfg.MainNetParams, nil

	case "testnet":
		return &chaincfg.TestNet3Params, nil

	case "simnet":
		return &chaincfg.SimNetParams, nil

	case "signet":
		return &chaincfg.SigNetParams, nil

	case "regtest":
		return &chaincfg.RegressionNetParams, nil

	default:
		return nil, errors.New("invalid network specified: " + strNet)
	}
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

func derivePrivKey(seed []byte, net *chaincfg.Params,
	derivationPath []uint32) (*hdkeychain.ExtendedKey, error) {

	if len(derivationPath) != 5 {
		return nil, errors.New("derivation path not 5 elements")
	}

	err := assertHardened(derivationPath[:2]...)
	if err != nil {
		return nil, err
	}

	rootKey, err := hdkeychain.NewMaster(seed, net)
	if err != nil {
		return nil, err
	}
	defer rootKey.Zero()

	// Derive purpose.
	purposeKey, err := rootKey.DeriveNonStandard(
		derivationPath[0],
	)
	if err != nil {
		return nil, errors.New("error deriving purpose")
	}
	defer purposeKey.Zero()

	// Derive coin type.
	coinTypeKey, err := purposeKey.DeriveNonStandard(
		derivationPath[1],
	)
	if err != nil {
		return nil, errors.New("error deriving coin type")
	}
	defer coinTypeKey.Zero()

	// Derive account.
	accountKey, err := coinTypeKey.DeriveNonStandard(
		derivationPath[2],
	)
	if err != nil {
		return nil, errors.New("error deriving account")
	}
	defer accountKey.Zero()

	// Derive branch.
	branchKey, err := accountKey.DeriveNonStandard(derivationPath[3])
	if err != nil {
		return nil, errors.New("error deriving branch")
	}
	defer branchKey.Zero()

	// Derive index.
	indexKey, err := accountKey.DeriveNonStandard(derivationPath[4])
	if err != nil {
		return nil, errors.New("error deriving index")
	}

	return indexKey, nil
}

func derivePubKey(seed []byte, net *chaincfg.Params,
	derivationPath []uint32) (*hdkeychain.ExtendedKey, error) {

	privKey, err := derivePrivKey(seed, net, derivationPath)
	if err != nil {
		return nil, err
	}

	return privKey.Neuter()
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend,
	error) {

	var b backend
	b.Backend = &framework.Backend{
		Help:  "",
		Paths: framework.PathAppend(b.paths()),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"lnd-nodes/",
			},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}

	err := b.Setup(ctx, conf)
	if err != nil {
		return nil, err
	}

	return &b, nil
}

// sliceIntToUint32 converts a derivation path that's a slice of int to a slice
// of uint32 for use in deriving a key.
func sliceIntToUint32(ints []int) ([]uint32, error) {
	uints := make([]uint32, len(ints))

	for idx := range ints {
		if ints[idx] < 0 {
			return nil, errors.New("negative derivation path " +
				"element")
		}

		if ints[idx] > math.MaxUint32 {
			return nil, errors.New("derivation path element > " +
				"MaxUint32")
		}

		uints[idx] = uint32(ints[idx])
	}

	return uints, nil
}

// zero sets all bytes in the passed slice to zero.  This is used to
// explicitly clear private key material from memory.
func zero(b []byte) {
	lenb := len(b)
	for i := 0; i < lenb; i++ {
		b[i] = 0
	}
}
