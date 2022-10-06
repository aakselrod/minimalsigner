package vault

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/aakselrod/minimalsigner/keyring"
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
	}
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
	err = hdkeychain.ErrUnusableSeed
	for err == hdkeychain.ErrUnusableSeed {
		seed, err = hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	}
	if err != nil {
		b.Logger().Error("Failed to generate new LND seed",
			"error", err)
		return nil, err
	}

	nodePrivKey, err := derivePrivKey(seed, net, [5]uint32{
		keyring.Bip0043purpose,
		net.HDCoinType,
		keyring.NodeKeyAcct,
		0,
		0,
	})
	if err != nil {
		b.Logger().Error("Failed to derive node privkey from LND seed",
			"error", err)
		return nil, err
	}
	defer nodePrivKey.Zero()

	pubKey, err := nodePrivKey.ECPubKey()
	if err != nil {
		b.Logger().Error("Failed to derive node pubkey from privkey",
			"error", err)
		return nil, err
	}

	strPubKey := hex.EncodeToString(pubKey.SerializeCompressed())
	if len(strPubKey) != 66 {
		b.Logger().Error("Failed to get hex of node pubkey")
		return nil, errors.New("Failed to get hex of node pubkey")
	}
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

func derivePrivKey(seed []byte, net *chaincfg.Params,
	derivationPath [5]uint32) (*hdkeychain.ExtendedKey, error) {

	rootKey, err := hdkeychain.NewMaster(seed, net)
	if err != nil {
		return nil, err
	}
	defer rootKey.Zero()

	// Derive purpose.
	if derivationPath[0] > hdkeychain.HardenedKeyStart {
		return nil, errors.New("purpose already hardened")
	}
	purposeKey, err := rootKey.DeriveNonStandard(
		derivationPath[0] + hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		return nil, errors.New("error deriving purpose")
	}
	defer purposeKey.Zero()

	// Derive coin type.
	if derivationPath[1] > hdkeychain.HardenedKeyStart {
		return nil, errors.New("coin type already hardened")
	}
	coinTypeKey, err := purposeKey.DeriveNonStandard(
		derivationPath[1] + hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		return nil, errors.New("error deriving coin type")
	}
	defer coinTypeKey.Zero()

	// Derive account.
	if derivationPath[2] > hdkeychain.HardenedKeyStart {
		return nil, errors.New("account already hardened")
	}
	accountKey, err := coinTypeKey.DeriveNonStandard(
		derivationPath[2] + hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		return nil, errors.New("error deriving account")
	}
	defer accountKey.Zero()

	// Derive branch.
	if derivationPath[3] > hdkeychain.HardenedKeyStart {
		return nil, errors.New("branch is hardened")
	}
	branchKey, err := accountKey.DeriveNonStandard(derivationPath[3])
	if err != nil {
		return nil, errors.New("error deriving branch")
	}
	defer branchKey.Zero()

	// Derive index.
	if derivationPath[2] > hdkeychain.HardenedKeyStart {
		return nil, errors.New("index is hardened")
	}
	indexKey, err := accountKey.DeriveNonStandard(derivationPath[4])
	if err != nil {
		return nil, errors.New("error deriving index")
	}

	return indexKey, nil
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
