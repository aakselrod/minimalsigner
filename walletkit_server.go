package minimalsigner

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/aakselrod/minimalsigner/proto"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

var (
	// macPermissions maps RPC calls to the permissions they require.
	walletPermissions = map[string][]bakery.Op{
		"/walletrpc.WalletKit/SignPsbt": {{
			Entity: "onchain",
			Action: "write",
		}},
		"/walletrpc.WalletKit/ListAccounts": {{
			Entity: "onchain",
			Action: "read",
		}},
	}
)

// walletKit is a sub-RPC server that exposes a tool kit which allows clients
// to execute common wallet operations. This includes requesting new addresses,
// keys (for contracts!), and publishing transactions.
type walletKit struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	proto.UnimplementedWalletKitServer

	wallet *lnwallet.LightningWallet
}

// A compile time check to ensure that walletKit fully implements the
// proto.WalletKitServer gRPC service.
var _ proto.WalletKitServer = (*walletKit)(nil)

// internalScope returns the internal key scope.
func (w *walletKit) internalScope() waddrmgr.KeyScope {
	return waddrmgr.KeyScope{
		Purpose: keychain.BIP0043Purpose,
		Coin:    w.wallet.Cfg.NetParams.HDCoinType,
	}
}

// SignPsbt expects a partial transaction with all inputs and outputs fully
// declared and tries to sign all unsigned inputs that have all required fields
// (UTXO information, BIP32 derivation information, witness or sig scripts)
// set.
// If no error is returned, the PSBT is ready to be given to the next signer or
// to be finalized if lnd was the last signer.
//
// NOTE: This RPC only signs inputs (and only those it can sign), it does not
// perform any other tasks (such as coin selection, UTXO locking or
// input/output/fee value validation, PSBT finalization). Any input that is
// incomplete will be skipped.
func (w *walletKit) SignPsbt(_ context.Context, req *proto.SignPsbtRequest) (
	*proto.SignPsbtResponse, error) {

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(req.FundedPsbt), false,
	)
	if err != nil {
		ltndLog.Debugf("Error parsing PSBT: %v, raw input: %x", err,
			req.FundedPsbt)
		return nil, fmt.Errorf("error parsing PSBT: %v", err)
	}

	// Before we attempt to sign the packet, ensure that every input either
	// has a witness UTXO, or a non witness UTXO.
	for idx := range packet.UnsignedTx.TxIn {
		in := packet.Inputs[idx]

		// Doesn't have either a witness or non witness UTXO so we need
		// to exit here as otherwise signing will fail.
		if in.WitnessUtxo == nil && in.NonWitnessUtxo == nil {
			return nil, fmt.Errorf("input (index=%v) doesn't "+
				"specify any UTXO info", idx)
		}
	}

	// Let the wallet do the heavy lifting. This will sign all inputs that
	// we have the UTXO for. If some inputs can't be signed and don't have
	// witness data attached, they will just be skipped.
	signedInputs, err := w.wallet.SignPsbt(packet)
	if err != nil {
		return nil, fmt.Errorf("error signing PSBT: %v", err)
	}

	// Serialize the signed PSBT in both the packet and wire format.
	var signedPsbtBytes bytes.Buffer
	err = packet.Serialize(&signedPsbtBytes)
	if err != nil {
		return nil, fmt.Errorf("error serializing PSBT: %v", err)
	}

	return &proto.SignPsbtResponse{
		SignedPsbt:   signedPsbtBytes.Bytes(),
		SignedInputs: signedInputs,
	}, nil
}

// marshalWalletAccount converts the properties of an account into its RPC
// representation.
func marshalWalletAccount(internalScope waddrmgr.KeyScope,
	account *waddrmgr.AccountProperties) (*proto.Account, error) {

	var addrType proto.AddressType
	switch account.KeyScope {
	case waddrmgr.KeyScopeBIP0049Plus:
		// No address schema present represents the traditional BIP-0049
		// address derivation scheme.
		if account.AddrSchema == nil {
			addrType = proto.AddressType_HYBRID_NESTED_WITNESS_PUBKEY_HASH
			break
		}

		switch *account.AddrSchema {
		case waddrmgr.KeyScopeBIP0049AddrSchema:
			addrType = proto.AddressType_NESTED_WITNESS_PUBKEY_HASH

		case waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0049Plus]:
			addrType = proto.AddressType_HYBRID_NESTED_WITNESS_PUBKEY_HASH

		default:
			return nil, fmt.Errorf("unsupported address schema %v",
				*account.AddrSchema)
		}

	case waddrmgr.KeyScopeBIP0084:
		addrType = proto.AddressType_WITNESS_PUBKEY_HASH

	case waddrmgr.KeyScopeBIP0086:
		addrType = proto.AddressType_TAPROOT_PUBKEY

	case internalScope:
		addrType = proto.AddressType_WITNESS_PUBKEY_HASH

	default:
		return nil, fmt.Errorf("account %v has unsupported "+
			"key scope %v", account.AccountName, account.KeyScope)
	}

	rpcAccount := &proto.Account{
		Name:             account.AccountName,
		AddressType:      addrType,
		ExternalKeyCount: account.ExternalKeyCount,
		InternalKeyCount: account.InternalKeyCount,
		WatchOnly:        account.IsWatchOnly,
	}

	// The remaining fields can only be done on accounts other than the
	// default imported one existing within each key scope.
	if account.AccountName != waddrmgr.ImportedAddrAccountName {
		nonHardenedIndex := account.AccountPubKey.ChildIndex() -
			hdkeychain.HardenedKeyStart
		rpcAccount.ExtendedPublicKey = account.AccountPubKey.String()
		if account.MasterKeyFingerprint != 0 {
			var mkfp [4]byte
			binary.BigEndian.PutUint32(
				mkfp[:], account.MasterKeyFingerprint,
			)
			rpcAccount.MasterKeyFingerprint = mkfp[:]
		}
		rpcAccount.DerivationPath = fmt.Sprintf("%v/%v'",
			account.KeyScope, nonHardenedIndex)
	}

	return rpcAccount, nil
}

// ListAccounts retrieves all accounts belonging to the wallet by default. A
// name and key scope filter can be provided to filter through all of the wallet
// accounts and return only those matching.
func (w *walletKit) ListAccounts(ctx context.Context,
	req *proto.ListAccountsRequest) (*proto.ListAccountsResponse, error) {

	// Map the supported address types into their corresponding key scope.
	var keyScopeFilter *waddrmgr.KeyScope
	switch req.AddressType {
	case proto.AddressType_UNKNOWN:
		break

	case proto.AddressType_WITNESS_PUBKEY_HASH:
		keyScope := waddrmgr.KeyScopeBIP0084
		keyScopeFilter = &keyScope

	case proto.AddressType_NESTED_WITNESS_PUBKEY_HASH,
		proto.AddressType_HYBRID_NESTED_WITNESS_PUBKEY_HASH:

		keyScope := waddrmgr.KeyScopeBIP0049Plus
		keyScopeFilter = &keyScope

	case proto.AddressType_TAPROOT_PUBKEY:
		keyScope := waddrmgr.KeyScopeBIP0086
		keyScopeFilter = &keyScope

	default:
		return nil, fmt.Errorf("unhandled address type %v", req.AddressType)
	}

	accounts, err := w.wallet.ListAccounts(req.Name, keyScopeFilter)
	if err != nil {
		return nil, err
	}

	rpcAccounts := make([]*proto.Account, 0, len(accounts))
	for _, account := range accounts {
		// Don't include the default imported accounts created by the
		// wallet in the response if they don't have any keys imported.
		if account.AccountName == waddrmgr.ImportedAddrAccountName &&
			account.ImportedKeyCount == 0 {

			continue
		}

		rpcAccount, err := marshalWalletAccount(
			w.internalScope(), account,
		)
		if err != nil {
			return nil, err
		}
		rpcAccounts = append(rpcAccounts, rpcAccount)
	}

	return &proto.ListAccountsResponse{Accounts: rpcAccounts}, nil
}
