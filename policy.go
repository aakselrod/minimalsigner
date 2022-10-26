package minimalsigner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/aakselrod/minimalsigner/proto"
	"github.com/aakselrod/minimalsigner/vault"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
)

type chanInfo struct {
}

type acctInfo struct {
}

type nodeInfo struct {
	sync.RWMutex

	// node is the hex pubkey of the node.
	node string

	// accounts is a mapping by derivation of the node's account extended
	// public keys. The path elements are all hardened.
	accounts map[[3]uint32]*hdkeychain.ExtendedKey

	// channels is a mapping by channel point of channel info structs.
	channels map[wire.OutPoint]*chanInfo
}

func (r *rpcServer) getNodeInfo(node string) (*nodeInfo, error) {
	r.stateMtx.RLock()
	info, ok := r.nodes[node]
	r.stateMtx.RUnlock()

	if ok {
		return info, nil
	}

	// We didn't find our node info already cached, so get it from the
	// vault.
	info = &nodeInfo{
		node:     node,
		channels: make(map[wire.OutPoint]*chanInfo),
	}

	listAcctsResp, err := r.client.ReadWithData(
		"minimalsigner/lnd-nodes/accounts",
		map[string][]string{
			"node": []string{node},
		},
	)
	if err != nil {
		return nil, err
	}

	acctList, ok := listAcctsResp.Data["acctList"].(string)
	if !ok {
		return nil, fmt.Errorf("accounts not returned for node %s",
			node)
	}

	info.accounts, err = getAccounts(acctList)
	if err != nil {
		return nil, err
	}

	r.stateMtx.Lock()
	r.nodes[node] = info
	r.stateMtx.Unlock()

	return info, nil

}

func (r *rpcServer) enforcePolicy(ctx context.Context, node string,
	req interface{}) error {

	info, err := r.getNodeInfo(node)
	if err != nil {
		return err
	}

	switch req.(type) {

	case *proto.SignPsbtRequest:
		return r.enforcePsbt(ctx, info, req.(*proto.SignPsbtRequest))
	}

	return nil
}

func (r *rpcServer) enforcePsbt(ctx context.Context, node *nodeInfo,
	req *proto.SignPsbtRequest) error {

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(req.FundedPsbt), false,
	)
	if err != nil {
		signerLog.Debugf("Error parsing PSBT: %v, raw input: %x", err,
			req.FundedPsbt)
		return fmt.Errorf("error parsing PSBT: %v", err)
	}

	signerLog.Debugf("Got PSBT packet to sign with unsigned TX: %s",
		spew.Sdump(packet.UnsignedTx))

	if len(packet.UnsignedTx.TxIn) != 1 || len(packet.Inputs) != 1 {
		// Single input for channel update should be channel point, so
		// this must be an on-chain spend.
		return r.enforceOnChainPolicy(ctx, packet, node)
	}

	derPaths := packet.Inputs[0].Bip32Derivation
	if len(derPaths) != 1 {
		// We expect exactly one derivation path for a channel update.
		return r.enforceChainPolicy(ctx, packet, node)
	}

	if len(derPaths[0]) != 5 {
		return fmt.Errorf("invalid derivation path in PSBT request")
	}

	if derPaths[0][0] != vault.Bip0043purpose+
		hdkeychain.HardenedKeyStart || // Channel update for LN.
		derPaths[0][1] != nodeInfo.coin+
			hdkeychain.HardenedKeyStart || // Coin type must match.
		derPaths[0][2] != hdkeychain.HardenedKeyStart { // Multisig.

		// Not deriving from the correct account to sign for a
		// channel point.
		return r.enforceOnChainPolicy(ctx, packet, node)
	}

	channel, err := r.getChanInfo(ctx, packet, node)
	if err != nil {
		return err
	}

	if channel == nil {
		return r.enforceOnChainPolicy(ctx, packet, node)
	}

	return r.enforceChannelPolicy(ctx, packet, node, channel)
}

func (r *rpcServer) enforceOnChainPolicy(ctx context.Context,
	packet *psbt.Packet, node *nodeInfo) error {

	// TODO(aakselrod): Handle on-chain policy enforcement.
	return nil
}

// getChanInfo constructs a chanInfo struct from the supplied parameters.
//
// TODO(aakselrod): Get channel info from LND or from when we're creating the
// channel. For now, we guess based on what we get to sign.
func (r *rpcServer) getChanInfo(ctx context.Context, packet *psbt.Packet,
	node *nodeInfo) (*chanInfo, error) {

	node.RLock()
	info, ok := node.channels[packet.UnsignedTx.TxIn[0].PreviousOutPoint]
	node.RUnlock()

	if ok {
		return info, nil
	}

	// Read node's channel backup file. We add a suffix for the specific
	// node, just as we do when writing a macaroon or accounts file.
	// We expect that this is updated every time a new channel is opened.
	// This makes it easy to use a symlink in local testing, but requires
	// production deployments to somehow get the backup file to the signer
	// after each channel opening.
	//
	// TODO(aakselrod): better integration here.
	chbuBytes, err := os.ReadFile(r.cfg.ChannelBackup + "." + node.node)
	if err != nil {
		return nil, err
	}

	branchKey, err :=

		node.Lock()
	node.channels[packet.UnsignedTx.TxIn[0].PreviousOutPoint] = info
	node.Unlock()

	return info, nil
}

func (r *rpcServer) enforceChannelPolicy(ctx context.Context,
	packet *psbt.Packet, node *nodeInfo, channel *chanInfo) error {

	return nil
}

func getAccounts(acctList string) (map[[3]uint32]*hdkeychain.ExtendedKey,
	error) {

	accounts := make(map[[3]uint32]*hdkeychain.ExtendedKey)

	elements := make(map[string]interface{})

	err := json.Unmarshal([]byte(acctList), elements)
	if err != nil {
		return nil, err
	}

	acctElements, ok := elements["accounts"].([]map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("no accounts returned in JSON")
	}

	for _, acctEl := range acctElements {
		strKey, ok := acctEl["extended_public_key"].(string)
		if !ok {
			return nil, fmt.Errorf("account has no extended pubkey")
		}

		xPub, err := hdkeychain.NewKeyFromString(strKey)
		if err != nil {
			return nil, err
		}

		strDerPath, ok := acctEl["derivation_path"].(string)
		if !ok {
			return nil, fmt.Errorf("account has no derivation path")
		}

		pathEls := strings.Split(strDerPath, "/")
		if len(pathEls) != 4 || pathEls[0] != "m" {
			return nil, fmt.Errorf("invalid derivation path")
		}

		var derPath [3]uint32
		for idx, el := range pathEls[1:] {
			if !strings.HasPrefix(el, "'") {
				return nil, fmt.Errorf("acct derivation path "+
					"element %d not hardened", idx)
			}

			intEl, err := strconv.ParseUint(el[:len(el)-1])
			if err != nil {
				return nil, err
			}

			derPath[idx] = uint32(intEl) +
				hdkeychain.HardenedKeyStart
		}

		accounts[derPath] = xPub
	}

	return accounts, nil

}
