package minimalsigner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/aakselrod/minimalsigner/proto"
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

	// accounts is a mapping by derivation of the node's account extended
	// public keys. The path elements are all hardened.
	accounts map[[3]uint32]*hdkeychain.ExtendedKey

	// TODO(aakselrod): populate initial channel state from watch-only lnd
	// instances.
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
		// TODO(aakselrod): get the channels from somewhere.
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

	ni, err := r.getNodeInfo(node)
	if err != nil {
		return err
	}

	switch req.(type) {

	case *proto.SignPsbtRequest:
		return r.enforcePsbt(ctx, ni, req.(*proto.SignPsbtRequest))
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

	if len(packet.UnsignedTx.TxIn) != 1 {
		// Single input for channel update should be channel point, so
		// this must be an on-chain spend.
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

	// We try to guess the to-us and to-them pubkeys used for refund
	// outputs so we can track money flows as we update state.
	//
	// TODO(aakselrod): FIX THIS. This assumes that:
	// - the outputs are sorted correctly from smallest to largest
	// - the two largest outputs are
	// var ourScript, theirScript *btcec.PublicKey

	for range packet.UnsignedTx.TxOut[len(
		packet.UnsignedTx.TxOut)-2:] {

	}

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

		strDerPath, ok := acctEl["derivation_path"].(string)
		if !ok {
			return nil, fmt.Errorf("account has no derivation path")
		}
	}

	return nil, nil

}
