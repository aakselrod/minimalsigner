package minimalsigner

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/aakselrod/minimalsigner/keyring"
	"github.com/aakselrod/minimalsigner/proto"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
)

type chanInfo struct {
}

type nodeInfo struct {
	sync.RWMutex

	// TODO(aakselrod): populate initial channel state from watch-only lnd
	// instances.
	channels map[wire.OutPoint]*chanInfo
}

func (r *rpcServer) enforcePolicy(ctx context.Context, keyRing *keyring.KeyRing,
	req interface{}) error {
	switch req.(type) {

	case *proto.SignPsbtRequest:
		return r.enforcePsbt(ctx, keyRing, req.(*proto.SignPsbtRequest))
	}

	return nil
}

func (r *rpcServer) enforcePsbt(ctx context.Context, keyRing *keyring.KeyRing,
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
		return r.enforceOnChainPolicy(ctx, keyRing, packet)
	}

	r.stateMtx.RLock()
	node, ok := r.nodes[keyRing.node]
	r.stateMtx.RUnlock()

	if !ok {
		node = &nodeInfo{
			channels: make(map[wire.OutPoint]*chanInfo),
		}

		r.stateMtx.Lock()
		r.nodes[keyRing.node] = node
		r.stateMtx.Unlock()
	}

	node.RLock()
	channel, ok := node.channels[packet.UnsignedTx.TxIn[0].OutPoint]
	node.RUnlock()

	if !ok {
		channel, err := r.getChannel(ctx, keyRing, packet, node)
		if err != nil {
			return err
		}
	}

	if channel == nil {
		return r.enforceOnChainPolicy(ctx, keyRing, packet)
	}

	if !ok {
		node.Lock()
		node.channels[packet.UnsignedTx.TxIn[0].OutPoint] = channel
		node.Unlock()
	}

	return r.enforceChannelPolicy(ctx, keyRing, packet, node, channel)
}

func (r *rpcServer) enforceOnChainPolicy(ctx context.Context,
	keyRing *keyring.KeyRing, packet *psbt.Packet) error {

	// TODO(aakselrod): Handle on-chain policy enforcement.
	return nil
}

// TODO(aakselrod): Get channel info from LND or from when we're creating the
// channel. For now, we guess based on what we get to sign.
func (r *rpcServer) getChannel(ctx context.Context, keyRing *keyring.KeyRing,
	packet *psbt.Packet, node *nodeInfo) (*chanInfo, error) {

	// We only support anchor channels for now because they're easy to
	// detect by counting exactly two 330-sat anchor outputs.
	var numAnchors int
	for _, out := range packet.UnsignedTx.TxOut {
		if out.Value == 330 {
			numAnchors++
		}
	}

	// Not a channel.
	if numAnchors != 2 {
		return nil, nil
	}

	// Guess which scripts are ours and theirs.
	var ourScript, theirKey *btcec.PublicKey
	for _, out := range packet.UnsignedTx.TxOut {
	}
}

func (r *rpcServer) enforceChannelPolicy(ctx context.Context,
	keyRing *keyring.KeyRing, packet *psbt.Packet, node *nodeInfo,
	channel *chanInfo) error {

}
