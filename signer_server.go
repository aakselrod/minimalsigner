package minimalsigner

import (
	"context"
	"fmt"

	"github.com/aakselrod/minimalsigner/proto"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightningnetwork/lnd/lnwire"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

var (
	// signerPermissions maps RPC calls to the permissions they require.
	signerPermissions = map[string][]bakery.Op{
		"/signrpc.Signer/SignMessage": {{
			Entity: "signer",
			Action: "generate",
		}},
		"/signrpc.Signer/DeriveSharedKey": {{
			Entity: "signer",
			Action: "generate",
		}},
	}
)

// Server is a sub-server of the main RPC server: the signer RPC. This sub RPC
// server allows external callers to access the full signing capabilities of
// lnd. This allows callers to create custom protocols, external to lnd, even
// backed by multiple distinct lnd across independent failure domains.
type signerServer struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	proto.UnimplementedSignerServer

	server *server
}

// A compile time check to ensure that Server fully implements the SignerServer
// gRPC service.
var _ proto.SignerServer = (*signerServer)(nil)

// SignMessage signs a message with the key specified in the key locator. The
// returned signature is fixed-size LN wire format encoded.
func (s *signerServer) SignMessage(_ context.Context,
	in *proto.SignMessageReq) (*proto.SignMessageResp, error) {

	if in.Msg == nil {
		return nil, fmt.Errorf("a message to sign MUST be passed in")
	}
	if in.KeyLoc == nil {
		return nil, fmt.Errorf("a key locator MUST be passed in")
	}
	if in.SchnorrSig && in.CompactSig {
		return nil, fmt.Errorf("compact format can not be used for " +
			"Schnorr signatures")
	}

	// Describe the private key we'll be using for signing.
	keyLocator := KeyLocator{
		Family: uint32(in.KeyLoc.KeyFamily),
		Index:  uint32(in.KeyLoc.KeyIndex),
	}

	// Use the schnorr signature algorithm to sign the message.
	if in.SchnorrSig {
		sig, err := s.server.keyRing.SignMessageSchnorr(
			keyLocator, in.Msg, in.DoubleHash,
			in.SchnorrSigTapTweak,
		)
		if err != nil {
			return nil, fmt.Errorf("can't sign the hash: %v", err)
		}

		sigParsed, err := schnorr.ParseSignature(sig.Serialize())
		if err != nil {
			return nil, fmt.Errorf("can't parse Schnorr "+
				"signature: %v", err)
		}

		return &proto.SignMessageResp{
			Signature: sigParsed.Serialize(),
		}, nil
	}

	// To allow a watch-only wallet to forward the SignMessageCompact to an
	// endpoint that doesn't add the message prefix, we allow this RPC to
	// also return the compact signature format instead of adding a flag to
	// the proto.SignMessage call that removes the message prefix.
	if in.CompactSig {
		sigBytes, err := s.server.keyRing.SignMessageCompact(
			keyLocator, in.Msg, in.DoubleHash,
		)
		if err != nil {
			return nil, fmt.Errorf("can't sign the hash: %v", err)
		}

		return &proto.SignMessageResp{
			Signature: sigBytes,
		}, nil
	}

	// Create the raw ECDSA signature first and convert it to the final wire
	// format after.
	sig, err := s.server.keyRing.SignMessage(
		keyLocator, in.Msg, in.DoubleHash,
	)
	if err != nil {
		return nil, fmt.Errorf("can't sign the hash: %v", err)
	}
	wireSig, err := lnwire.NewSigFromSignature(sig)
	if err != nil {
		return nil, fmt.Errorf("can't convert to wire format: %v", err)
	}
	return &proto.SignMessageResp{
		Signature: wireSig.ToSignatureBytes(),
	}, nil
}

// DeriveSharedKey returns a shared secret key by performing Diffie-Hellman key
// derivation between the ephemeral public key in the request and the node's
// key specified in the key_desc parameter. Either a key locator or a raw public
// key is expected in the key_desc, if neither is supplied, defaults to the
// node's identity private key. The old key_loc parameter in the request
// shouldn't be used anymore.
// The resulting shared public key is serialized in the compressed format and
// hashed with sha256, resulting in the final key length of 256bit.
func (s *signerServer) DeriveSharedKey(_ context.Context,
	in *proto.SharedKeyRequest) (*proto.SharedKeyResponse, error) {

	// Check that EphemeralPubkey is valid.
	ephemeralPubkey, err := parseRawKeyBytes(in.EphemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("error in ephemeral pubkey: %v", err)
	}
	if ephemeralPubkey == nil {
		return nil, fmt.Errorf("must provide ephemeral pubkey")
	}

	// Check for backward compatibility. The caller either specifies the old
	// key_loc field, or the new key_desc field, but not both.
	if in.KeyDesc != nil && in.KeyLoc != nil {
		return nil, fmt.Errorf("use either key_desc or key_loc")
	}

	// When key_desc is used, the key_desc.key_loc is expected as the caller
	// needs to specify the KeyFamily.
	if in.KeyDesc != nil && in.KeyDesc.KeyLoc == nil {
		return nil, fmt.Errorf("when setting key_desc the field " +
			"key_desc.key_loc must also be set")
	}

	// We extract two params, rawKeyBytes and keyLoc. Notice their initial
	// values will be overwritten if not using the deprecated RPC param.
	var rawKeyBytes []byte
	keyLoc := in.KeyLoc
	if in.KeyDesc != nil {
		keyLoc = in.KeyDesc.GetKeyLoc()
		rawKeyBytes = in.KeyDesc.GetRawKeyBytes()
	}

	// When no keyLoc is supplied, defaults to the node's identity private
	// key.
	if keyLoc == nil {
		keyLoc = &proto.KeyLocator{
			KeyFamily: int32(nodeKeyAcct),
			KeyIndex:  0,
		}
	}

	// Check the caller is using either the key index or the raw public key
	// to perform the ECDH, we can't have both.
	if rawKeyBytes != nil && keyLoc.KeyIndex != 0 {
		return nil, fmt.Errorf("use either raw_key_bytes or key_index")
	}

	// Check the raw public key is valid. Notice that if the rawKeyBytes is
	// empty, the parseRawKeyBytes won't return an error, a nil
	// *btcec.PublicKey is returned instead.
	pk, err := parseRawKeyBytes(rawKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error in raw pubkey: %v", err)
	}

	// Create a key descriptor. When the KeyIndex is not specified, it uses
	// the empty value 0, and when the raw public key is not specified, the
	// pk is nil.
	keyDescriptor := KeyDescriptor{
		KeyLocator: KeyLocator{
			Family: uint32(keyLoc.KeyFamily),
			Index:  uint32(keyLoc.KeyIndex),
		},
		PubKey: pk,
	}

	// Derive the shared key using ECDH and hashing the serialized
	// compressed shared point.
	sharedKeyHash, err := s.server.keyRing.ECDH(keyDescriptor, ephemeralPubkey)
	if err != nil {
		err := fmt.Errorf("unable to derive shared key: %v", err)
		signerLog.Error(err)
		return nil, err
	}

	return &proto.SharedKeyResponse{SharedKey: sharedKeyHash[:]}, nil
}

// parseRawKeyBytes checks that the provided raw public key is valid and returns
// the public key. A nil public key is returned if the length of the rawKeyBytes
// is zero.
func parseRawKeyBytes(rawKeyBytes []byte) (*btcec.PublicKey, error) {
	switch {
	case len(rawKeyBytes) == 33:
		// If a proper raw key was provided, then we'll attempt
		// to decode and parse it.
		return btcec.ParsePubKey(rawKeyBytes)

	case len(rawKeyBytes) == 0:
		// No key is provided, return nil.
		return nil, nil

	default:
		// If the user provided a raw key, but it's of the
		// wrong length, then we'll return with an error.
		return nil, fmt.Errorf("pubkey must be " +
			"serialized in compressed format if " +
			"specified")
	}
}
