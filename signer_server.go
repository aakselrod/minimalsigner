package minimalsigner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/aakselrod/minimalsigner/proto"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/lightningnetwork/lnd/input"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	// MuSig2PartialSigSize is the size of a MuSig2 partial signature.
	// Because a partial signature is just the s value, this corresponds to
	// the length of a scalar.
	MuSig2PartialSigSize = 32
)

var (
	// signerPermissions maps RPC calls to the permissions they require.
	signerPermissions = map[string][]bakery.Op{
		"/proto.Signer/SignMessage": {{
			Entity: "signer",
			Action: "generate",
		}},
		"/proto.Signer/DeriveSharedKey": {{
			Entity: "signer",
			Action: "generate",
		}},
		"/proto.Signer/MuSig2CreateSession": {{
			Entity: "signer",
			Action: "generate",
		}},
		"/signrpc.Signer/MuSig2RegisterNonces": {{
			Entity: "signer",
			Action: "generate",
		}},
		"/signrpc.Signer/MuSig2Sign": {{
			Entity: "signer",
			Action: "generate",
		}},
		"/signrpc.Signer/MuSig2CombineSig": {{
			Entity: "signer",
			Action: "generate",
		}},
		"/signrpc.Signer/MuSig2Cleanup": {{
			Entity: "signer",
			Action: "generate",
		}},
	}
)

// MuSig2SessionID is a type for a session ID that is just a hash of the MuSig2
// combined key and the local public nonces.
type MuSig2SessionID [sha256.Size]byte

// signerServer is a sub-server of the main RPC server: the signer RPC. This sub RPC
// server allows external callers to access the full signing capabilities of
// lnd. This allows callers to create custom protocols, external to lnd, even
// backed by multiple distinct lnd across independent failure domains.
type signerServer struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	proto.UnimplementedSignerServer

	server *rpcServer
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
	return &proto.SignMessageResp{
		Signature: sig.Serialize(),
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

// MuSig2CreateSession creates a new MuSig2 signing session using the local
// key identified by the key locator. The complete list of all public keys of
// all signing parties must be provided, including the public key of the local
// signing key. If nonces of other parties are already known, they can be
// submitted as well to reduce the number of RPC calls necessary later on.
func (s *signerServer) MuSig2CreateSession(_ context.Context,
	in *proto.MuSig2SessionRequest) (*proto.MuSig2SessionResponse, error) {

	// A key locator is always mandatory.
	if in.KeyLoc == nil {
		return nil, fmt.Errorf("missing key_loc")
	}
	keyLoc := KeyLocator{
		Family: uint32(in.KeyLoc.KeyFamily),
		Index:  uint32(in.KeyLoc.KeyIndex),
	}

	// Parse the public keys of all signing participants. This must also
	// include our own, local key.
	allSignerPubKeys := make([]*btcec.PublicKey, len(in.AllSignerPubkeys))
	if len(in.AllSignerPubkeys) < 2 {
		return nil, fmt.Errorf("need at least two signing public keys")
	}

	for idx, pubKeyBytes := range in.AllSignerPubkeys {
		pubKey, err := schnorr.ParsePubKey(pubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing signer public "+
				"key %d: %v", idx, err)
		}
		allSignerPubKeys[idx] = pubKey
	}

	// We participate a nonce ourselves, so we can't have more nonces than
	// the total number of participants minus ourselves.
	maxNonces := len(in.AllSignerPubkeys) - 1
	if len(in.OtherSignerPublicNonces) > maxNonces {
		return nil, fmt.Errorf("too many other signer public nonces, "+
			"got %d but expected a maximum of %d",
			len(in.OtherSignerPublicNonces), maxNonces)
	}

	// Parse all other nonces we might already know.
	otherSignerNonces, err := parseMuSig2PublicNonces(
		in.OtherSignerPublicNonces, true,
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing other nonces: %v", err)
	}

	// Are there any tweaks to apply to the combined public key?
	tweaks, err := UnmarshalTweaks(in.Tweaks, in.TaprootTweak)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling tweak options: %v",
			err)
	}

	// Register the session with the internal wallet/signer now.
	session, err := s.server.keyRing.MuSig2CreateSession(
		keyLoc, allSignerPubKeys, tweaks, otherSignerNonces,
	)
	if err != nil {
		return nil, fmt.Errorf("error registering session: %v", err)
	}

	var internalKeyBytes []byte
	if session.TaprootTweak {
		internalKeyBytes = schnorr.SerializePubKey(
			session.TaprootInternalKey,
		)
	}

	return &proto.MuSig2SessionResponse{
		SessionId: session.SessionID[:],
		CombinedKey: schnorr.SerializePubKey(
			session.CombinedKey,
		),
		TaprootInternalKey: internalKeyBytes,
		LocalPublicNonces:  session.PublicNonce[:],
		HaveAllNonces:      session.HaveAllNonces,
	}, nil
}

// MuSig2RegisterNonces registers one or more public nonces of other signing
// participants for a session identified by its ID.
func (s *signerServer) MuSig2RegisterNonces(_ context.Context,
	in *proto.MuSig2RegisterNoncesRequest) (
	*proto.MuSig2RegisterNoncesResponse, error) {

	// Check session ID length.
	sessionID, err := parseMuSig2SessionID(in.SessionId)
	if err != nil {
		return nil, fmt.Errorf("error parsing session ID: %v", err)
	}

	// Parse the other signing participants' nonces. We can't validate the
	// number of nonces here because we don't have access to the session in
	// this context. But the signer will be able to make sure we don't
	// register more nonces than there are signers (which would mean
	// something is wrong in the signing setup). But we want at least a
	// single nonce for each call.
	otherSignerNonces, err := parseMuSig2PublicNonces(
		in.OtherSignerPublicNonces, false,
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing other nonces: %v", err)
	}

	// Register the nonces now.
	haveAllNonces, err := s.server.keyRing.MuSig2RegisterNonces(
		sessionID, otherSignerNonces,
	)
	if err != nil {
		return nil, fmt.Errorf("error registering nonces: %v", err)
	}

	return &proto.MuSig2RegisterNoncesResponse{
		HaveAllNonces: haveAllNonces,
	}, nil
}

// MuSig2Sign creates a partial signature using the local signing key that was
// specified when the session was created. This can only be called when all
// public nonces of all participants are known and have been registered with
// the session. If this node isn't responsible for combining all the partial
// signatures, then the cleanup flag should be set, indicating that the session
// can be removed from memory once the signature was produced.
func (s *signerServer) MuSig2Sign(_ context.Context,
	in *proto.MuSig2SignRequest) (*proto.MuSig2SignResponse, error) {

	// Check session ID length.
	sessionID, err := parseMuSig2SessionID(in.SessionId)
	if err != nil {
		return nil, fmt.Errorf("error parsing session ID: %v", err)
	}

	// Schnorr signatures only work reliably if the message is 32 bytes.
	msg := [sha256.Size]byte{}
	if len(in.MessageDigest) != sha256.Size {
		return nil, fmt.Errorf("invalid message digest size, got %d "+
			"but expected %d", len(in.MessageDigest), sha256.Size)
	}
	copy(msg[:], in.MessageDigest)

	// Create our own partial signature with the local signing key.
	partialSig, err := s.server.keyRing.MuSig2Sign(
		sessionID,
		msg,
		in.Cleanup,
	)
	if err != nil {
		return nil, fmt.Errorf("error signing: %v", err)
	}

	serializedPartialSig, err := serializePartialSignature(partialSig)
	if err != nil {
		return nil, fmt.Errorf("error serializing sig: %v", err)
	}

	return &proto.MuSig2SignResponse{
		LocalPartialSignature: serializedPartialSig[:],
	}, nil
}

// MuSig2CombineSig combines the given partial signature(s) with the local one,
// if it already exists. Once a partial signature of all participants is
// registered, the final signature will be combined and returned.
func (s *signerServer) MuSig2CombineSig(_ context.Context,
	in *MuSig2CombineSigRequest) (*MuSig2CombineSigResponse, error) {

	// Check session ID length.
	sessionID, err := parseMuSig2SessionID(in.SessionId)
	if err != nil {
		return nil, fmt.Errorf("error parsing session ID: %v", err)
	}

	// Parse all other signatures. This can be called multiple times, so we
	// can't really sanity check how many we already have vs. how many the
	// user supplied in this call.
	partialSigs, err := parseMuSig2PartialSignatures(
		in.OtherPartialSignatures,
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing partial signatures: %v",
			err)
	}

	// Combine the signatures now, potentially getting the final, full
	// signature if we've already got all partial ones.
	finalSig, haveAllSigs, err := s.server.keyRing.MuSig2CombineSig(
		sessionID, partialSigs,
	)
	if err != nil {
		return nil, fmt.Errorf("error combining signatures: %v", err)
	}

	resp := &MuSig2CombineSigResponse{
		HaveAllSignatures: haveAllSigs,
	}

	if haveAllSigs {
		resp.FinalSignature = finalSig.Serialize()
	}

	return resp, err
}

// MuSig2Cleanup removes a session from memory to free up resources.
func (s *signerServer) MuSig2Cleanup(_ context.Context,
	in *MuSig2CleanupRequest) (*MuSig2CleanupResponse, error) {

	// Check session ID length.
	sessionID, err := parseMuSig2SessionID(in.SessionId)
	if err != nil {
		return nil, fmt.Errorf("error parsing session ID: %v", err)
	}

	err = s.server.keyRing.MuSig2Cleanup(sessionID)
	if err != nil {
		return nil, fmt.Errorf("error cleaning up session: %v", err)
	}

	return &MuSig2CleanupResponse{}, nil
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

// parseMuSig2SessionID parses a MuSig2 session ID from a raw byte slice.
func parseMuSig2SessionID(rawID []byte) (input.MuSig2SessionID, error) {
	sessionID := input.MuSig2SessionID{}

	// The session ID must be exact in its length.
	if len(rawID) != sha256.Size {
		return sessionID, fmt.Errorf("invalid session ID size, got "+
			"%d but expected %d", len(rawID), sha256.Size)
	}
	copy(sessionID[:], rawID)

	return sessionID, nil
}

// parseMuSig2PublicNonces sanity checks and parses the other signers' public
// nonces.
func parseMuSig2PublicNonces(pubNonces [][]byte,
	emptyAllowed bool) ([][musig2.PubNonceSize]byte, error) {

	// For some calls the nonces are optional while for others it doesn't
	// make any sense to not specify them (for example for the explicit
	// nonce registration call there should be at least one nonce).
	if !emptyAllowed && len(pubNonces) == 0 {
		return nil, fmt.Errorf("at least one other signer public " +
			"nonce is required")
	}

	// Parse all other nonces. This can be called multiple times, so we
	// can't really sanity check how many we already have vs. how many the
	// user supplied in this call.
	otherSignerNonces := make([][musig2.PubNonceSize]byte, len(pubNonces))
	for idx, otherNonceBytes := range pubNonces {
		if len(otherNonceBytes) != musig2.PubNonceSize {
			return nil, fmt.Errorf("invalid public nonce at "+
				"index %d: invalid length, got %d but "+
				"expected %d", idx, len(otherNonceBytes),
				musig2.PubNonceSize)
		}
		copy(otherSignerNonces[idx][:], otherNonceBytes)
	}

	return otherSignerNonces, nil
}

// parseMuSig2PartialSignatures sanity checks and parses the other signers'
// partial signatures.
func parseMuSig2PartialSignatures(
	partialSignatures [][]byte) ([]*musig2.PartialSignature, error) {

	// We always want at least one partial signature.
	if len(partialSignatures) == 0 {
		return nil, fmt.Errorf("at least one partial signature is " +
			"required")
	}

	parsedPartialSigs := make(
		[]*musig2.PartialSignature, len(partialSignatures),
	)
	for idx, otherPartialSigBytes := range partialSignatures {
		sig, err := input.DeserializePartialSignature(
			otherPartialSigBytes,
		)
		if err != nil {
			return nil, fmt.Errorf("invalid partial signature at "+
				"index %d: %v", idx, err)
		}

		parsedPartialSigs[idx] = sig
	}

	return parsedPartialSigs, nil
}

// UnmarshalTweaks parses the RPC tweak descriptions into their native
// counterpart.
func UnmarshalTweaks(rpcTweaks []*TweakDesc,
	taprootTweak *TaprootTweakDesc) (*input.MuSig2Tweaks, error) {

	// Parse the generic tweaks first.
	tweaks := &input.MuSig2Tweaks{
		GenericTweaks: make([]musig2.KeyTweakDesc, len(rpcTweaks)),
	}
	for idx, rpcTweak := range rpcTweaks {
		if len(rpcTweak.Tweak) == 0 {
			return nil, fmt.Errorf("tweak cannot be empty")
		}

		copy(tweaks.GenericTweaks[idx].Tweak[:], rpcTweak.Tweak)
		tweaks.GenericTweaks[idx].IsXOnly = rpcTweak.IsXOnly
	}

	// Now parse the taproot specific tweak.
	if taprootTweak != nil {
		if taprootTweak.KeySpendOnly {
			tweaks.TaprootBIP0086Tweak = true
		} else {
			if len(taprootTweak.ScriptRoot) == 0 {
				return nil, fmt.Errorf("script root cannot " +
					"be empty for non-keyspend")
			}

			tweaks.TaprootTweak = taprootTweak.ScriptRoot
		}
	}

	return tweaks, nil
}

// serializePartialSignature encodes the partial signature to a fixed size byte
// array.
func serializePartialSignature(sig *musig2.PartialSignature) (
	[MuSig2PartialSigSize]byte, error) {

	var (
		buf    bytes.Buffer
		result [MuSig2PartialSigSize]byte
	)
	if err := sig.Encode(&buf); err != nil {
		return result, fmt.Errorf("error encoding partial signature: "+
			"%v", err)
	}

	if buf.Len() != MuSig2PartialSigSize {
		return result, fmt.Errorf("invalid partial signature length, "+
			"got %d wanted %d", buf.Len(), MuSig2PartialSigSize)
	}

	copy(result[:], buf.Bytes())

	return result, nil
}

// deserializePartialSignature decodes a partial signature from a byte slice.
func deserializePartialSignature(scalarBytes []byte) (*musig2.PartialSignature,
	error) {

	if len(scalarBytes) != MuSig2PartialSigSize {
		return nil, fmt.Errorf("invalid partial signature length, got "+
			"%d wanted %d", len(scalarBytes), MuSig2PartialSigSize)
	}

	sig := &musig2.PartialSignature{}
	if err := sig.Decode(bytes.NewReader(scalarBytes)); err != nil {
		return nil, fmt.Errorf("error decoding partial signature: %v",
			err)
	}

	return sig, nil
}
