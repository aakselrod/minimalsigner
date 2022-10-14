package minimalsigner

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/macaroon.v2"
)

var defaultRootKeyID = []byte("0")

type assignedRootKeyStore struct {
	key []byte
}

func (s *assignedRootKeyStore) Get(ctx context.Context, id []byte) ([]byte,
	error) {

	return s.key, nil
}

func (s *assignedRootKeyStore) RootKey(ctx context.Context) ([]byte, []byte,
	error) {

	return s.key, defaultRootKeyID, nil
}

func (r *rpcServer) checkMac(ctx context.Context, method string) (string, int,
	error) {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		signerLog.Warnf("request for %v without metadata", method)
		return "", 0, status.Error(codes.Unauthenticated, "no metadata")
	}

	macaroonHex, ok := md["macaroon"]
	if !ok {
		signerLog.Warnf("request for %v without macaroons", method)
		return "", 0, status.Error(codes.Unauthenticated, "no macaroons")
	}

	var macSlice macaroon.Slice

	var (
		node    string
		coin    int
		coinSet bool

		check = func(caveat string) error {
			signerLog.Tracef("checking caveat: %s", caveat)

			switch {
			case strings.HasPrefix(caveat, "node:"):
				if node != "" {
					return errors.New("node already set")
				}

				// Caveat should be 5 bytes of "node:" prefix
				// plus 66 bytes of pubkey hex digits.
				if len(caveat) != 71 {
					return errors.New("invalid node pubkey")
				}

				node = caveat[5:]

			case caveat == "coin:0":
				if coinSet {
					return errors.New("coin already set")
				}

				coin = 0
				coinSet = true

			case caveat == "coin:1":
				if coinSet {
					return errors.New("coin already set")
				}

				coin = 1
				coinSet = true

			default:
				return errors.New("invalid caveat")

			}

			return nil
		}
	)

	for _, macHex := range macaroonHex {
		macBytes, err := hex.DecodeString(macHex)
		if err != nil {
			signerLog.Warnf("failed to decode macaroon hex "+
				"for %v: %v", method, err)
			continue
		}

		mac := &macaroon.Macaroon{}
		err = mac.UnmarshalBinary(macBytes)
		if err != nil {
			signerLog.Warnf("failed to unmarshal macaroon bytes "+
				"for %v: %v", method, err)
			continue
		}

		err = mac.Verify(r.cfg.macRootKey[:], check, nil)
		if err != nil {
			signerLog.Warnf("failed to verify macaroon "+
				"for %v: %v", method, err)
			continue
		}

		macSlice = append(macSlice, mac)
	}

	if len(macSlice) == 0 {
		signerLog.Warnf("macaroon authentication failure for %v",
			method)
		return "", 0, status.Error(codes.Unauthenticated,
			"macaroon authentication failure")
	}

	if !(len(node) == 66 && coinSet) {
		signerLog.Warn("macaroon doesn't specify both node and coin")
		return "", 0, status.Error(codes.Unauthenticated,
			"macaroon authentication failure")
	}

	authChecker := r.checker.Auth(macSlice)
	authInfo, err := authChecker.Allow(ctx, r.perms[method]...)
	if err != nil {
		signerLog.Warnf("macaroon authorization failure for %v: %v",
			method, err)
		return "", 0, status.Error(codes.PermissionDenied,
			"macaroon authorization failure")
	}

	signerLog.Debugf("successfully authorized request to %v", method)
	signerLog.Tracef("auth info for %v: %+v", method, authInfo)

	return node, coin, nil
}
