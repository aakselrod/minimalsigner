package minimalsigner

import (
	"context"
	"fmt"

	"github.com/aakselrod/minimalsigner/proto"
	"github.com/tv42/zbase32"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

var (
	// nodePermissions is a slice of all entities for using signing
	// permissions for authorization purposes, all lowercase.
	nodePermissions = []bakery.Op{
		{
			Entity: "onchain",
			Action: "write",
		},
		{
			Entity: "message",
			Action: "write",
		},
		{
			Entity: "signer",
			Action: "generate",
		},
	}

	// TODO(guggero): Refactor into constants that are used for all
	// permissions in this file. Also expose the list of possible
	// permissions in an RPC when per RPC permissions are
	// implemented.
	validActions  = []string{"write", "generate"}
	validEntities = []string{"onchain", "message", "signer"}
)

// stringInSlice returns true if a string is contained in the given slice.
func stringInSlice(a string, slice []string) bool {
	for _, b := range slice {
		if b == a {
			return true
		}
	}
	return false
}

// GetAllPermissions returns all the permissions required to interact with lnd.
func GetAllPermissions() []bakery.Op {
	allPerms := make([]bakery.Op, 0)

	// The map will help keep track of which specific permission pairs have
	// already been added to the slice.
	allPermsMap := make(map[string]map[string]struct{})

	for _, perms := range MainRPCServerPermissions() {
		for _, perm := range perms {
			entity := perm.Entity
			action := perm.Action

			// If this specific entity-action permission pair isn't
			// in the map yet. Add it to map, and the permission
			// slice.
			if acts, ok := allPermsMap[entity]; ok {
				if _, ok := acts[action]; !ok {
					allPermsMap[entity][action] = struct{}{}

					allPerms = append(
						allPerms, perm,
					)
				}
			} else {
				allPermsMap[entity] = make(map[string]struct{})
				allPermsMap[entity][action] = struct{}{}
				allPerms = append(allPerms, perm)
			}
		}
	}

	return allPerms
}

// MainRPCServerPermissions returns a mapping of the main RPC server calls to
// the permissions they require.
func MainRPCServerPermissions() map[string][]bakery.Op {
	return map[string][]bakery.Op{
		"/lnrpc.Lightning/SignMessage": {{
			Entity: "message",
			Action: "write",
		}},
	}
}

// rpcServer is a gRPC, RPC front end to the lnd daemon.
// TODO(roasbeef): pagination support for the list-style calls
type rpcServer struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	// Must be after the atomically used variables to not break struct
	// alignment.
	proto.UnimplementedLightningServer

	server *server

	cfg *Config

	quit chan struct{}
}

// A compile time check to ensure that rpcServer fully implements the
// LightningServer gRPC service.
var _ proto.LightningServer = (*rpcServer)(nil)

// newRPCServer creates and returns a new instance of the rpcServer. Before
// dependencies are added, this will be an non-functioning RPC server only to
// be used to register the LightningService with the gRPC server.
func newRPCServer(cfg *Config) *rpcServer {
	return &rpcServer{
		cfg:  cfg,
		quit: make(chan struct{}, 1),
	}
}

// addDeps populates all dependencies needed by the RPC server, and any
// of the sub-servers that it maintains. When this is done, the RPC server can
// be started, and start accepting RPC calls.
func (r *rpcServer) addDeps(s *server, checker *bakery.Checker) error {
	// Next, we need to merge the set of sub server macaroon permissions
	// with the main RPC server permissions so we can unite them under a
	// single set of interceptors.
	/*for m, ops := range MainRPCServerPermissions() {
		err := r.interceptorChain.AddPermission(m, ops)
		if err != nil {
			return err
		}
	}

	// Wallet kit permissions.
	for m, ops := range walletPermissions {
		err := r.interceptorChain.AddPermission(m, ops)
		if err != nil {
			return err
		}
	}

	// signer permissions.
	for m, ops := range signerPermissions {
		err := r.interceptorChain.AddPermission(m, ops)
		if err != nil {
			return err
		}
	}*/

	// Finally, with all the set up complete, add the last dependencies to
	// the rpc server.
	r.server = s

	return nil
}

// RegisterWithGrpcServer registers the rpcServer and any subservers with the
// root gRPC server.
func (r *rpcServer) RegisterWithGrpcServer(grpcServer *grpc.Server) error {
	// Register the main RPC server.
	proto.RegisterLightningServer(grpcServer, r)

	// Register the wallet subserver.
	proto.RegisterWalletKitServer(grpcServer, &walletKit{
		server: r.server,
	})

	// Register the signer subserver.
	proto.RegisterSignerServer(grpcServer, &signerServer{
		server: r.server,
	})

	return nil
}

var (
	// signedMsgPrefix is a special prefix that we'll prepend to any
	// messages we sign/verify. We do this to ensure that we don't
	// accidentally sign a sighash, or other sensitive material. By
	// prepending this fragment, we mind message signing to our particular
	// context.
	signedMsgPrefix = []byte("Lightning Signed Message:")
)

// SignMessage signs a message with the resident node's private key. The
// returned signature string is zbase32 encoded and pubkey recoverable, meaning
// that only the message digest and signature are needed for verification.
func (r *rpcServer) SignMessage(_ context.Context,
	in *proto.SignMessageRequest) (*proto.SignMessageResponse, error) {

	if in.Msg == nil {
		return nil, fmt.Errorf("need a message to sign")
	}

	in.Msg = append(signedMsgPrefix, in.Msg...)
	sigBytes, err := r.server.nodeSigner.SignMessageCompact(
		in.Msg, !in.SingleHash,
	)
	if err != nil {
		return nil, err
	}

	sig := zbase32.EncodeToString(sigBytes)
	return &proto.SignMessageResponse{Signature: sig}, nil
}
