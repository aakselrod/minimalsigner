package minimalsigner

import (
	"context"
	"fmt"

	"github.com/aakselrod/minimalsigner/proto"
	"github.com/tv42/zbase32"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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

	keyRing *KeyRing

	checker *bakery.Checker

	cfg *Config
}

// A compile time check to ensure that rpcServer fully implements the
// LightningServer gRPC service.
var _ proto.LightningServer = (*rpcServer)(nil)

// newRPCServer creates and returns a new instance of the rpcServer. Before
// dependencies are added, this will be an non-functioning RPC server only to
// be used to register the LightningService with the gRPC server.
func newRPCServer(cfg *Config, k *KeyRing, checker *bakery.Checker) *rpcServer {
	return &rpcServer{
		cfg:     cfg,
		keyRing: k,
		checker: checker,
	}
}

// intercept allows the RPC server to intercept requests to ensure that they're
// authorized by a macaroon signed by the macaroon root key.
func (r *rpcServer) intercept(ctx context.Context, req interface{},
	info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (
	interface{}, error) {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no metadata")
	}

	macaroonHex, ok := md["macaroon"]
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no macaroon")
	}

	signerLog.Infof("got macaroon: %+v", macaroonHex)

	return handler(ctx, req)
}

// RegisterWithGrpcServer registers the rpcServer and any subservers with the
// root gRPC server.
func (r *rpcServer) RegisterWithGrpcServer(grpcServer *grpc.Server) error {
	// Register the main RPC server.
	proto.RegisterLightningServer(grpcServer, r)

	// Register the wallet subserver.
	walletDesc := proto.WalletKit_ServiceDesc
	walletDesc.ServiceName = "walletrpc.WalletKit"
	grpcServer.RegisterService(&walletDesc, &walletKit{
		server: r,
	})

	// Register the signer subserver.
	signerDesc := proto.Signer_ServiceDesc
	signerDesc.ServiceName = "signrpc.Signer"
	grpcServer.RegisterService(&signerDesc, &signerServer{
		server: r,
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
	keyLoc := KeyLocator{
		Family: 6,
		Index:  0,
	}

	sigBytes, err := r.keyRing.SignMessageCompact(
		keyLoc, in.Msg, !in.SingleHash,
	)
	if err != nil {
		return nil, err
	}

	sig := zbase32.EncodeToString(sigBytes)
	return &proto.SignMessageResponse{Signature: sig}, nil
}
