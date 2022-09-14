package minimalsigner

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/aakselrod/minimalsigner/proto"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/lightningnetwork/lnd/rpcperms"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/tv42/zbase32"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

var (
	// readPermissions is a slice of all entities that allow read
	// permissions for authorization purposes, all lowercase.
	readPermissions = []bakery.Op{
		{
			Entity: "onchain",
			Action: "read",
		},
		{
			Entity: "address",
			Action: "read",
		},
		{
			Entity: "info",
			Action: "read",
		},
		{
			Entity: "macaroon",
			Action: "read",
		},
	}

	// writePermissions is a slice of all entities that allow write
	// permissions for authorization purposes, all lowercase.
	writePermissions = []bakery.Op{
		{
			Entity: "onchain",
			Action: "write",
		},
		{
			Entity: "message",
			Action: "write",
		},
		{
			Entity: "info",
			Action: "write",
		},
		{
			Entity: "signer",
			Action: "generate",
		},
		{
			Entity: "macaroon",
			Action: "generate",
		},
		{
			Entity: "macaroon",
			Action: "write",
		},
	}

	// TODO(guggero): Refactor into constants that are used for all
	// permissions in this file. Also expose the list of possible
	// permissions in an RPC when per RPC permissions are
	// implemented.
	validActions  = []string{"read", "write", "generate"}
	validEntities = []string{
		"onchain", "address", "message",
		"info", "signer", "macaroon",
	}

	// If the --no-macaroons flag is used to start lnd, the macaroon service
	// is not initialized. errMacaroonDisabled is then returned when
	// macaroon related services are used.
	errMacaroonDisabled = fmt.Errorf("macaroon authentication disabled, " +
		"remove --no-macaroons flag to enable")
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
		"/lnrpc.Lightning/GetInfo": {{
			Entity: "info",
			Action: "read",
		}},
		"/lnrpc.Lightning/StopDaemon": {{
			Entity: "info",
			Action: "write",
		}},
		"/lnrpc.Lightning/DebugLevel": {{
			Entity: "info",
			Action: "write",
		}},
		"/lnrpc.Lightning/BakeMacaroon": {{
			Entity: "macaroon",
			Action: "generate",
		}},
		"/lnrpc.Lightning/ListMacaroonIDs": {{
			Entity: "macaroon",
			Action: "read",
		}},
		"/lnrpc.Lightning/DeleteMacaroonID": {{
			Entity: "macaroon",
			Action: "write",
		}},
		"/lnrpc.Lightning/ListPermissions": {{
			Entity: "info",
			Action: "read",
		}},
		"/lnrpc.Lightning/CheckMacaroonPermissions": {{
			Entity: "macaroon",
			Action: "read",
		}},
	}
}

// rpcServer is a gRPC, RPC front end to the lnd daemon.
// TODO(roasbeef): pagination support for the list-style calls
type rpcServer struct {
	started  int32 // To be used atomically.
	shutdown int32 // To be used atomically.

	// Required by the grpc-gateway/v2 library for forward compatibility.
	// Must be after the atomically used variables to not break struct
	// alignment.
	proto.UnimplementedLightningServer

	server *server

	cfg *Config

	quit chan struct{}

	// macService is the macaroon service that we need to mint new
	// macaroons.
	macService *macaroons.Service

	// interceptorChain is the interceptor added to our gRPC server.
	interceptorChain *rpcperms.InterceptorChain

	// implCfg is the configuration for some of the interfaces that can be
	// provided externally.
	implCfg *ImplementationCfg

	// interceptor is used to be able to request a shutdown
	interceptor signal.Interceptor
}

// A compile time check to ensure that rpcServer fully implements the
// LightningServer gRPC service.
var _ proto.LightningServer = (*rpcServer)(nil)

// newRPCServer creates and returns a new instance of the rpcServer. Before
// dependencies are added, this will be an non-functioning RPC server only to
// be used to register the LightningService with the gRPC server.
func newRPCServer(cfg *Config, interceptorChain *rpcperms.InterceptorChain,
	implCfg *ImplementationCfg, interceptor signal.Interceptor) *rpcServer {

	return &rpcServer{
		cfg:              cfg,
		interceptorChain: interceptorChain,
		implCfg:          implCfg,
		quit:             make(chan struct{}, 1),
		interceptor:      interceptor,
	}
}

// addDeps populates all dependencies needed by the RPC server, and any
// of the sub-servers that it maintains. When this is done, the RPC server can
// be started, and start accepting RPC calls.
func (r *rpcServer) addDeps(s *server, macService *macaroons.Service) error {

	// Next, we need to merge the set of sub server macaroon permissions
	// with the main RPC server permissions so we can unite them under a
	// single set of interceptors.
	for m, ops := range MainRPCServerPermissions() {
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
	}

	// External subserver possibly need to register their own permissions
	// and macaroon validator.
	for method, ops := range r.implCfg.ExternalValidator.Permissions() {
		err := r.interceptorChain.AddPermission(method, ops)
		if err != nil {
			return err
		}

		// Give the external subservers the possibility to also use
		// their own validator to check any macaroons attached to calls
		// to this method. This allows them to have their own root key
		// ID database and permission entities.
		err = macService.RegisterExternalValidator(
			method, r.implCfg.ExternalValidator,
		)
		if err != nil {
			return fmt.Errorf("could not register external "+
				"macaroon validator: %v", err)
		}
	}

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
		wallet: r.server.cc.Wallet,
	})

	// Register the signer subserver.
	proto.RegisterSignerServer(grpcServer, &signerServer{
		wallet: r.server.cc.Wallet,
	})

	// Before actually listening on the gRPC listener, give external
	// subservers the chance to register to our gRPC server. Those external
	// subservers (think GrUB) are responsible for starting/stopping on
	// their own, we just let them register their services to the same
	// server instance so all of them can be exposed on the same
	// port/listener.
	err := r.implCfg.RegisterGrpcSubserver(grpcServer)
	if err != nil {
		rpcsLog.Errorf("error registering external gRPC "+
			"subserver: %v", err)
	}

	return nil
}

// Start launches any helper goroutines required for the rpcServer to function.
func (r *rpcServer) Start() error {
	if atomic.AddInt32(&r.started, 1) != 1 {
		return nil
	}

	return nil
}

// Stop signals any active goroutines for a graceful closure.
func (r *rpcServer) Stop() error {
	if atomic.AddInt32(&r.shutdown, 1) != 1 {
		return nil
	}

	rpcsLog.Infof("Stopping RPC Server")

	close(r.quit)

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

// GetInfo returns general information concerning the lightning node including
// its identity pubkey, alias, the chains it is connected to, and information
// concerning the number of open+pending channels.
func (r *rpcServer) GetInfo(_ context.Context,
	_ *proto.GetInfoRequest) (*proto.GetInfoResponse, error) {

	idPub := r.server.identityECDH.PubKey().SerializeCompressed()
	encodedIDPub := hex.EncodeToString(idPub)

	network := lncfg.NormalizeNetwork(r.cfg.ActiveNetParams.Name)
	activeChains := make([]*proto.Chain, 1)
	activeChains[0] = &proto.Chain{
		Chain:   chainreg.BitcoinChain.String(),
		Network: network,
	}

	return &proto.GetInfoResponse{
		IdentityPubkey: encodedIDPub,
		Chains:         activeChains,
		Version:        build.Version() + " commit=" + build.Commit,
		CommitHash:     build.CommitHash,
	}, nil
}

// StopDaemon will send a shutdown request to the interrupt handler, triggering
// a graceful shutdown of the daemon.
func (r *rpcServer) StopDaemon(_ context.Context,
	_ *proto.StopRequest) (*proto.StopResponse, error) {

	// Before we even consider a shutdown, are we currently in recovery
	// mode? We don't want to allow shutting down during recovery because
	// that would mean the user would have to manually continue the rescan
	// process next time by using `lncli unlock --recovery_window X`
	// otherwise some funds wouldn't be picked up.
	isRecoveryMode, progress, err := r.server.cc.Wallet.GetRecoveryInfo()
	if err != nil {
		return nil, fmt.Errorf("unable to get wallet recovery info: %v",
			err)
	}
	if isRecoveryMode && progress < 1 {
		return nil, fmt.Errorf("wallet recovery in progress, cannot " +
			"shut down, please wait until rescan finishes")
	}

	r.interceptor.RequestShutdown()
	return &proto.StopResponse{}, nil
}

// DebugLevel allows a caller to programmatically set the logging verbosity of
// lnd. The logging can be targeted according to a coarse daemon-wide logging
// level, or in a granular fashion to specify the logging for a target
// sub-system.
func (r *rpcServer) DebugLevel(ctx context.Context,
	req *proto.DebugLevelRequest) (*proto.DebugLevelResponse, error) {

	// If show is set, then we simply print out the list of available
	// sub-systems.
	if req.Show {
		return &proto.DebugLevelResponse{
			SubSystems: strings.Join(
				r.cfg.LogWriter.SupportedSubsystems(), " ",
			),
		}, nil
	}

	rpcsLog.Infof("[debuglevel] changing debug level to: %v", req.LevelSpec)

	// Otherwise, we'll attempt to set the logging level using the
	// specified level spec.
	err := build.ParseAndSetDebugLevels(req.LevelSpec, r.cfg.LogWriter)
	if err != nil {
		return nil, err
	}

	return &proto.DebugLevelResponse{}, nil
}

// BakeMacaroon allows the creation of a new macaroon with custom read and write
// permissions. No first-party caveats are added since this can be done offline.
// If the --allow-external-permissions flag is set, the RPC will allow
// external permissions that LND is not aware of.
func (r *rpcServer) BakeMacaroon(ctx context.Context,
	req *proto.BakeMacaroonRequest) (*proto.BakeMacaroonResponse, error) {

	rpcsLog.Debugf("[bakemacaroon]")

	// If the --no-macaroons flag is used to start lnd, the macaroon service
	// is not initialized. Therefore we can't bake new macaroons.
	if r.macService == nil {
		return nil, errMacaroonDisabled
	}

	helpMsg := fmt.Sprintf("supported actions are %v, supported entities "+
		"are %v", validActions, validEntities)

	// Don't allow empty permission list as it doesn't make sense to have
	// a macaroon that is not allowed to access any RPC.
	if len(req.Permissions) == 0 {
		return nil, fmt.Errorf("permission list cannot be empty. "+
			"specify at least one action/entity pair. %s", helpMsg)
	}

	// Validate and map permission struct used by gRPC to the one used by
	// the bakery. If the --allow-external-permissions flag is set, we
	// will not validate, but map.
	requestedPermissions := make([]bakery.Op, len(req.Permissions))
	for idx, op := range req.Permissions {
		if req.AllowExternalPermissions {
			requestedPermissions[idx] = bakery.Op{
				Entity: op.Entity,
				Action: op.Action,
			}
			continue
		}

		if !stringInSlice(op.Entity, validEntities) {
			return nil, fmt.Errorf("invalid permission entity. %s",
				helpMsg)
		}

		// Either we have the special entity "uri" which specifies a
		// full gRPC URI or we have one of the pre-defined actions.
		if op.Entity == macaroons.PermissionEntityCustomURI {
			allPermissions := r.interceptorChain.Permissions()
			_, ok := allPermissions[op.Action]
			if !ok {
				return nil, fmt.Errorf("invalid permission " +
					"action, must be an existing URI in " +
					"the format /package.Service/" +
					"MethodName")
			}
		} else if !stringInSlice(op.Action, validActions) {
			return nil, fmt.Errorf("invalid permission action. %s",
				helpMsg)
		}

		requestedPermissions[idx] = bakery.Op{
			Entity: op.Entity,
			Action: op.Action,
		}
	}

	// Convert root key id from uint64 to bytes. Because the
	// DefaultRootKeyID is a digit 0 expressed in a byte slice of a string
	// "0", we will keep the IDs in the same format - all must be numeric,
	// and must be a byte slice of string value of the digit, e.g.,
	// uint64(123) to string(123).
	rootKeyID := []byte(strconv.FormatUint(req.RootKeyId, 10))

	// Bake new macaroon with the given permissions and send it binary
	// serialized and hex encoded to the client.
	newMac, err := r.macService.NewMacaroon(
		ctx, rootKeyID, requestedPermissions...,
	)
	if err != nil {
		return nil, err
	}
	newMacBytes, err := newMac.M().MarshalBinary()
	if err != nil {
		return nil, err
	}
	resp := &proto.BakeMacaroonResponse{}
	resp.Macaroon = hex.EncodeToString(newMacBytes)

	return resp, nil
}

// ListMacaroonIDs returns a list of macaroon root key IDs in use.
func (r *rpcServer) ListMacaroonIDs(ctx context.Context,
	req *proto.ListMacaroonIDsRequest) (
	*proto.ListMacaroonIDsResponse, error) {

	rpcsLog.Debugf("[listmacaroonids]")

	// If the --no-macaroons flag is used to start lnd, the macaroon service
	// is not initialized. Therefore we can't show any IDs.
	if r.macService == nil {
		return nil, errMacaroonDisabled
	}

	rootKeyIDByteSlice, err := r.macService.ListMacaroonIDs(ctx)
	if err != nil {
		return nil, err
	}

	var rootKeyIDs []uint64
	for _, value := range rootKeyIDByteSlice {
		// Convert bytes into uint64.
		id, err := strconv.ParseUint(string(value), 10, 64)
		if err != nil {
			return nil, err
		}

		rootKeyIDs = append(rootKeyIDs, id)
	}

	return &proto.ListMacaroonIDsResponse{RootKeyIds: rootKeyIDs}, nil
}

// DeleteMacaroonID removes a specific macaroon ID.
func (r *rpcServer) DeleteMacaroonID(ctx context.Context,
	req *proto.DeleteMacaroonIDRequest) (
	*proto.DeleteMacaroonIDResponse, error) {

	rpcsLog.Debugf("[deletemacaroonid]")

	// If the --no-macaroons flag is used to start lnd, the macaroon service
	// is not initialized. Therefore we can't delete any IDs.
	if r.macService == nil {
		return nil, errMacaroonDisabled
	}

	// Convert root key id from uint64 to bytes. Because the
	// DefaultRootKeyID is a digit 0 expressed in a byte slice of a string
	// "0", we will keep the IDs in the same format - all must be digit, and
	// must be a byte slice of string value of the digit.
	rootKeyID := []byte(strconv.FormatUint(req.RootKeyId, 10))
	deletedIDBytes, err := r.macService.DeleteMacaroonID(ctx, rootKeyID)
	if err != nil {
		return nil, err
	}

	return &proto.DeleteMacaroonIDResponse{
		// If the root key ID doesn't exist, it won't be deleted. We
		// will return a response with deleted = false, otherwise true.
		Deleted: deletedIDBytes != nil,
	}, nil
}

// ListPermissions lists all RPC method URIs and their required macaroon
// permissions to access them.
func (r *rpcServer) ListPermissions(_ context.Context,
	_ *proto.ListPermissionsRequest) (*proto.ListPermissionsResponse,
	error) {

	rpcsLog.Debugf("[listpermissions]")

	permissionMap := make(map[string]*proto.MacaroonPermissionList)
	for uri, perms := range r.interceptorChain.Permissions() {
		rpcPerms := make([]*proto.MacaroonPermission, len(perms))
		for idx, perm := range perms {
			rpcPerms[idx] = &proto.MacaroonPermission{
				Entity: perm.Entity,
				Action: perm.Action,
			}
		}
		permissionMap[uri] = &proto.MacaroonPermissionList{
			Permissions: rpcPerms,
		}
	}

	return &proto.ListPermissionsResponse{
		MethodPermissions: permissionMap,
	}, nil
}

// CheckMacaroonPermissions checks the caveats and permissions of a macaroon.
func (r *rpcServer) CheckMacaroonPermissions(ctx context.Context,
	req *proto.CheckMacPermRequest) (*proto.CheckMacPermResponse, error) {

	// Turn grpc macaroon permission into bakery.Op for the server to
	// process.
	permissions := make([]bakery.Op, len(req.Permissions))
	for idx, perm := range req.Permissions {
		permissions[idx] = bakery.Op{
			Entity: perm.Entity,
			Action: perm.Action,
		}
	}

	err := r.macService.CheckMacAuth(
		ctx, req.Macaroon, permissions, req.FullMethod,
	)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &proto.CheckMacPermResponse{
		Valid: true,
	}, nil
}
