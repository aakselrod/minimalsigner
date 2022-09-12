package minimalsigner

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
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
			Entity: "offchain",
			Action: "read",
		},
		{
			Entity: "address",
			Action: "read",
		},
		{
			Entity: "message",
			Action: "read",
		},
		{
			Entity: "peers",
			Action: "read",
		},
		{
			Entity: "info",
			Action: "read",
		},
		{
			Entity: "invoices",
			Action: "read",
		},
		{
			Entity: "signer",
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
			Entity: "offchain",
			Action: "write",
		},
		{
			Entity: "address",
			Action: "write",
		},
		{
			Entity: "message",
			Action: "write",
		},
		{
			Entity: "peers",
			Action: "write",
		},
		{
			Entity: "info",
			Action: "write",
		},
		{
			Entity: "invoices",
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

	// invoicePermissions is a slice of all the entities that allows a user
	// to only access calls that are related to invoices, so: streaming
	// RPCs, generating, and listening invoices.
	invoicePermissions = []bakery.Op{
		{
			Entity: "invoices",
			Action: "read",
		},
		{
			Entity: "invoices",
			Action: "write",
		},
		{
			Entity: "address",
			Action: "read",
		},
		{
			Entity: "address",
			Action: "write",
		},
		{
			Entity: "onchain",
			Action: "read",
		},
	}

	// TODO(guggero): Refactor into constants that are used for all
	// permissions in this file. Also expose the list of possible
	// permissions in an RPC when per RPC permissions are
	// implemented.
	validActions  = []string{"read", "write", "generate"}
	validEntities = []string{
		"onchain", "offchain", "address", "message",
		"peers", "info", "invoices", "signer", "macaroon",
		macaroons.PermissionEntityCustomURI,
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
		"/lnrpc.Lightning/SendCoins": {{
			Entity: "onchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/ListUnspent": {{
			Entity: "onchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/SendMany": {{
			Entity: "onchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/NewAddress": {{
			Entity: "address",
			Action: "write",
		}},
		"/lnrpc.Lightning/SignMessage": {{
			Entity: "message",
			Action: "write",
		}},
		"/lnrpc.Lightning/VerifyMessage": {{
			Entity: "message",
			Action: "read",
		}},
		"/lnrpc.Lightning/ConnectPeer": {{
			Entity: "peers",
			Action: "write",
		}},
		"/lnrpc.Lightning/DisconnectPeer": {{
			Entity: "peers",
			Action: "write",
		}},
		"/lnrpc.Lightning/OpenChannel": {{
			Entity: "onchain",
			Action: "write",
		}, {
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/BatchOpenChannel": {{
			Entity: "onchain",
			Action: "write",
		}, {
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/OpenChannelSync": {{
			Entity: "onchain",
			Action: "write",
		}, {
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/CloseChannel": {{
			Entity: "onchain",
			Action: "write",
		}, {
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/AbandonChannel": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/GetInfo": {{
			Entity: "info",
			Action: "read",
		}},
		"/lnrpc.Lightning/GetRecoveryInfo": {{
			Entity: "info",
			Action: "read",
		}},
		"/lnrpc.Lightning/ListPeers": {{
			Entity: "peers",
			Action: "read",
		}},
		"/lnrpc.Lightning/WalletBalance": {{
			Entity: "onchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/EstimateFee": {{
			Entity: "onchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/ChannelBalance": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/PendingChannels": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/ListChannels": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/SubscribeChannelEvents": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/ClosedChannels": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/SendPayment": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/SendPaymentSync": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/SendToRoute": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/SendToRouteSync": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/AddInvoice": {{
			Entity: "invoices",
			Action: "write",
		}},
		"/lnrpc.Lightning/LookupInvoice": {{
			Entity: "invoices",
			Action: "read",
		}},
		"/lnrpc.Lightning/ListInvoices": {{
			Entity: "invoices",
			Action: "read",
		}},
		"/lnrpc.Lightning/SubscribeInvoices": {{
			Entity: "invoices",
			Action: "read",
		}},
		"/lnrpc.Lightning/SubscribeTransactions": {{
			Entity: "onchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/GetTransactions": {{
			Entity: "onchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/DescribeGraph": {{
			Entity: "info",
			Action: "read",
		}},
		"/lnrpc.Lightning/GetNodeMetrics": {{
			Entity: "info",
			Action: "read",
		}},
		"/lnrpc.Lightning/GetChanInfo": {{
			Entity: "info",
			Action: "read",
		}},
		"/lnrpc.Lightning/GetNodeInfo": {{
			Entity: "info",
			Action: "read",
		}},
		"/lnrpc.Lightning/QueryRoutes": {{
			Entity: "info",
			Action: "read",
		}},
		"/lnrpc.Lightning/GetNetworkInfo": {{
			Entity: "info",
			Action: "read",
		}},
		"/lnrpc.Lightning/StopDaemon": {{
			Entity: "info",
			Action: "write",
		}},
		"/lnrpc.Lightning/SubscribeChannelGraph": {{
			Entity: "info",
			Action: "read",
		}},
		"/lnrpc.Lightning/ListPayments": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/DeletePayment": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/DeleteAllPayments": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/DebugLevel": {{
			Entity: "info",
			Action: "write",
		}},
		"/lnrpc.Lightning/DecodePayReq": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/FeeReport": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/UpdateChannelPolicy": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/ForwardingHistory": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/RestoreChannelBackups": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/ExportChannelBackup": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/VerifyChanBackup": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/ExportAllChannelBackups": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/SubscribeChannelBackups": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/ChannelAcceptor": {{
			Entity: "onchain",
			Action: "write",
		}, {
			Entity: "offchain",
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
		"/lnrpc.Lightning/SubscribePeerEvents": {{
			Entity: "peers",
			Action: "read",
		}},
		"/lnrpc.Lightning/FundingStateStep": {{
			Entity: "onchain",
			Action: "write",
		}, {
			Entity: "offchain",
			Action: "write",
		}},
		lnrpc.RegisterRPCMiddlewareURI: {{
			Entity: "macaroon",
			Action: "write",
		}},
		"/lnrpc.Lightning/SendCustomMessage": {{
			Entity: "offchain",
			Action: "write",
		}},
		"/lnrpc.Lightning/SubscribeCustomMessages": {{
			Entity: "offchain",
			Action: "read",
		}},
		"/lnrpc.Lightning/ListAliases": {{
			Entity: "offchain",
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
	lnrpc.UnimplementedLightningServer

	server *server

	cfg *Config

	// subServers are a set of sub-RPC servers that use the same gRPC and
	// listening sockets as the main RPC server, but which maintain their
	// own independent service. This allows us to expose a set of
	// micro-service like abstractions to the outside world for users to
	// consume.
	subServers      []lnrpc.SubServer
	subGrpcHandlers []lnrpc.GrpcHandler

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
var _ lnrpc.LightningServer = (*rpcServer)(nil)

// newRPCServer creates and returns a new instance of the rpcServer. Before
// dependencies are added, this will be an non-functioning RPC server only to
// be used to register the LightningService with the gRPC server.
func newRPCServer(cfg *Config, interceptorChain *rpcperms.InterceptorChain,
	implCfg *ImplementationCfg, interceptor signal.Interceptor) *rpcServer {

	// We go trhough the list of registered sub-servers, and create a gRPC
	// handler for each. These are used to register with the gRPC server
	// before all dependencies are available.
	registeredSubServers := lnrpc.RegisteredSubServers()

	var subServerHandlers []lnrpc.GrpcHandler
	for _, subServer := range registeredSubServers {
		subServerHandlers = append(
			subServerHandlers, subServer.NewGrpcHandler(),
		)
	}

	return &rpcServer{
		cfg:              cfg,
		subGrpcHandlers:  subServerHandlers,
		interceptorChain: interceptorChain,
		implCfg:          implCfg,
		quit:             make(chan struct{}, 1),
		interceptor:      interceptor,
	}
}

// addDeps populates all dependencies needed by the RPC server, and any
// of the sub-servers that it maintains. When this is done, the RPC server can
// be started, and start accepting RPC calls.
func (r *rpcServer) addDeps(s *server, macService *macaroons.Service,
	subServerCgs *subRPCServerConfigs) error {

	var (
		subServers     []lnrpc.SubServer
		subServerPerms []lnrpc.MacaroonPerms
	)

	// Before we create any of the sub-servers, we need to ensure that all
	// the dependencies they need are properly populated within each sub
	// server configuration struct.
	//
	// TODO(roasbeef): extend sub-sever config to have both (local vs remote) DB
	err := subServerCgs.PopulateDependencies(
		r.cfg, s.cc, r.cfg.networkDir, macService, s.nodeSigner,
		s.sweeper, r.cfg.ActiveNetParams.Params, rpcsLog,
	)
	if err != nil {
		return err
	}

	// Now that the sub-servers have all their dependencies in place, we
	// can create each sub-server!
	for _, subServerInstance := range r.subGrpcHandlers {
		subServer, macPerms, err := subServerInstance.CreateSubServer(
			subServerCgs,
		)
		if err != nil {
			return err
		}

		// We'll collect the sub-server, and also the set of
		// permissions it needs for macaroons so we can apply the
		// interceptors below.
		subServers = append(subServers, subServer)
		subServerPerms = append(subServerPerms, macPerms)
	}

	// Next, we need to merge the set of sub server macaroon permissions
	// with the main RPC server permissions so we can unite them under a
	// single set of interceptors.
	for m, ops := range MainRPCServerPermissions() {
		err := r.interceptorChain.AddPermission(m, ops)
		if err != nil {
			return err
		}
	}

	for _, subServerPerm := range subServerPerms {
		for method, ops := range subServerPerm {
			err := r.interceptorChain.AddPermission(method, ops)
			if err != nil {
				return err
			}
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
	r.subServers = subServers
	r.macService = macService

	return nil
}

// RegisterWithGrpcServer registers the rpcServer and any subservers with the
// root gRPC server.
func (r *rpcServer) RegisterWithGrpcServer(grpcServer *grpc.Server) error {
	// Register the main RPC server.
	lnrpc.RegisterLightningServer(grpcServer, r)

	// Now the main RPC server has been registered, we'll iterate through
	// all the sub-RPC servers and register them to ensure that requests
	// are properly routed towards them.
	for _, subServer := range r.subGrpcHandlers {
		err := subServer.RegisterWithRootServer(grpcServer)
		if err != nil {
			return fmt.Errorf("unable to register "+
				"sub-server with root: %v", err)
		}
	}

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

	// First, we'll start all the sub-servers to ensure that they're ready
	// to take new requests in.
	//
	// TODO(roasbeef): some may require that the entire daemon be started
	// at that point
	for _, subServer := range r.subServers {
		rpcsLog.Debugf("Starting sub RPC server: %v", subServer.Name())

		if err := subServer.Start(); err != nil {
			return err
		}
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

	// After we've signalled all of our active goroutines to exit, we'll
	// then do the same to signal a graceful shutdown of all the sub
	// servers.
	for _, subServer := range r.subServers {
		rpcsLog.Infof("Stopping %v Sub-RPC Server",
			subServer.Name())

		if err := subServer.Stop(); err != nil {
			rpcsLog.Errorf("unable to stop sub-server %v: %v",
				subServer.Name(), err)
			continue
		}
	}

	return nil
}

// allowCORS wraps the given http.Handler with a function that adds the
// Access-Control-Allow-Origin header to the response.
func allowCORS(handler http.Handler, origins []string) http.Handler {
	allowHeaders := "Access-Control-Allow-Headers"
	allowMethods := "Access-Control-Allow-Methods"
	allowOrigin := "Access-Control-Allow-Origin"

	// If the user didn't supply any origins that means CORS is disabled
	// and we should return the original handler.
	if len(origins) == 0 {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Skip everything if the browser doesn't send the Origin field.
		if origin == "" {
			handler.ServeHTTP(w, r)
			return
		}

		// Set the static header fields first.
		w.Header().Set(
			allowHeaders,
			"Content-Type, Accept, Grpc-Metadata-Macaroon",
		)
		w.Header().Set(allowMethods, "GET, POST, DELETE")

		// Either we allow all origins or the incoming request matches
		// a specific origin in our list of allowed origins.
		for _, allowedOrigin := range origins {
			if allowedOrigin == "*" || origin == allowedOrigin {
				// Only set allowed origin to requested origin.
				w.Header().Set(allowOrigin, origin)

				break
			}
		}

		// For a pre-flight request we only need to send the headers
		// back. No need to call the rest of the chain.
		if r.Method == "OPTIONS" {
			return
		}

		// Everything's prepared now, we can pass the request along the
		// chain of handlers.
		handler.ServeHTTP(w, r)
	})
}

// NewAddress creates a new address under control of the local wallet.
func (r *rpcServer) NewAddress(ctx context.Context,
	in *lnrpc.NewAddressRequest) (*lnrpc.NewAddressResponse, error) {

	// Always use the default wallet account unless one was specified.
	account := lnwallet.DefaultAccountName
	if in.Account != "" {
		account = in.Account
	}

	// Translate the gRPC proto address type to the wallet controller's
	// available address types.
	var (
		addr btcutil.Address
		err  error
	)
	switch in.Type {
	case lnrpc.AddressType_WITNESS_PUBKEY_HASH:
		addr, err = r.server.cc.Wallet.NewAddress(
			lnwallet.WitnessPubKey, false, account,
		)
		if err != nil {
			return nil, err
		}

	case lnrpc.AddressType_NESTED_PUBKEY_HASH:
		addr, err = r.server.cc.Wallet.NewAddress(
			lnwallet.NestedWitnessPubKey, false, account,
		)
		if err != nil {
			return nil, err
		}

	case lnrpc.AddressType_TAPROOT_PUBKEY:
		addr, err = r.server.cc.Wallet.NewAddress(
			lnwallet.TaprootPubkey, false, account,
		)
		if err != nil {
			return nil, err
		}

	case lnrpc.AddressType_UNUSED_WITNESS_PUBKEY_HASH:
		addr, err = r.server.cc.Wallet.LastUnusedAddress(
			lnwallet.WitnessPubKey, account,
		)
		if err != nil {
			return nil, err
		}

	case lnrpc.AddressType_UNUSED_NESTED_PUBKEY_HASH:
		addr, err = r.server.cc.Wallet.LastUnusedAddress(
			lnwallet.NestedWitnessPubKey, account,
		)
		if err != nil {
			return nil, err
		}

	case lnrpc.AddressType_UNUSED_TAPROOT_PUBKEY:
		addr, err = r.server.cc.Wallet.LastUnusedAddress(
			lnwallet.TaprootPubkey, account,
		)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unknown address type: %v", in.Type)
	}

	rpcsLog.Debugf("[newaddress] account=%v type=%v addr=%v", account,
		in.Type, addr.String())
	return &lnrpc.NewAddressResponse{Address: addr.String()}, nil
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
	in *lnrpc.SignMessageRequest) (*lnrpc.SignMessageResponse, error) {

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
	return &lnrpc.SignMessageResponse{Signature: sig}, nil
}

// GetInfo returns general information concerning the lightning node including
// its identity pubkey, alias, the chains it is connected to, and information
// concerning the number of open+pending channels.
func (r *rpcServer) GetInfo(_ context.Context,
	_ *lnrpc.GetInfoRequest) (*lnrpc.GetInfoResponse, error) {

	idPub := r.server.identityECDH.PubKey().SerializeCompressed()
	encodedIDPub := hex.EncodeToString(idPub)

	network := lncfg.NormalizeNetwork(r.cfg.ActiveNetParams.Name)
	activeChains := make([]*lnrpc.Chain, r.cfg.registeredChains.NumActiveChains())
	for i, chain := range r.cfg.registeredChains.ActiveChains() {
		activeChains[i] = &lnrpc.Chain{
			Chain:   chain.String(),
			Network: network,
		}
	}

	// TODO(roasbeef): add synced height n stuff
	return &lnrpc.GetInfoResponse{
		IdentityPubkey: encodedIDPub,
		Chains:         activeChains,
		Version:        build.Version() + " commit=" + build.Commit,
		CommitHash:     build.CommitHash,
	}, nil
}

// StopDaemon will send a shutdown request to the interrupt handler, triggering
// a graceful shutdown of the daemon.
func (r *rpcServer) StopDaemon(_ context.Context,
	_ *lnrpc.StopRequest) (*lnrpc.StopResponse, error) {

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
	return &lnrpc.StopResponse{}, nil
}

// DebugLevel allows a caller to programmatically set the logging verbosity of
// lnd. The logging can be targeted according to a coarse daemon-wide logging
// level, or in a granular fashion to specify the logging for a target
// sub-system.
func (r *rpcServer) DebugLevel(ctx context.Context,
	req *lnrpc.DebugLevelRequest) (*lnrpc.DebugLevelResponse, error) {

	// If show is set, then we simply print out the list of available
	// sub-systems.
	if req.Show {
		return &lnrpc.DebugLevelResponse{
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

	return &lnrpc.DebugLevelResponse{}, nil
}

// BakeMacaroon allows the creation of a new macaroon with custom read and write
// permissions. No first-party caveats are added since this can be done offline.
// If the --allow-external-permissions flag is set, the RPC will allow
// external permissions that LND is not aware of.
func (r *rpcServer) BakeMacaroon(ctx context.Context,
	req *lnrpc.BakeMacaroonRequest) (*lnrpc.BakeMacaroonResponse, error) {

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
	resp := &lnrpc.BakeMacaroonResponse{}
	resp.Macaroon = hex.EncodeToString(newMacBytes)

	return resp, nil
}

// ListMacaroonIDs returns a list of macaroon root key IDs in use.
func (r *rpcServer) ListMacaroonIDs(ctx context.Context,
	req *lnrpc.ListMacaroonIDsRequest) (
	*lnrpc.ListMacaroonIDsResponse, error) {

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

	return &lnrpc.ListMacaroonIDsResponse{RootKeyIds: rootKeyIDs}, nil
}

// DeleteMacaroonID removes a specific macaroon ID.
func (r *rpcServer) DeleteMacaroonID(ctx context.Context,
	req *lnrpc.DeleteMacaroonIDRequest) (
	*lnrpc.DeleteMacaroonIDResponse, error) {

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

	return &lnrpc.DeleteMacaroonIDResponse{
		// If the root key ID doesn't exist, it won't be deleted. We
		// will return a response with deleted = false, otherwise true.
		Deleted: deletedIDBytes != nil,
	}, nil
}

// ListPermissions lists all RPC method URIs and their required macaroon
// permissions to access them.
func (r *rpcServer) ListPermissions(_ context.Context,
	_ *lnrpc.ListPermissionsRequest) (*lnrpc.ListPermissionsResponse,
	error) {

	rpcsLog.Debugf("[listpermissions]")

	permissionMap := make(map[string]*lnrpc.MacaroonPermissionList)
	for uri, perms := range r.interceptorChain.Permissions() {
		rpcPerms := make([]*lnrpc.MacaroonPermission, len(perms))
		for idx, perm := range perms {
			rpcPerms[idx] = &lnrpc.MacaroonPermission{
				Entity: perm.Entity,
				Action: perm.Action,
			}
		}
		permissionMap[uri] = &lnrpc.MacaroonPermissionList{
			Permissions: rpcPerms,
		}
	}

	return &lnrpc.ListPermissionsResponse{
		MethodPermissions: permissionMap,
	}, nil
}

// CheckMacaroonPermissions checks the caveats and permissions of a macaroon.
func (r *rpcServer) CheckMacaroonPermissions(ctx context.Context,
	req *lnrpc.CheckMacPermRequest) (*lnrpc.CheckMacPermResponse, error) {

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

	return &lnrpc.CheckMacPermResponse{
		Valid: true,
	}, nil
}

// RegisterRPCMiddleware adds a new gRPC middleware to the interceptor chain. A
// gRPC middleware is software component external to lnd that aims to add
// additional business logic to lnd by observing/intercepting/validating
// incoming gRPC client requests and (if needed) replacing/overwriting outgoing
// messages before they're sent to the client. When registering the middleware
// must identify itself and indicate what custom macaroon caveats it wants to
// be responsible for. Only requests that contain a macaroon with that specific
// custom caveat are then sent to the middleware for inspection. As a security
// measure, _no_ middleware can intercept requests made with _unencumbered_
// macaroons!
func (r *rpcServer) RegisterRPCMiddleware(
	stream lnrpc.Lightning_RegisterRPCMiddlewareServer) error {

	// This is a security critical functionality and needs to be enabled
	// specifically by the user.
	if !r.cfg.RPCMiddleware.Enable {
		return fmt.Errorf("RPC middleware not enabled in config")
	}

	// When registering a middleware the first message being sent from the
	// middleware must be a registration message containing its name and the
	// custom caveat it wants to register for.
	var (
		registerChan     = make(chan *lnrpc.MiddlewareRegistration, 1)
		registerDoneChan = make(chan struct{})
		errChan          = make(chan error, 1)
	)
	ctxc, cancel := context.WithTimeout(
		stream.Context(), r.cfg.RPCMiddleware.InterceptTimeout,
	)
	defer cancel()

	// Read the first message in a goroutine because the Recv method blocks
	// until the message arrives.
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			errChan <- err

			return
		}

		registerChan <- msg.GetRegister()
	}()

	// Wait for the initial message to arrive or time out if it takes too
	// long.
	var registerMsg *lnrpc.MiddlewareRegistration
	select {
	case registerMsg = <-registerChan:
		if registerMsg == nil {
			return fmt.Errorf("invalid initial middleware " +
				"registration message")
		}

	case err := <-errChan:
		return fmt.Errorf("error receiving initial middleware "+
			"registration message: %v", err)

	case <-ctxc.Done():
		return ctxc.Err()

	case <-r.quit:
		return ErrServerShuttingDown
	}

	// Make sure the registration is valid.
	const nameMinLength = 5
	if len(registerMsg.MiddlewareName) < nameMinLength {
		return fmt.Errorf("invalid middleware name, use descriptive "+
			"name of at least %d characters", nameMinLength)
	}

	readOnly := registerMsg.ReadOnlyMode
	caveatName := registerMsg.CustomMacaroonCaveatName
	switch {
	case readOnly && len(caveatName) > 0:
		return fmt.Errorf("cannot set read-only and custom caveat " +
			"name at the same time")

	case !readOnly && len(caveatName) < nameMinLength:
		return fmt.Errorf("need to set either custom caveat name "+
			"of at least %d characters or read-only mode",
			nameMinLength)
	}

	middleware := rpcperms.NewMiddlewareHandler(
		registerMsg.MiddlewareName,
		caveatName, readOnly, stream.Recv, stream.Send,
		r.cfg.RPCMiddleware.InterceptTimeout,
		r.cfg.ActiveNetParams.Params, r.quit,
	)

	// Add the RPC middleware to the interceptor chain and defer its
	// removal.
	if err := r.interceptorChain.RegisterMiddleware(middleware); err != nil {
		return fmt.Errorf("error registering middleware: %v", err)
	}
	defer r.interceptorChain.RemoveMiddleware(registerMsg.MiddlewareName)

	// Send a message to the client to indicate that the registration has
	// successfully completed.
	regCompleteMsg := &lnrpc.RPCMiddlewareRequest{
		InterceptType: &lnrpc.RPCMiddlewareRequest_RegComplete{
			RegComplete: true,
		},
	}

	// Send the message in a goroutine because the Send method blocks until
	// the message is read by the client.
	go func() {
		err := stream.Send(regCompleteMsg)
		if err != nil {
			errChan <- err
			return
		}

		close(registerDoneChan)
	}()

	select {
	case err := <-errChan:
		return fmt.Errorf("error sending middleware registration "+
			"complete message: %v", err)

	case <-ctxc.Done():
		return ctxc.Err()

	case <-r.quit:
		return ErrServerShuttingDown

	case <-registerDoneChan:
	}

	return middleware.Run()
}
