// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 The Lightning Network Developers

package minimalsigner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof" // nolint:gosec // used to set up profiling HTTP handlers.
	"os"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/lightningnetwork/lnd/monitoring"
	"github.com/lightningnetwork/lnd/rpcperms"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/walletunlocker"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon.v2"
)

const (
	// adminMacaroonFilePermissions is the file permission that is used for
	// creating the admin macaroon file.
	//
	// Why 640 is safe:
	// Assuming a reasonably secure Linux system, it will have a
	// separate group for each user. E.g. a new user lnd gets assigned group
	// lnd which nothing else belongs to. A system that does not do this is
	// inherently broken already.
	//
	// Since there is no other user in the group, no other user can read
	// admin macaroon unless the administrator explicitly allowed it. Thus
	// there's no harm allowing group read.
	adminMacaroonFilePermissions = 0640
)

// AdminAuthOptions returns a list of DialOptions that can be used to
// authenticate with the RPC server with admin capabilities.
// skipMacaroons=true should be set if we don't want to include macaroons with
// the auth options. This is needed for instance for the WalletUnlocker
// service, which must be usable also before macaroons are created.
//
// NOTE: This should only be called after the RPCListener has signaled it is
// ready.
func AdminAuthOptions(cfg *Config, skipMacaroons bool) ([]grpc.DialOption,
	error) {

	creds, err := credentials.NewClientTLSFromFile(cfg.TLSCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("unable to read TLS cert: %v", err)
	}

	// Create a dial options array.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	// Get the admin macaroon if macaroons are active.
	if !skipMacaroons && !cfg.NoMacaroons {
		// Load the adming macaroon file.
		macBytes, err := ioutil.ReadFile(cfg.AdminMacPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read macaroon "+
				"path (check the network setting!): %v", err)
		}

		mac := &macaroon.Macaroon{}
		if err = mac.UnmarshalBinary(macBytes); err != nil {
			return nil, fmt.Errorf("unable to decode macaroon: %v",
				err)
		}

		// Now we append the macaroon credentials to the dial options.
		cred, err := macaroons.NewMacaroonCredential(mac)
		if err != nil {
			return nil, fmt.Errorf("error cloning mac: %v", err)
		}
		opts = append(opts, grpc.WithPerRPCCredentials(cred))
	}

	return opts, nil
}

// ListenerWithSignal is a net.Listener that has an additional Ready channel
// that will be closed when a server starts listening.
type ListenerWithSignal struct {
	net.Listener

	// Ready will be closed by the server listening on Listener.
	Ready chan struct{}

	// MacChan is an optional way to pass the admin macaroon to the program
	// that started lnd. The channel should be buffered to avoid lnd being
	// blocked on sending to the channel.
	MacChan chan []byte
}

// ListenerCfg is a wrapper around custom listeners that can be passed to lnd
// when calling its main method.
type ListenerCfg struct {
	// RPCListeners can be set to the listeners to use for the RPC server.
	// If empty a regular network listener will be created.
	RPCListeners []*ListenerWithSignal
}

// Main is the true entry point for lnd. It accepts a fully populated and
// validated main configuration struct and an optional listener config struct.
// This function starts all main system components then blocks until a signal
// is received on the shutdownChan at which point everything is shut down again.
func Main(cfg *Config, lisCfg ListenerCfg, implCfg *ImplementationCfg,
	interceptor signal.Interceptor) error {

	defer func() {
		ltndLog.Info("Shutdown complete\n")
		err := cfg.LogWriter.Close()
		if err != nil {
			ltndLog.Errorf("Could not close log rotator: %v", err)
		}
	}()

	mkErr := func(format string, args ...interface{}) error {
		ltndLog.Errorf("Shutting down because error in main "+
			"method: "+format, args...)
		return fmt.Errorf(format, args...)
	}

	// Show version at startup.
	ltndLog.Infof("Version: %s commit=%s, build=%s, logging=%s, "+
		"debuglevel=%s", build.Version(), build.Commit,
		build.Deployment, build.LoggingType, cfg.DebugLevel)

	var network string
	switch {
	case cfg.TestNet3:
		network = "testnet"

	case cfg.MainNet:
		network = "mainnet"

	case cfg.SimNet:
		network = "simnet"

	case cfg.RegTest:
		network = "regtest"

	case cfg.SigNet:
		network = "signet"
	}

	ltndLog.Infof("Active chain: %v (network=%v)",
		"bitcoin",
		network,
	)

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		go func() {
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			ltndLog.Infof("Pprof listening on %v", cfg.Profile)
			fmt.Println(http.ListenAndServe(cfg.Profile, nil))
		}()
	}

	// Write cpu profile if requested.
	if cfg.CPUProfile != "" {
		f, err := os.Create(cfg.CPUProfile)
		if err != nil {
			return mkErr("unable to create CPU profile: %v", err)
		}
		pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Only process macaroons if --no-macaroons isn't set.
	serverOpts, cleanUp, err := getTLSConfig(cfg)
	if err != nil {
		return mkErr("unable to load TLS credentials: %v", err)
	}

	defer cleanUp()

	// If we have chosen to start with a dedicated listener for the
	// rpc server, we set it directly.
	grpcListeners := append([]*ListenerWithSignal{}, lisCfg.RPCListeners...)
	if len(grpcListeners) == 0 {
		// Otherwise we create listeners from the RPCListeners defined
		// in the config.
		for _, grpcEndpoint := range cfg.RPCListeners {
			// Start a gRPC server listening for HTTP/2
			// connections.
			lis, err := lncfg.ListenOnAddress(grpcEndpoint)
			if err != nil {
				return mkErr("unable to listen on %s: %v",
					grpcEndpoint, err)
			}
			defer lis.Close()

			grpcListeners = append(
				grpcListeners, &ListenerWithSignal{
					Listener: lis,
					Ready:    make(chan struct{}),
				},
			)
		}
	}

	// Create a new RPC interceptor that we'll add to the GRPC server. This
	// will be used to log the API calls invoked on the GRPC server.
	interceptorChain := rpcperms.NewInterceptorChain(
		rpcsLog, cfg.NoMacaroons, cfg.RPCMiddleware.Mandatory,
	)
	if err := interceptorChain.Start(); err != nil {
		return mkErr("error starting interceptor chain: %v", err)
	}
	defer func() {
		err := interceptorChain.Stop()
		if err != nil {
			ltndLog.Warnf("error stopping RPC interceptor "+
				"chain: %v", err)
		}
	}()

	rpcServerOpts := interceptorChain.CreateServerOpts()
	serverOpts = append(serverOpts, rpcServerOpts...)
	serverOpts = append(
		serverOpts, grpc.MaxRecvMsgSize(lnrpc.MaxGrpcMsgSize),
	)

	grpcServer := grpc.NewServer(serverOpts...)
	defer grpcServer.Stop()

	// We'll also register the RPC interceptor chain as the StateServer, as
	// it can be used to query for the current state of the wallet.
	lnrpc.RegisterStateServer(grpcServer, interceptorChain)

	// Initialize, and register our implementation of the gRPC interface
	// exported by the rpcServer.
	rpcServer := newRPCServer(cfg, interceptorChain, implCfg, interceptor)
	err = rpcServer.RegisterWithGrpcServer(grpcServer)
	if err != nil {
		return mkErr("error registering gRPC server: %v", err)
	}

	// Now that both the WalletUnlocker and LightningService have been
	// registered with the GRPC server, we can start listening.
	err = startGrpcListen(cfg, grpcServer, grpcListeners)
	if err != nil {
		return mkErr("error starting gRPC listener: %v", err)
	}

	// Start leader election if we're running on etcd. Continuation will be
	// blocked until this instance is elected as the current leader or
	// shutting down.
	elected := false
	if cfg.Cluster.EnableLeaderElection {
		electionCtx, cancelElection := context.WithCancel(ctx)

		go func() {
			<-interceptor.ShutdownChannel()
			cancelElection()
		}()

		ltndLog.Infof("Using %v leader elector",
			cfg.Cluster.LeaderElector)

		leaderElector, err := cfg.Cluster.MakeLeaderElector(
			electionCtx, cfg.DB,
		)
		if err != nil {
			return err
		}

		defer func() {
			if !elected {
				return
			}

			ltndLog.Infof("Attempting to resign from leader role "+
				"(%v)", cfg.Cluster.ID)

			if err := leaderElector.Resign(); err != nil {
				ltndLog.Errorf("Leader elector failed to "+
					"resign: %v", err)
			}
		}()

		ltndLog.Infof("Starting leadership campaign (%v)",
			cfg.Cluster.ID)

		if err := leaderElector.Campaign(electionCtx); err != nil {
			return mkErr("leadership campaign failed: %v", err)
		}

		elected = true
		ltndLog.Infof("Elected as leader (%v)", cfg.Cluster.ID)
	}

	dbs, cleanUp, err := implCfg.DatabaseBuilder.BuildDatabase(ctx)
	if err != nil {
		return mkErr("unable to open databases: %v", err)
	}

	defer cleanUp()

	partialChainControl, walletConfig, cleanUp, err := implCfg.BuildWalletConfig(
		ctx, dbs, interceptorChain, grpcListeners,
	)
	if err != nil {
		return mkErr("error creating wallet config: %v", err)
	}

	defer cleanUp()

	activeChainControl, cleanUp, err := implCfg.BuildChainControl(
		partialChainControl, walletConfig,
	)
	if err != nil {
		return mkErr("error loading chain control: %v", err)
	}

	defer cleanUp()

	// TODO(roasbeef): add rotation
	idKeyDesc, err := activeChainControl.KeyRing.DeriveKey(
		keychain.KeyLocator{
			Family: keychain.KeyFamilyNodeKey,
			Index:  0,
		},
	)
	if err != nil {
		return mkErr("error deriving node key: %v", err)
	}

	// Set up the core server which will listen for incoming peer
	// connections.
	server := newServer(cfg, dbs, activeChainControl, &idKeyDesc)

	// Now we have created all dependencies necessary to populate and
	// start the RPC server.
	err = rpcServer.addDeps(
		server, interceptorChain.MacaroonService(),
	)
	if err != nil {
		return mkErr("unable to add deps to RPC server: %v", err)
	}
	if err := rpcServer.Start(); err != nil {
		return mkErr("unable to start RPC server: %v", err)
	}
	defer rpcServer.Stop()

	// We transition the RPC state to Active, as the RPC server is up.
	interceptorChain.SetRPCActive()

	if err := interceptor.Notifier.NotifyReady(true); err != nil {
		return mkErr("error notifying ready: %v", err)
	}

	// With all the relevant chains initialized, we can finally start the
	// server itself.
	if err := server.Start(); err != nil {
		return mkErr("unable to start server: %v", err)
	}
	defer server.Stop()

	// We transition the server state to Active, as the server is up.
	interceptorChain.SetServerActive()

	// Wait for shutdown signal from either a graceful server stop or from
	// the interrupt handler.
	<-interceptor.ShutdownChannel()
	return nil
}

// getTLSConfig returns a TLS configuration for the gRPC server.
func getTLSConfig(cfg *Config) ([]grpc.ServerOption, func(), error) {

	// Ensure we create TLS key and certificate if they don't exist.
	if !fileExists(cfg.TLSCertPath) && !fileExists(cfg.TLSKeyPath) {
		rpcsLog.Infof("Generating TLS certificates...")
		err := cert.GenCertPair(
			"lnd autogenerated cert", cfg.TLSCertPath,
			cfg.TLSKeyPath, cfg.TLSExtraIPs, cfg.TLSExtraDomains,
			cfg.TLSDisableAutofill, cfg.TLSCertDuration,
		)
		if err != nil {
			return nil, nil, err
		}
		rpcsLog.Infof("Done generating TLS certificates")
	}

	certData, parsedCert, err := cert.LoadCert(
		cfg.TLSCertPath, cfg.TLSKeyPath,
	)
	if err != nil {
		return nil, nil, err
	}

	// We check whether the certificate we have on disk match the IPs and
	// domains specified by the config. If the extra IPs or domains have
	// changed from when the certificate was created, we will refresh the
	// certificate if auto refresh is active.
	refresh := false
	if cfg.TLSAutoRefresh {
		refresh, err = cert.IsOutdated(
			parsedCert, cfg.TLSExtraIPs,
			cfg.TLSExtraDomains, cfg.TLSDisableAutofill,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	// If the certificate expired or it was outdated, delete it and the TLS
	// key and generate a new pair.
	if time.Now().After(parsedCert.NotAfter) || refresh {
		ltndLog.Info("TLS certificate is expired or outdated, " +
			"generating a new one")

		err := os.Remove(cfg.TLSCertPath)
		if err != nil {
			return nil, nil, err
		}

		err = os.Remove(cfg.TLSKeyPath)
		if err != nil {
			return nil, nil, err
		}

		rpcsLog.Infof("Renewing TLS certificates...")
		err = cert.GenCertPair(
			"lnd autogenerated cert", cfg.TLSCertPath,
			cfg.TLSKeyPath, cfg.TLSExtraIPs, cfg.TLSExtraDomains,
			cfg.TLSDisableAutofill, cfg.TLSCertDuration,
		)
		if err != nil {
			return nil, nil, err
		}
		rpcsLog.Infof("Done renewing TLS certificates")

		// Reload the certificate data.
		certData, _, err = cert.LoadCert(
			cfg.TLSCertPath, cfg.TLSKeyPath,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	tlsCfg := cert.TLSConfFromCert(certData)

	// If Let's Encrypt is enabled, instantiate autocert to request/renew
	// the certificates.
	cleanUp := func() {}
	if cfg.LetsEncryptDomain != "" {
		ltndLog.Infof("Using Let's Encrypt certificate for domain %v",
			cfg.LetsEncryptDomain)

		manager := autocert.Manager{
			Cache:      autocert.DirCache(cfg.LetsEncryptDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.LetsEncryptDomain),
		}

		srv := &http.Server{
			Addr:    cfg.LetsEncryptListen,
			Handler: manager.HTTPHandler(nil),
		}
		shutdownCompleted := make(chan struct{})
		cleanUp = func() {
			err := srv.Shutdown(context.Background())
			if err != nil {
				ltndLog.Errorf("Autocert listener shutdown "+
					" error: %v", err)

				return
			}
			<-shutdownCompleted
			ltndLog.Infof("Autocert challenge listener stopped")
		}

		go func() {
			ltndLog.Infof("Autocert challenge listener started "+
				"at %v", cfg.LetsEncryptListen)

			err := srv.ListenAndServe()
			if err != http.ErrServerClosed {
				ltndLog.Errorf("autocert http: %v", err)
			}
			close(shutdownCompleted)
		}()

		getCertificate := func(h *tls.ClientHelloInfo) (
			*tls.Certificate, error) {

			lecert, err := manager.GetCertificate(h)
			if err != nil {
				ltndLog.Errorf("GetCertificate: %v", err)
				return &certData, nil
			}

			return lecert, err
		}

		// The self-signed tls.cert remains available as fallback.
		tlsCfg.GetCertificate = getCertificate
	}

	serverCreds := credentials.NewTLS(tlsCfg)
	serverOpts := []grpc.ServerOption{grpc.Creds(serverCreds)}

	return serverOpts, cleanUp, nil
}

// fileExists reports whether the named file or directory exists.
// This function is taken from https://github.com/btcsuite/btcd
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// bakeMacaroon creates a new macaroon with newest version and the given
// permissions then returns it binary serialized.
func bakeMacaroon(ctx context.Context, svc *macaroons.Service,
	permissions []bakery.Op) ([]byte, error) {

	mac, err := svc.NewMacaroon(
		ctx, macaroons.DefaultRootKeyID, permissions...,
	)
	if err != nil {
		return nil, err
	}

	return mac.M().MarshalBinary()
}

// genMacaroons generates two macaroon files; one admin-level and one
// read-only. These can also be used to generate more granular macaroons.
func genMacaroons(ctx context.Context, svc *macaroons.Service,
	admFile, roFile string) error {

	// Generate the read-only macaroon and write it to a file.
	roBytes, err := bakeMacaroon(ctx, svc, readPermissions)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(roFile, roBytes, 0644); err != nil {
		_ = os.Remove(roFile)
		return err
	}

	// Generate the admin macaroon and write it to a file.
	admBytes, err := bakeMacaroon(ctx, svc, adminPermissions())
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(admFile, admBytes, adminMacaroonFilePermissions)
	if err != nil {
		_ = os.Remove(admFile)
		return err
	}

	return nil
}

// adminPermissions returns a list of all permissions in a safe way that doesn't
// modify any of the source lists.
func adminPermissions() []bakery.Op {
	admin := make([]bakery.Op, len(readPermissions)+len(writePermissions))
	copy(admin[:len(readPermissions)], readPermissions)
	copy(admin[len(readPermissions):], writePermissions)
	return admin
}

// createWalletUnlockerService creates a WalletUnlockerService from the passed
// config.
func createWalletUnlockerService(cfg *Config) *walletunlocker.UnlockerService {
	// The macaroonFiles are passed to the wallet unlocker so they can be
	// deleted and recreated in case the root macaroon key is also changed
	// during the change password operation.
	macaroonFiles := []string{
		cfg.AdminMacPath, cfg.ReadMacPath,
	}

	return walletunlocker.New(
		cfg.ActiveNetParams.Params, macaroonFiles, false, nil,
	)
}

// startGrpcListen starts the GRPC server on the passed listeners.
func startGrpcListen(cfg *Config, grpcServer *grpc.Server,
	listeners []*ListenerWithSignal) error {

	// Use a WaitGroup so we can be sure the instructions on how to input the
	// password is the last thing to be printed to the console.
	var wg sync.WaitGroup

	for _, lis := range listeners {
		wg.Add(1)
		go func(lis *ListenerWithSignal) {
			rpcsLog.Infof("RPC server listening on %s", lis.Addr())

			// Close the ready chan to indicate we are listening.
			close(lis.Ready)

			wg.Done()
			_ = grpcServer.Serve(lis)
		}(lis)
	}

	// If Prometheus monitoring is enabled, start the Prometheus exporter.
	if cfg.Prometheus.Enabled() {
		err := monitoring.ExportPrometheusMetrics(
			grpcServer, cfg.Prometheus,
		)
		if err != nil {
			return err
		}
	}

	// Wait for gRPC servers to be up running.
	wg.Wait()

	return nil
}
