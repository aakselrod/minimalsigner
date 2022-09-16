// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 The Lightning Network Developers

package minimalsigner

import (
	"context"
	"fmt"
	"net"
	_ "net/http/pprof" // nolint:gosec // used to set up profiling HTTP handlers.
	"os"
	"sync"
	"time"

	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	// signerMacaroonFilePermissions is the file permission that is used for
	// creating the signer macaroon file.
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
	signerMacaroonFilePermissions = 0640
)

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
func Main(cfg *Config, lisCfg ListenerCfg) error {
	// mkErr makes it easy to return logged errors.
	mkErr := func(format string, args ...interface{}) error {
		signerLog.Errorf("Shutting down because error in main "+
			"method: "+format, args...)
		return fmt.Errorf(format, args...)
	}

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

	signerLog.Infof("Active chain: %v (network=%v)",
		"bitcoin",
		network,
	)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	serverOpts, err := getTLSConfig(cfg)
	if err != nil {
		return mkErr("unable to load TLS credentials: %v", err)
	}

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

	grpcServer := grpc.NewServer(serverOpts...)
	defer grpcServer.Stop()

	// Initialize, and register our implementation of the gRPC interface
	// exported by the rpcServer.
	rpcServer := newRPCServer(cfg)
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

	keyRing, err := NewKeyRing(make([]byte, 32), &cfg.ActiveNetParams)
	if err != nil {
		return mkErr("error creating keyring: %v", err)
	}

	idKeyDesc, err := keyRing.DeriveKey(
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
	server := newServer(cfg, keyRing, &idKeyDesc)

	// Now we have created all dependencies necessary to populate and
	// start the RPC server.
	err = rpcServer.addDeps(
		server, nil,
	)
	if err != nil {
		return mkErr("unable to add deps to RPC server: %v", err)
	}

	// Wait for shutdown signal from either a graceful server stop or from
	// the interrupt handler.
	//<-interceptor.ShutdownChannel()
	return nil
}

// getTLSConfig returns a TLS configuration for the gRPC server.
func getTLSConfig(cfg *Config) ([]grpc.ServerOption, error) {

	// Ensure we create TLS key and certificate if they don't exist.
	if !fileExists(cfg.TLSCertPath) && !fileExists(cfg.TLSKeyPath) {
		signerLog.Infof("Generating TLS certificates...")
		err := cert.GenCertPair(
			"signer autogenerated cert", cfg.TLSCertPath,
			cfg.TLSKeyPath, cfg.TLSExtraIPs, cfg.TLSExtraDomains,
			cfg.TLSDisableAutofill, cfg.TLSCertDuration,
		)
		if err != nil {
			return nil, err
		}
		signerLog.Infof("Done generating TLS certificates")
	}

	certData, parsedCert, err := cert.LoadCert(
		cfg.TLSCertPath, cfg.TLSKeyPath,
	)
	if err != nil {
		return nil, err
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
			return nil, err
		}
	}

	// If the certificate expired or it was outdated, delete it and the TLS
	// key and generate a new pair.
	if time.Now().After(parsedCert.NotAfter) || refresh {
		signerLog.Info("TLS certificate is expired or outdated, " +
			"generating a new one")

		err := os.Remove(cfg.TLSCertPath)
		if err != nil {
			return nil, err
		}

		err = os.Remove(cfg.TLSKeyPath)
		if err != nil {
			return nil, err
		}

		signerLog.Infof("Renewing TLS certificates...")
		err = cert.GenCertPair(
			"signer autogenerated cert", cfg.TLSCertPath,
			cfg.TLSKeyPath, cfg.TLSExtraIPs, cfg.TLSExtraDomains,
			cfg.TLSDisableAutofill, cfg.TLSCertDuration,
		)
		if err != nil {
			return nil, err
		}
		signerLog.Infof("Done renewing TLS certificates")

		// Reload the certificate data.
		certData, _, err = cert.LoadCert(
			cfg.TLSCertPath, cfg.TLSKeyPath,
		)
		if err != nil {
			return nil, err
		}
	}

	tlsCfg := cert.TLSConfFromCert(certData)

	serverCreds := credentials.NewTLS(tlsCfg)
	serverOpts := []grpc.ServerOption{grpc.Creds(serverCreds)}

	return serverOpts, nil
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

// startGrpcListen starts the GRPC server on the passed listeners.
func startGrpcListen(cfg *Config, grpcServer *grpc.Server,
	listeners []*ListenerWithSignal) error {

	// Use a WaitGroup so we can be sure the instructions on how to input the
	// password is the last thing to be printed to the console.
	var wg sync.WaitGroup

	for _, lis := range listeners {
		wg.Add(1)
		go func(lis *ListenerWithSignal) {
			signerLog.Infof("RPC server listening on %s", lis.Addr())

			// Close the ready chan to indicate we are listening.
			close(lis.Ready)

			wg.Done()
			_ = grpcServer.Serve(lis)
		}(lis)
	}

	// Wait for gRPC servers to be up running.
	wg.Wait()

	return nil
}
