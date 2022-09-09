package minimalsigner

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/healthcheck"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/netann"
	"github.com/lightningnetwork/lnd/peer"
	"github.com/lightningnetwork/lnd/pool"
	"github.com/lightningnetwork/lnd/subscribe"
)

const (
	// defaultMinPeers is the minimum number of peers nodes should always be
	// connected to.
	defaultMinPeers = 3

	// defaultStableConnDuration is a floor under which all reconnection
	// attempts will apply exponential randomized backoff. Connections
	// durations exceeding this value will be eligible to have their
	// backoffs reduced.
	defaultStableConnDuration = 10 * time.Minute

	// numInstantInitReconnect specifies how many persistent peers we should
	// always attempt outbound connections to immediately. After this value
	// is surpassed, the remaining peers will be randomly delayed using
	// maxInitReconnectDelay.
	numInstantInitReconnect = 10

	// maxInitReconnectDelay specifies the maximum delay in seconds we will
	// apply in attempting to reconnect to persistent peers on startup. The
	// value used or a particular peer will be chosen between 0s and this
	// value.
	maxInitReconnectDelay = 30

	// multiAddrConnectionStagger is the number of seconds to wait between
	// attempting to a peer with each of its advertised addresses.
	multiAddrConnectionStagger = 10 * time.Second
)

var (
	// ErrPeerNotConnected signals that the server has no connection to the
	// given peer.
	ErrPeerNotConnected = errors.New("peer is not connected")

	// ErrServerNotActive indicates that the server has started but hasn't
	// fully finished the startup process.
	ErrServerNotActive = errors.New("server is still in the process of " +
		"starting")

	// ErrServerShuttingDown indicates that the server is in the process of
	// gracefully exiting.
	ErrServerShuttingDown = errors.New("server is shutting down")

	// MaxFundingAmount is a soft-limit of the maximum channel size
	// currently accepted within the Lightning Protocol. This is
	// defined in BOLT-0002, and serves as an initial precautionary limit
	// while implementations are battle tested in the real world.
	//
	// At the moment, this value depends on which chain is active. It is set
	// to the value under the Bitcoin chain as default.
	//
	// TODO(roasbeef): add command line param to modify.
	MaxFundingAmount = funding.MaxBtcFundingAmount
)

// errPeerAlreadyConnected is an error returned by the server when we're
// commanded to connect to a peer, but they're already connected.
type errPeerAlreadyConnected struct {
	peer *peer.Brontide
}

// Error returns the human readable version of this error type.
//
// NOTE: Part of the error interface.
func (e *errPeerAlreadyConnected) Error() string {
	return fmt.Sprintf("already connected to peer: %v", e.peer)
}

// server is the main server of the Lightning Network Daemon. The server houses
// global state pertaining to the wallet, database, and the rpcserver.
// Additionally, the server is also used as a central messaging bus to interact
// with any of its companion objects.
type server struct {
	active   int32 // atomic
	stopping int32 // atomic

	start sync.Once
	stop  sync.Once

	cfg *Config

	// identityECDH is an ECDH capable wrapper for the private key used
	// to authenticate any incoming connections.
	identityECDH keychain.SingleKeyECDH

	// identityKeyLoc is the key locator for the above wrapped identity key.
	identityKeyLoc keychain.KeyLocator

	// nodeSigner is an implementation of the MessageSigner implementation
	// that's backed by the identity private key of the running lnd node.
	nodeSigner *netann.NodeSigner

	mu sync.RWMutex

	cc *chainreg.ChainControl

	// miscDB is the DB that contains all "other" databases within the main
	// channel DB that haven't been separated out yet.
	sigPool *lnwallet.SigPool

	writePool *pool.Write

	readPool *pool.Read

	// livelinessMonitor monitors that lnd has access to critical resources.
	livelinessMonitor *healthcheck.Monitor

	customMessageServer *subscribe.Server

	quit chan struct{}

	wg sync.WaitGroup
}

// newServer creates a new instance of the server which is to listen using the
// passed listener address.
func newServer(cfg *Config, dbs *DatabaseInstances, cc *chainreg.ChainControl,
	nodeKeyDesc *keychain.KeyDescriptor) *server {

	var (
		nodeKeyECDH = keychain.NewPubKeyECDH(*nodeKeyDesc, cc.KeyRing)

		// We just derived the full descriptor, so we know the public
		// key is set on it.
		nodeKeySigner = keychain.NewPubKeyMessageSigner(
			nodeKeyDesc.PubKey, nodeKeyDesc.KeyLocator, cc.KeyRing,
		)
	)

	var serializedPubKey [33]byte
	copy(serializedPubKey[:], nodeKeyDesc.PubKey.SerializeCompressed())

	writeBufferPool := pool.NewWriteBuffer(
		pool.DefaultWriteBufferGCInterval,
		pool.DefaultWriteBufferExpiryInterval,
	)

	writePool := pool.NewWrite(
		writeBufferPool, cfg.Workers.Write, pool.DefaultWorkerTimeout,
	)

	readBufferPool := pool.NewReadBuffer(
		pool.DefaultReadBufferGCInterval,
		pool.DefaultReadBufferExpiryInterval,
	)

	readPool := pool.NewRead(
		readBufferPool, cfg.Workers.Read, pool.DefaultWorkerTimeout,
	)

	s := &server{
		cfg:       cfg,
		cc:        cc,
		sigPool:   lnwallet.NewSigPool(cfg.Workers.Sig, cc.Signer),
		writePool: writePool,
		readPool:  readPool,

		identityECDH:   nodeKeyECDH,
		identityKeyLoc: nodeKeyDesc.KeyLocator,
		nodeSigner:     netann.NewNodeSigner(nodeKeySigner),

		quit: make(chan struct{}),
	}

	// Create liveliness monitor.
	s.createLivenessMonitor(cfg, cc)

	return s
}

// createLivenessMonitor creates a set of health checks using our configured
// values and uses these checks to create a liveliness monitor. Available
// health checks,
//   - chainHealthCheck (will be disabled for --nochainbackend mode)
//   - diskCheck
//   - tlsHealthCheck
//   - torController, only created when tor is enabled.
//
// If a health check has been disabled by setting attempts to 0, our monitor
// will not run it.
func (s *server) createLivenessMonitor(cfg *Config, cc *chainreg.ChainControl) {
	diskCheck := healthcheck.NewObservation(
		"disk space",
		func() error {
			free, err := healthcheck.AvailableDiskSpaceRatio(
				cfg.LndDir,
			)
			if err != nil {
				return err
			}

			// If we have more free space than we require,
			// we return a nil error.
			if free > cfg.HealthChecks.DiskCheck.RequiredRemaining {
				return nil
			}

			return fmt.Errorf("require: %v free space, got: %v",
				cfg.HealthChecks.DiskCheck.RequiredRemaining,
				free)
		},
		cfg.HealthChecks.DiskCheck.Interval,
		cfg.HealthChecks.DiskCheck.Timeout,
		cfg.HealthChecks.DiskCheck.Backoff,
		cfg.HealthChecks.DiskCheck.Attempts,
	)

	tlsHealthCheck := healthcheck.NewObservation(
		"tls",
		func() error {
			_, parsedCert, err := cert.LoadCert(
				cfg.TLSCertPath, cfg.TLSKeyPath,
			)
			if err != nil {
				return err
			}

			// If the current time is passed the certificate's
			// expiry time, then it is considered expired
			if time.Now().After(parsedCert.NotAfter) {
				return fmt.Errorf("TLS certificate is "+
					"expired as of %v", parsedCert.NotAfter)
			}

			// If the certificate is not outdated, no error needs
			// to be returned
			return nil
		},
		cfg.HealthChecks.TLSCheck.Interval,
		cfg.HealthChecks.TLSCheck.Timeout,
		cfg.HealthChecks.TLSCheck.Backoff,
		cfg.HealthChecks.TLSCheck.Attempts,
	)

	checks := []*healthcheck.Observation{
		diskCheck, tlsHealthCheck,
	}

	// If we have not disabled all of our health checks, we create a
	// liveliness monitor with our configured checks.
	s.livelinessMonitor = healthcheck.NewMonitor(
		&healthcheck.Config{
			Checks:   checks,
			Shutdown: srvrLog.Criticalf,
		},
	)
}

// Started returns true if the server has been started, and false otherwise.
// NOTE: This function is safe for concurrent access.
func (s *server) Started() bool {
	return atomic.LoadInt32(&s.active) != 0
}

// cleaner is used to aggregate "cleanup" functions during an operation that
// starts several subsystems. In case one of the subsystem fails to start
// and a proper resource cleanup is required, the "run" method achieves this
// by running all these added "cleanup" functions.
type cleaner []func() error

// add is used to add a cleanup function to be called when
// the run function is executed.
func (c cleaner) add(cleanup func() error) cleaner {
	return append(c, cleanup)
}

// run is used to run all the previousely added cleanup functions.
func (c cleaner) run() {
	for i := len(c) - 1; i >= 0; i-- {
		if err := c[i](); err != nil {
			srvrLog.Infof("Cleanup failed: %v", err)
		}
	}
}

// Start starts the main daemon server, all requested listeners, and any helper
// goroutines.
// NOTE: This function is safe for concurrent access.
func (s *server) Start() error {
	var startErr error

	// If one sub system fails to start, the following code ensures that the
	// previous started ones are stopped. It also ensures a proper wallet
	// shutdown which is important for releasing its resources (boltdb, etc...)
	cleanup := cleaner{}

	s.start.Do(func() {
		if s.livelinessMonitor != nil {
			if err := s.livelinessMonitor.Start(); err != nil {
				startErr = err
				return
			}
			cleanup = cleanup.add(s.livelinessMonitor.Stop)
		}

		// Start the notification server. This is used so channel
		// management goroutines can be notified when a funding
		// transaction reaches a sufficient number of confirmations, or
		// when the input for the funding transaction is spent in an
		// attempt at an uncooperative close by the counterparty.
		if err := s.sigPool.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.sigPool.Stop)

		if err := s.writePool.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.writePool.Stop)

		if err := s.readPool.Start(); err != nil {
			startErr = err
			return
		}
		cleanup = cleanup.add(s.readPool.Stop)

		// Set the active flag now that we've completed the full
		// startup.
		atomic.StoreInt32(&s.active, 1)
	})

	if startErr != nil {
		cleanup.run()
	}
	return startErr
}

// Stop gracefully shutsdown the main daemon server. This function will signal
// any active goroutines, or helper objects to exit, then blocks until they've
// all successfully exited. Additionally, any/all listeners are closed.
// NOTE: This function is safe for concurrent access.
func (s *server) Stop() error {
	s.stop.Do(func() {
		atomic.StoreInt32(&s.stopping, 1)

		close(s.quit)

		// Shutdown the wallet and the rpc server.
		if s.livelinessMonitor != nil {
			if err := s.livelinessMonitor.Stop(); err != nil {
				srvrLog.Warnf("unable to shutdown liveliness "+
					"monitor: %v", err)
			}
		}

		// Wait for all lingering goroutines to quit.
		s.wg.Wait()

		s.sigPool.Stop()
		s.writePool.Stop()
		s.readPool.Stop()
	})

	return nil
}

// Stopped returns true if the server has been instructed to shutdown.
// NOTE: This function is safe for concurrent access.
func (s *server) Stopped() bool {
	return atomic.LoadInt32(&s.stopping) != 0
}
