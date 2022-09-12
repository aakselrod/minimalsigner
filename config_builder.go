package minimalsigner

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcwallet/wallet"
	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/lightningnetwork/lnd/rpcperms"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/walletunlocker"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	// From github.com/lightningnetwork/lnd/lncfg/db.go
	macaroonDBName = "macaroons.db"
)

// GrpcRegistrar is an interface that must be satisfied by an external subserver
// that wants to be able to register its own gRPC server onto lnd's main
// grpc.Server instance.
type GrpcRegistrar interface {
	// RegisterGrpcSubserver is called for each net.Listener on which lnd
	// creates a grpc.Server instance. External subservers implementing this
	// method can then register their own gRPC server structs to the main
	// server instance.
	RegisterGrpcSubserver(*grpc.Server) error
}

// ExternalValidator is an interface that must be satisfied by an external
// macaroon validator.
type ExternalValidator interface {
	macaroons.MacaroonValidator

	// Permissions returns the permissions that the external validator is
	// validating. It is a map between the full HTTP URI of each RPC and its
	// required macaroon permissions. If multiple action/entity tuples are
	// specified per URI, they are all required. See rpcserver.go for a list
	// of valid action and entity values.
	Permissions() map[string][]bakery.Op
}

// DatabaseBuilder is an interface that must be satisfied by the implementation
// that provides lnd's main database backend instances.
type DatabaseBuilder interface {
	// BuildDatabase extracts the current databases that we'll use for
	// normal operation in the daemon. A function closure that closes all
	// opened databases is also returned.
	BuildDatabase(ctx context.Context) (*DatabaseInstances, func(), error)
}

// WalletConfigBuilder is an interface that must be satisfied by a custom wallet
// implementation.
type WalletConfigBuilder interface {
	// BuildWalletConfig is responsible for creating or unlocking and then
	// fully initializing a wallet.
	BuildWalletConfig(context.Context, *DatabaseInstances,
		*rpcperms.InterceptorChain,
		[]*ListenerWithSignal) (*chainreg.PartialChainControl,
		*btcwallet.Config, func(), error)
}

// ChainControlBuilder is an interface that must be satisfied by a custom wallet
// implementation.
type ChainControlBuilder interface {
	// BuildChainControl is responsible for creating a fully populated chain
	// control instance from a wallet.
	BuildChainControl(*chainreg.PartialChainControl,
		*btcwallet.Config) (*chainreg.ChainControl, func(), error)
}

// ImplementationCfg is a struct that holds all configuration items for
// components that can be implemented outside lnd itself.
type ImplementationCfg struct {
	// GrpcRegistrar is a type that can register additional gRPC subservers
	// before the main gRPC server is started.
	GrpcRegistrar

	// ExternalValidator is a type that can provide external macaroon
	// validation.
	ExternalValidator

	// DatabaseBuilder is a type that can provide lnd's main database
	// backend instances.
	DatabaseBuilder

	// WalletConfigBuilder is a type that can provide a wallet configuration
	// with a fully loaded and unlocked wallet.
	WalletConfigBuilder

	// ChainControlBuilder is a type that can provide a custom wallet
	// implementation.
	ChainControlBuilder
}

// DefaultWalletImpl is the default implementation of our normal, btcwallet
// backed configuration.
type DefaultWalletImpl struct {
	cfg         *Config
	logger      btclog.Logger
	interceptor signal.Interceptor

	watchOnly        bool
	migrateWatchOnly bool
	pwService        *walletunlocker.UnlockerService
}

// NewDefaultWalletImpl creates a new default wallet implementation.
func NewDefaultWalletImpl(cfg *Config, logger btclog.Logger,
	interceptor signal.Interceptor, watchOnly bool) *DefaultWalletImpl {

	return &DefaultWalletImpl{
		cfg:         cfg,
		logger:      logger,
		interceptor: interceptor,
		watchOnly:   watchOnly,
		pwService:   createWalletUnlockerService(cfg),
	}
}

// RegisterRestSubserver is called after lnd creates the main proxy.ServeMux
// instance. External subservers implementing this method can then register
// their own REST proxy stubs to the main server instance.
//
// NOTE: This is part of the GrpcRegistrar interface.
func (d *DefaultWalletImpl) RegisterRestSubserver(ctx context.Context,
	mux *proxy.ServeMux, restProxyDest string,
	restDialOpts []grpc.DialOption) error {

	return lnrpc.RegisterWalletUnlockerHandlerFromEndpoint(
		ctx, mux, restProxyDest, restDialOpts,
	)
}

// RegisterGrpcSubserver is called for each net.Listener on which lnd creates a
// grpc.Server instance. External subservers implementing this method can then
// register their own gRPC server structs to the main server instance.
//
// NOTE: This is part of the GrpcRegistrar interface.
func (d *DefaultWalletImpl) RegisterGrpcSubserver(s *grpc.Server) error {
	lnrpc.RegisterWalletUnlockerServer(s, d.pwService)

	return nil
}

// ValidateMacaroon extracts the macaroon from the context's gRPC metadata,
// checks its signature, makes sure all specified permissions for the called
// method are contained within and finally ensures all caveat conditions are
// met. A non-nil error is returned if any of the checks fail.
//
// NOTE: This is part of the ExternalValidator interface.
func (d *DefaultWalletImpl) ValidateMacaroon(ctx context.Context,
	requiredPermissions []bakery.Op, fullMethod string) error {

	// Because the default implementation does not return any permissions,
	// we shouldn't be registered as an external validator at all and this
	// should never be invoked.
	return fmt.Errorf("default implementation does not support external " +
		"macaroon validation")
}

// Permissions returns the permissions that the external validator is
// validating. It is a map between the full HTTP URI of each RPC and its
// required macaroon permissions. If multiple action/entity tuples are specified
// per URI, they are all required. See rpcserver.go for a list of valid action
// and entity values.
//
// NOTE: This is part of the ExternalValidator interface.
func (d *DefaultWalletImpl) Permissions() map[string][]bakery.Op {
	return nil
}

// BuildWalletConfig is responsible for creating or unlocking and then
// fully initializing a wallet.
//
// NOTE: This is part of the WalletConfigBuilder interface.
func (d *DefaultWalletImpl) BuildWalletConfig(ctx context.Context,
	dbs *DatabaseInstances, interceptorChain *rpcperms.InterceptorChain,
	grpcListeners []*ListenerWithSignal) (*chainreg.PartialChainControl,
	*btcwallet.Config, func(), error) {

	// Keep track of our various cleanup functions. We use a defer function
	// as well to not repeat ourselves with every return statement.
	var (
		cleanUpTasks []func()
		earlyExit    = true
		cleanUp      = func() {
			for _, fn := range cleanUpTasks {
				if fn == nil {
					continue
				}

				fn()
			}
		}
	)
	defer func() {
		if earlyExit {
			cleanUp()
		}
	}()

	var (
		walletInitParams = walletunlocker.WalletUnlockParams{
			// In case we do auto-unlock, we need to be able to send
			// into the channel without blocking so we buffer it.
			MacResponseChan: make(chan []byte, 1),
		}
		privateWalletPw = lnwallet.DefaultPrivatePassphrase
		publicWalletPw  = lnwallet.DefaultPublicPassphrase
	)

	// If the user didn't request a seed, then we'll manually assume a
	// wallet birthday of now, as otherwise the seed would've specified
	// this information.
	walletInitParams.Birthday = time.Now()

	d.pwService.SetLoaderOpts([]btcwallet.LoaderOption{dbs.WalletDB})
	d.pwService.SetMacaroonDB(dbs.MacaroonDB)
	walletExists, err := d.pwService.WalletExists()
	if err != nil {
		return nil, nil, nil, err
	}

	if !walletExists {
		interceptorChain.SetWalletNotCreated()
	} else {
		interceptorChain.SetWalletLocked()
	}

	// If we've started in auto unlock mode, then a wallet should already
	// exist because we don't want to enable the RPC unlocker in that case
	// for security reasons (an attacker could inject their seed since the
	// RPC is unauthenticated). Only if the user explicitly wants to allow
	// wallet creation we don't error out here.
	if d.cfg.WalletUnlockPasswordFile != "" && !walletExists &&
		!d.cfg.WalletUnlockAllowCreate {

		return nil, nil, nil, fmt.Errorf("wallet unlock password file " +
			"was specified but wallet does not exist; initialize " +
			"the wallet before using auto unlocking")
	}

	// What wallet mode are we running in? We've already made sure the no
	// seed backup and auto unlock aren't both set during config parsing.
	switch {
	// A password for unlocking is provided in a file.
	case d.cfg.WalletUnlockPasswordFile != "" && walletExists:
		d.logger.Infof("Attempting automatic wallet unlock with " +
			"password provided in file")
		pwBytes, err := ioutil.ReadFile(d.cfg.WalletUnlockPasswordFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error reading "+
				"password from file %s: %v",
				d.cfg.WalletUnlockPasswordFile, err)
		}

		// Remove any newlines at the end of the file. The lndinit tool
		// won't ever write a newline but maybe the file was provisioned
		// by another process or user.
		pwBytes = bytes.TrimRight(pwBytes, "\r\n")

		// We have the password now, we can ask the unlocker service to
		// do the unlock for us.
		unlockedWallet, unloadWalletFn, err := d.pwService.LoadAndUnlock(
			pwBytes, 0,
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error unlocking "+
				"wallet with password from file: %v", err)
		}

		cleanUpTasks = append(cleanUpTasks, func() {
			if err := unloadWalletFn(); err != nil {
				d.logger.Errorf("Could not unload wallet: %v",
					err)
			}
		})

		privateWalletPw = pwBytes
		publicWalletPw = pwBytes
		walletInitParams.Wallet = unlockedWallet
		walletInitParams.UnloadWallet = unloadWalletFn

	// If none of the automatic startup options are selected, we fall back
	// to the default behavior of waiting for the wallet creation/unlocking
	// over RPC.
	default:
		if err := d.interceptor.Notifier.NotifyReady(false); err != nil {
			return nil, nil, nil, err
		}

		params, err := waitForWalletPassword(
			d.cfg, d.pwService, []btcwallet.LoaderOption{dbs.WalletDB},
			d.interceptor.ShutdownChannel(),
		)
		if err != nil {
			err := fmt.Errorf("unable to set up wallet password "+
				"listeners: %v", err)
			d.logger.Error(err)
			return nil, nil, nil, err
		}

		walletInitParams = *params
		privateWalletPw = walletInitParams.Password
		publicWalletPw = walletInitParams.Password
		cleanUpTasks = append(cleanUpTasks, func() {
			if err := walletInitParams.UnloadWallet(); err != nil {
				d.logger.Errorf("Could not unload wallet: %v",
					err)
			}
		})

		if walletInitParams.RecoveryWindow > 0 {
			d.logger.Infof("Wallet recovery mode enabled with "+
				"address lookahead of %d addresses",
				walletInitParams.RecoveryWindow)
		}
	}

	err = walletInitParams.Wallet.Unlock(privateWalletPw, nil)
	if err != nil {
		d.logger.Error(err)
		return nil, nil, nil, err
	}

	var macaroonService *macaroons.Service
	if !d.cfg.NoMacaroons {
		// Create the macaroon authentication/authorization service.
		rootKeyStore, err := macaroons.NewRootKeyStorage(dbs.MacaroonDB)
		if err != nil {
			return nil, nil, nil, err
		}
		macaroonService, err = macaroons.NewService(
			rootKeyStore, "lnd", walletInitParams.StatelessInit,
			macaroons.IPLockChecker,
			macaroons.CustomChecker(interceptorChain),
		)
		if err != nil {
			err := fmt.Errorf("unable to set up macaroon "+
				"authentication: %v", err)
			d.logger.Error(err)
			return nil, nil, nil, err
		}
		cleanUpTasks = append(cleanUpTasks, func() {
			if err := macaroonService.Close(); err != nil {
				d.logger.Errorf("Could not close macaroon "+
					"service: %v", err)
			}
		})

		// Try to unlock the macaroon store with the private password.
		// Ignore ErrAlreadyUnlocked since it could be unlocked by the
		// wallet unlocker.
		err = macaroonService.CreateUnlock(&privateWalletPw)
		if err != nil && err != macaroons.ErrAlreadyUnlocked {
			err := fmt.Errorf("unable to unlock macaroons: %v", err)
			d.logger.Error(err)
			return nil, nil, nil, err
		}

		// If we have a macaroon root key from the init wallet params,
		// set the root key before baking any macaroons.
		if len(walletInitParams.MacRootKey) > 0 {
			err := macaroonService.SetRootKey(
				walletInitParams.MacRootKey,
			)
			if err != nil {
				return nil, nil, nil, err
			}
		}

		// Send an admin macaroon to all our listeners that requested
		// one by setting a non-nil macaroon channel.
		adminMacBytes, err := bakeMacaroon(
			ctx, macaroonService, adminPermissions(),
		)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, lis := range grpcListeners {
			if lis.MacChan != nil {
				lis.MacChan <- adminMacBytes
			}
		}

		// The channel is buffered by one element so writing
		// should not block here.
		walletInitParams.MacResponseChan <- adminMacBytes

		// If the user requested a stateless initialization, no macaroon
		// files should be created.
		if !walletInitParams.StatelessInit &&
			!fileExists(d.cfg.AdminMacPath) &&
			!fileExists(d.cfg.ReadMacPath) {

			// Create macaroon files for lncli to use if they don't
			// exist.
			err = genMacaroons(
				ctx, macaroonService, d.cfg.AdminMacPath,
				d.cfg.ReadMacPath,
			)
			if err != nil {
				err := fmt.Errorf("unable to create macaroons "+
					"%v", err)
				d.logger.Error(err)
				return nil, nil, nil, err
			}
		}

		// As a security service to the user, if they requested
		// stateless initialization and there are macaroon files on disk
		// we log a warning.
		if walletInitParams.StatelessInit {
			msg := "Found %s macaroon on disk (%s) even though " +
				"--stateless_init was requested. Unencrypted " +
				"state is accessible by the host system. You " +
				"should change the password and use " +
				"--new_mac_root_key with --stateless_init to " +
				"clean up and invalidate old macaroons."

			if fileExists(d.cfg.AdminMacPath) {
				d.logger.Warnf(msg, "admin", d.cfg.AdminMacPath)
			}
			if fileExists(d.cfg.ReadMacPath) {
				d.logger.Warnf(msg, "readonly", d.cfg.ReadMacPath)
			}
		}

		// We add the macaroon service to our RPC interceptor. This
		// will start checking macaroons against permissions on every
		// RPC invocation.
		interceptorChain.AddMacaroonService(macaroonService)
	}

	// Now that the wallet password has been provided, transition the RPC
	// state into Unlocked.
	interceptorChain.SetWalletUnlocked()

	// Since calls to the WalletUnlocker service wait for a response on the
	// macaroon channel, we close it here to make sure they return in case
	// we did not return the admin macaroon above. This will be the case if
	// --no-macaroons is used.
	close(walletInitParams.MacResponseChan)

	// We'll also close all the macaroon channels since lnd is done sending
	// macaroon data over it.
	for _, lis := range grpcListeners {
		if lis.MacChan != nil {
			close(lis.MacChan)
		}
	}

	// With the information parsed from the configuration, create valid
	// instances of the pertinent interfaces required to operate the
	// Lightning Network Daemon.
	//
	// When we create the chain control, we need storage for the height
	// hints and also the wallet itself, for these two we want them to be
	// replicated, so we'll pass in the remote channel DB instance.
	chainControlCfg := &chainreg.Config{
		Bitcoin:            d.cfg.Bitcoin,
		PrimaryChain:       d.cfg.registeredChains.PrimaryChain,
		ActiveNetParams:    d.cfg.ActiveNetParams,
		WalletUnlockParams: &walletInitParams,
	}

	// Let's go ahead and create the partial chain control now that is only
	// dependent on our configuration and doesn't require any wallet
	// specific information.
	backend := &chainreg.NoChainBackend{}
	source := &chainreg.NoChainSource{
		BestBlockTime: time.Now(),
	}

	partialChainControl := &chainreg.PartialChainControl{
		Cfg:           chainControlCfg,
		ChainSource:   source,
		ChainNotifier: backend,
		ChainView:     backend,
		FeeEstimator:  backend,
		HealthCheck: func() error {
			return nil
		},
	}

	walletConfig := &btcwallet.Config{
		PrivatePass:    privateWalletPw,
		PublicPass:     publicWalletPw,
		Birthday:       walletInitParams.Birthday,
		RecoveryWindow: walletInitParams.RecoveryWindow,
		NetParams:      d.cfg.ActiveNetParams.Params,
		CoinType:       d.cfg.ActiveNetParams.CoinType,
		Wallet:         walletInitParams.Wallet,
		LoaderOptions:  []btcwallet.LoaderOption{dbs.WalletDB},
		ChainSource:    partialChainControl.ChainSource,
	}

	earlyExit = false
	return partialChainControl, walletConfig, cleanUp, nil
}

// BuildChainControl is responsible for creating a fully populated chain
// control instance from a wallet.
//
// NOTE: This is part of the ChainControlBuilder interface.
func (d *DefaultWalletImpl) BuildChainControl(
	partialChainControl *chainreg.PartialChainControl,
	walletConfig *btcwallet.Config) (*chainreg.ChainControl, func(), error) {

	walletController, err := btcwallet.New(
		*walletConfig, nil,
	)
	if err != nil {
		err := fmt.Errorf("unable to create wallet controller: %v", err)
		d.logger.Error(err)
		return nil, nil, err
	}

	keyRing := keychain.NewBtcWalletKeyRing(
		walletController.InternalWallet(),
		walletConfig.CoinType,
	)

	lnWallet, err := lnwallet.NewLightningWallet(lnwallet.Config{
		SecretKeyRing:    keyRing,
		WalletController: walletController,
	})
	if err != nil {
		d.logger.Error(err)
		return nil, nil, err
	}

	if err := lnWallet.Startup(); err != nil {
		d.logger.Error(err)
		return nil, nil, err
	}

	// We've created the wallet configuration now, so we can finish
	// initializing the main chain control.
	activeChainControl := &chainreg.ChainControl{
		PartialChainControl: partialChainControl,
		MsgSigner:           walletController,
		Signer:              walletController,
		ChainIO:             walletController,
		KeyRing:             keyRing,
		Wallet:              lnWallet,
	}

	return activeChainControl, func() {}, nil
}

// DatabaseInstances is a struct that holds all instances to the actual
// databases that are used in lnd.
type DatabaseInstances struct {
	// MacaroonDB is the database that stores macaroon root keys.
	MacaroonDB kvdb.Backend

	// WalletDB is the configuration for loading the wallet database using
	// the btcwallet's loader.
	WalletDB btcwallet.LoaderOption
}

// DefaultDatabaseBuilder is a type that builds the default database backends
// for lnd, using the given configuration to decide what actual implementation
// to use.
type DefaultDatabaseBuilder struct {
	cfg    *Config
	logger btclog.Logger
}

// NewDefaultDatabaseBuilder returns a new instance of the default database
// builder.
func NewDefaultDatabaseBuilder(cfg *Config,
	logger btclog.Logger) *DefaultDatabaseBuilder {

	return &DefaultDatabaseBuilder{
		cfg:    cfg,
		logger: logger,
	}
}

// BuildDatabase extracts the current databases that we'll use for normal
// operation in the daemon. A function closure that closes all opened databases
// is also returned.
func (d *DefaultDatabaseBuilder) BuildDatabase(
	ctx context.Context) (*DatabaseInstances, func(), error) {

	d.logger.Infof("Opening the main database, this might take a few " +
		"minutes...")

	cfg := d.cfg
	if cfg.DB.Backend == lncfg.BoltBackend {
		d.logger.Infof("Opening bbolt database, sync_freelist=%v, "+
			"auto_compact=%v", !cfg.DB.Bolt.NoFreelistSync,
			cfg.DB.Bolt.AutoCompact)
	}

	startOpenTime := time.Now()

	// TODO(aakselrod): fix this
	databaseBackends, err := GetBackends(ctx, cfg.DB, cfg.networkDir)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to obtain database "+
			"backends: %v", err)
	}

	// With the full remote mode we made sure both the graph and channel
	// state DB point to the same local or remote DB and the same namespace
	// within that DB.
	dbs := &DatabaseInstances{
		MacaroonDB: databaseBackends.MacaroonDB,
		WalletDB:   databaseBackends.WalletDB,
	}
	cleanUp := func() {
		// We can just close the returned close functions directly. Even
		// if we decorate the channel DB with an additional struct, its
		// close function still just points to the kvdb backend.
		for name, closeFunc := range databaseBackends.CloseFuncs {
			if err := closeFunc(); err != nil {
				d.logger.Errorf("Error closing %s "+
					"database: %v", name, err)
			}
		}
	}

	openTime := time.Since(startOpenTime)
	d.logger.Infof("Database(s) now open (time_to_open=%v)!", openTime)

	return dbs, cleanUp, nil
}

// waitForWalletPassword blocks until a password is provided by the user to
// this RPC server.
func waitForWalletPassword(cfg *Config,
	pwService *walletunlocker.UnlockerService,
	loaderOpts []btcwallet.LoaderOption, shutdownChan <-chan struct{}) (
	*walletunlocker.WalletUnlockParams, error) {

	// Wait for user to provide the password.
	ltndLog.Infof("Waiting for wallet encryption password. Use `lncli " +
		"create` to create a wallet, `lncli unlock` to unlock an " +
		"existing wallet, or `lncli changepassword` to change the " +
		"password of an existing wallet and unlock it.")

	// We currently don't distinguish between getting a password to be used
	// for creation or unlocking, as a new wallet db will be created if
	// none exists when creating the chain control.
	select {
	// The wallet is being created for the first time, we'll check to see
	// if the user provided any entropy for seed creation. If so, then
	// we'll create the wallet early to load the seed.
	case initMsg := <-pwService.InitMsgs:
		password := initMsg.Passphrase
		cipherSeed := initMsg.WalletSeed
		extendedKey := initMsg.WalletExtendedKey
		recoveryWindow := initMsg.RecoveryWindow

		// Before we proceed, we'll check the internal version of the
		// seed. If it's greater than the current key derivation
		// version, then we'll return an error as we don't understand
		// this.
		if cipherSeed != nil &&
			!keychain.IsKnownVersion(cipherSeed.InternalVersion) {

			return nil, fmt.Errorf("invalid internal "+
				"seed version %v, current max version is %v",
				cipherSeed.InternalVersion,
				keychain.CurrentKeyDerivationVersion)
		}

		loader, err := btcwallet.NewWalletLoader(
			cfg.ActiveNetParams.Params, recoveryWindow,
			loaderOpts...,
		)
		if err != nil {
			return nil, err
		}

		// With the seed, we can now use the wallet loader to create
		// the wallet, then pass it back to avoid unlocking it again.
		var (
			birthday  time.Time
			newWallet *wallet.Wallet
		)
		switch {
		// A normal cipher seed was given, use the birthday encoded in
		// it and create the wallet from that.
		case cipherSeed != nil:
			birthday = cipherSeed.BirthdayTime()
			newWallet, err = loader.CreateNewWallet(
				password, password, cipherSeed.Entropy[:],
				birthday,
			)

		// No seed was given, we're importing a wallet from its extended
		// private key.
		case extendedKey != nil:
			birthday = initMsg.ExtendedKeyBirthday
			newWallet, err = loader.CreateNewWalletExtendedKey(
				password, password, extendedKey, birthday,
			)

		default:
			// The unlocker service made sure either the cipher seed
			// or the extended key is set so, we shouldn't get here.
			// The default case is just here for readability and
			// completeness.
			err = fmt.Errorf("cannot create wallet, neither seed " +
				"nor extended key was given")
		}
		if err != nil {
			// Don't leave the file open in case the new wallet
			// could not be created for whatever reason.
			if err := loader.UnloadWallet(); err != nil {
				ltndLog.Errorf("Could not unload new "+
					"wallet: %v", err)
			}
			return nil, err
		}

		return &walletunlocker.WalletUnlockParams{
			Password:        password,
			Birthday:        birthday,
			RecoveryWindow:  recoveryWindow,
			Wallet:          newWallet,
			UnloadWallet:    loader.UnloadWallet,
			StatelessInit:   initMsg.StatelessInit,
			MacResponseChan: pwService.MacResponseChan,
			MacRootKey:      initMsg.MacRootKey,
		}, nil

	// The wallet has already been created in the past, and is simply being
	// unlocked. So we'll just return these passphrases.
	case unlockMsg := <-pwService.UnlockMsgs:
		return &walletunlocker.WalletUnlockParams{
			Password:        unlockMsg.Passphrase,
			RecoveryWindow:  unlockMsg.RecoveryWindow,
			Wallet:          unlockMsg.Wallet,
			UnloadWallet:    unlockMsg.UnloadWallet,
			StatelessInit:   unlockMsg.StatelessInit,
			MacResponseChan: pwService.MacResponseChan,
		}, nil

	// If we got a shutdown signal we just return with an error immediately
	case <-shutdownChan:
		return nil, fmt.Errorf("shutting down")
	}
}

// GetBackends returns a set of kvdb.Backends as set in the DB config.
// Migrated here from github.com/lightningnetwork/lnd/lncfg/db.go to remove
// requirement for creating any DBs except wallet and macaroons.
func GetBackends(ctx context.Context, db *lncfg.DB, walletDBPath string) (
	*lncfg.DatabaseBackends, error) {

	// We keep track of all the kvdb backends we actually open and return a
	// reference to their close function so they can be cleaned up properly
	// on error or shutdown.
	closeFuncs := make(map[string]func() error)

	// If we need to return early because of an error, we invoke any close
	// function that has been initialized so far.
	returnEarly := true
	defer func() {
		if !returnEarly {
			return
		}

		for _, closeFunc := range closeFuncs {
			_ = closeFunc()
		}
	}()

	switch db.Backend {
	case lncfg.EtcdBackend:
		// As long as the graph data, channel state and height hint
		// cache are all still in the channel.db file in bolt, we
		// replicate the same behavior here and use the same etcd
		// backend for those three sub DBs. But we namespace it properly
		// to make such a split even easier in the future. This will
		// break lnd for users that ran on etcd with 0.13.x since that
		// code used the root namespace. We assume that nobody used etcd
		// for mainnet just yet since that feature was clearly marked as
		// experimental in 0.13.x.
		etcdMacaroonBackend, err := kvdb.Open(
			kvdb.EtcdBackendName, ctx,
			db.Etcd.CloneWithSubNamespace(lncfg.NSMacaroonDB),
		)
		if err != nil {
			return nil, fmt.Errorf("error opening etcd macaroon "+
				"DB: %v", err)
		}
		closeFuncs[lncfg.NSMacaroonDB] = etcdMacaroonBackend.Close

		etcdWalletBackend, err := kvdb.Open(
			kvdb.EtcdBackendName, ctx,
			db.Etcd.
				CloneWithSubNamespace(lncfg.NSWalletDB).
				CloneWithSingleWriter(),
		)
		if err != nil {
			return nil, fmt.Errorf("error opening etcd macaroon "+
				"DB: %v", err)
		}
		closeFuncs[lncfg.NSWalletDB] = etcdWalletBackend.Close

		returnEarly = false
		return &lncfg.DatabaseBackends{
			MacaroonDB: etcdMacaroonBackend,
			// The wallet loader will attempt to use/create the
			// wallet in the replicated remote DB if we're running
			// in a clustered environment. This will ensure that all
			// members of the cluster have access to the same wallet
			// state.
			WalletDB: btcwallet.LoaderWithExternalWalletDB(
				etcdWalletBackend,
			),
			Remote:     true,
			CloseFuncs: closeFuncs,
		}, nil

	case lncfg.PostgresBackend:
		postgresMacaroonBackend, err := kvdb.Open(
			kvdb.PostgresBackendName, ctx,
			db.Postgres, lncfg.NSMacaroonDB,
		)
		if err != nil {
			return nil, fmt.Errorf("error opening postgres "+
				"macaroon DB: %v", err)
		}
		closeFuncs[lncfg.NSMacaroonDB] = postgresMacaroonBackend.Close

		postgresWalletBackend, err := kvdb.Open(
			kvdb.PostgresBackendName, ctx,
			db.Postgres, lncfg.NSWalletDB,
		)
		if err != nil {
			return nil, fmt.Errorf("error opening postgres macaroon "+
				"DB: %v", err)
		}
		closeFuncs[lncfg.NSWalletDB] = postgresWalletBackend.Close

		returnEarly = false
		return &lncfg.DatabaseBackends{
			MacaroonDB: postgresMacaroonBackend,
			// The wallet loader will attempt to use/create the
			// wallet in the replicated remote DB if we're running
			// in a clustered environment. This will ensure that all
			// members of the cluster have access to the same wallet
			// state.
			WalletDB: btcwallet.LoaderWithExternalWalletDB(
				postgresWalletBackend,
			),
			Remote:     true,
			CloseFuncs: closeFuncs,
		}, nil
	}

	// We're using all bbolt based databases by default.
	macaroonBackend, err := kvdb.GetBoltBackend(&kvdb.BoltBackendConfig{
		DBPath:            walletDBPath,
		DBFileName:        macaroonDBName,
		DBTimeout:         db.Bolt.DBTimeout,
		NoFreelistSync:    db.Bolt.NoFreelistSync,
		AutoCompact:       db.Bolt.AutoCompact,
		AutoCompactMinAge: db.Bolt.AutoCompactMinAge,
	})
	if err != nil {
		return nil, fmt.Errorf("error opening macaroon DB: %v", err)
	}
	closeFuncs[lncfg.NSMacaroonDB] = macaroonBackend.Close

	returnEarly = false
	return &lncfg.DatabaseBackends{
		MacaroonDB: macaroonBackend,
		// When "running locally", LND will use the bbolt wallet.db to
		// store the wallet located in the chain data dir, parametrized
		// by the active network. The wallet loader has its own cleanup
		// method so we don't need to add anything to our map (in fact
		// nothing is opened just yet).
		WalletDB: btcwallet.LoaderWithLocalWalletDB(
			walletDBPath, db.Bolt.NoFreelistSync, db.Bolt.DBTimeout,
		),
		CloseFuncs: closeFuncs,
	}, nil
}
