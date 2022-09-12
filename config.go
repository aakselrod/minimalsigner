// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 The Lightning Network Developers

package minimalsigner

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	flags "github.com/jessevdk/go-flags"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/signal"
)

const (
	defaultDataDirname      = "data"
	defaultChainSubDirname  = "chain"
	defaultTLSCertFilename  = "tls.cert"
	defaultTLSKeyFilename   = "tls.key"
	defaultAdminMacFilename = "admin.macaroon"
	defaultReadMacFilename  = "readonly.macaroon"
	defaultLogLevel         = "info"
	defaultLogDirname       = "logs"
	defaultLogFilename      = "lnd.log"
	defaultRPCPort          = 10009
	defaultRESTPort         = 8080
	defaultRPCHost          = "localhost"

	defaultMaxLogFiles        = 3
	defaultMaxLogFileSize     = 10
	defaultLetsEncryptDirname = "letsencrypt"
	defaultLetsEncryptListen  = ":80"

	// DefaultAutogenValidity is the default validity of a self-signed
	// certificate. The value corresponds to 14 months
	// (14 months * 30 days * 24 hours).
	defaultTLSCertDuration = 14 * 30 * 24 * time.Hour

	// Set defaults for a health check which ensures that we have space
	// available on disk. Although this check is off by default so that we
	// avoid breaking any existing setups (particularly on mobile), we still
	// set the other default values so that the health check can be easily
	// enabled with sane defaults.
	defaultRequiredDisk = 0.1
	defaultDiskInterval = time.Hour * 12
	defaultDiskTimeout  = time.Second * 5
	defaultDiskBackoff  = time.Minute
	defaultDiskAttempts = 0

	// Set defaults for a health check which ensures that the TLS certificate
	// is not expired. Although this check is off by default (not all setups
	// require it), we still set the other default values so that the health
	// check can be easily enabled with sane defaults.
	defaultTLSInterval = time.Minute
	defaultTLSTimeout  = time.Second * 5
	defaultTLSBackoff  = time.Minute
	defaultTLSAttempts = 0
)

var (
	// DefaultLndDir is the default directory where lnd tries to find its
	// configuration file and store its data. This is a directory in the
	// user's application data, for example:
	//   C:\Users\<username>\AppData\Local\Lnd on Windows
	//   ~/.lnd on Linux
	//   ~/Library/Application Support/Lnd on MacOS
	DefaultLndDir = btcutil.AppDataDir("lnd", false)

	// DefaultConfigFile is the default full path of lnd's configuration
	// file.
	DefaultConfigFile = filepath.Join(DefaultLndDir, lncfg.DefaultConfigFilename)

	defaultDataDir = filepath.Join(DefaultLndDir, defaultDataDirname)
	defaultLogDir  = filepath.Join(DefaultLndDir, defaultLogDirname)

	defaultTLSCertPath    = filepath.Join(DefaultLndDir, defaultTLSCertFilename)
	defaultTLSKeyPath     = filepath.Join(DefaultLndDir, defaultTLSKeyFilename)
	defaultLetsEncryptDir = filepath.Join(DefaultLndDir, defaultLetsEncryptDirname)
)

// Config defines the configuration options for lnd.
//
// See LoadConfig for further details regarding the configuration
// loading+parsing process.
type Config struct {
	ShowVersion bool `short:"V" long:"version" description:"Display version information and exit"`

	LndDir       string `long:"lnddir" description:"The base directory that contains lnd's data, logs, configuration file, etc."`
	ConfigFile   string `short:"C" long:"configfile" description:"Path to configuration file"`
	DataDir      string `short:"b" long:"datadir" description:"The directory to store lnd's data within"`
	SyncFreelist bool   `long:"sync-freelist" description:"Whether the databases used within lnd should sync their freelist to disk. This is disabled by default resulting in improved memory performance during operation, but with an increase in startup time."`

	TLSCertPath        string        `long:"tlscertpath" description:"Path to write the TLS certificate for lnd's RPC and REST services"`
	TLSKeyPath         string        `long:"tlskeypath" description:"Path to write the TLS private key for lnd's RPC and REST services"`
	TLSExtraIPs        []string      `long:"tlsextraip" description:"Adds an extra ip to the generated certificate"`
	TLSExtraDomains    []string      `long:"tlsextradomain" description:"Adds an extra domain to the generated certificate"`
	TLSAutoRefresh     bool          `long:"tlsautorefresh" description:"Re-generate TLS certificate and key if the IPs or domains are changed"`
	TLSDisableAutofill bool          `long:"tlsdisableautofill" description:"Do not include the interface IPs or the system hostname in TLS certificate, use first --tlsextradomain as Common Name instead, if set"`
	TLSCertDuration    time.Duration `long:"tlscertduration" description:"The duration for which the auto-generated TLS certificate will be valid for"`

	NoMacaroons    bool   `long:"no-macaroons" description:"Disable macaroon authentication, can only be used if server is not listening on a public interface."`
	AdminMacPath   string `long:"adminmacaroonpath" description:"Path to write the admin macaroon for lnd's RPC and REST services if it doesn't exist"`
	ReadMacPath    string `long:"readonlymacaroonpath" description:"Path to write the read-only macaroon for lnd's RPC and REST services if it doesn't exist"`
	LogDir         string `long:"logdir" description:"Directory to log output."`
	MaxLogFiles    int    `long:"maxlogfiles" description:"Maximum logfiles to keep (0 for no rotation)"`
	MaxLogFileSize int    `long:"maxlogfilesize" description:"Maximum logfile size in MB"`

	LetsEncryptDir    string `long:"letsencryptdir" description:"The directory to store Let's Encrypt certificates within"`
	LetsEncryptListen string `long:"letsencryptlisten" description:"The IP:port on which lnd will listen for Let's Encrypt challenges. Let's Encrypt will always try to contact on port 80. Often non-root processes are not allowed to bind to ports lower than 1024. This configuration option allows a different port to be used, but must be used in combination with port forwarding from port 80. This configuration can also be used to specify another IP address to listen on, for example an IPv6 address."`
	LetsEncryptDomain string `long:"letsencryptdomain" description:"Request a Let's Encrypt certificate for this domain. Note that the certificate is only requested and stored when the first rpc connection comes in."`

	// We'll parse these 'raw' string arguments into real net.Addrs in the
	// loadConfig function. We need to expose the 'raw' strings so the
	// command line library can access them.
	// Only the parsed net.Addrs should be used!
	RawRPCListeners  []string `long:"rpclisten" description:"Add an interface/port/socket to listen for RPC connections"`
	RawRESTListeners []string `long:"restlisten" description:"Add an interface/port/socket to listen for REST connections"`
	ExternalHosts    []string `long:"externalhosts" description:"Add a hostname:port that should be periodically resolved to announce IPs for. If a port is not specified, the default (9735) will be used."`
	RPCListeners     []net.Addr
	RESTListeners    []net.Addr
	RestCORS         []string      `long:"restcors" description:"Add an ip:port/hostname to allow cross origin access from. To allow all origins, set as \"*\"."`
	DisableRest      bool          `long:"norest" description:"Disable REST API"`
	DisableRestTLS   bool          `long:"no-rest-tls" description:"Disable TLS for REST connections"`
	WSPingInterval   time.Duration `long:"ws-ping-interval" description:"The ping interval for REST based WebSocket connections, set to 0 to disable sending ping messages from the server side"`
	WSPongWait       time.Duration `long:"ws-pong-wait" description:"The time we wait for a pong response message on REST based WebSocket connections before the connection is closed as inactive"`

	DebugLevel string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <global-level>,<subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`

	CPUProfile string `long:"cpuprofile" description:"Write CPU profile to the specified file"`

	Profile string `long:"profile" description:"Enable HTTP profiling on either a port or host:port"`

	Bitcoin *lncfg.Chain `group:"Bitcoin" namespace:"bitcoin"`

	SubRPCServers *subRPCServerConfigs `group:"subrpc"`

	WalletUnlockPasswordFile string `long:"wallet-unlock-password-file" description:"The full path to a file (or pipe/device) that contains the password for unlocking the wallet; if set, no unlocking through RPC is possible and lnd will exit if no wallet exists or the password is incorrect; if wallet-unlock-allow-create is also set then lnd will ignore this flag if no wallet exists and allow a wallet to be created through RPC."`
	WalletUnlockAllowCreate  bool   `long:"wallet-unlock-allow-create" description:"Don't fail with an error if wallet-unlock-password-file is set but no wallet exists yet."`

	DryRunMigration bool `long:"dry-run-migration" description:"If true, lnd will abort committing a migration if it would otherwise have been successful. This leaves the database unmodified, and still compatible with the previously active version of lnd."`

	Workers *lncfg.Workers `group:"workers" namespace:"workers"`

	Prometheus lncfg.Prometheus `group:"prometheus" namespace:"prometheus"`

	HealthChecks *lncfg.HealthCheckConfig `group:"healthcheck" namespace:"healthcheck"`

	DB *lncfg.DB `group:"db" namespace:"db"`

	Cluster *lncfg.Cluster `group:"cluster" namespace:"cluster"`

	RPCMiddleware *lncfg.RPCMiddleware `group:"rpcmiddleware" namespace:"rpcmiddleware"`

	// LogWriter is the root logger that all of the daemon's subloggers are
	// hooked up to.
	LogWriter *build.RotatingLogWriter

	// registeredChains keeps track of all chains that have been registered
	// with the daemon.
	registeredChains *chainreg.ChainRegistry

	// networkDir is the path to the directory of the currently active
	// network. This path will hold the files related to each different
	// network.
	networkDir string

	// ActiveNetParams contains parameters of the target chain.
	ActiveNetParams chainreg.BitcoinNetParams
}

// DefaultConfig returns all default values for the Config struct.
func DefaultConfig() Config {
	return Config{
		LndDir:            DefaultLndDir,
		ConfigFile:        DefaultConfigFile,
		DataDir:           defaultDataDir,
		DebugLevel:        defaultLogLevel,
		TLSCertPath:       defaultTLSCertPath,
		TLSKeyPath:        defaultTLSKeyPath,
		TLSCertDuration:   defaultTLSCertDuration,
		LetsEncryptDir:    defaultLetsEncryptDir,
		LetsEncryptListen: defaultLetsEncryptListen,
		LogDir:            defaultLogDir,
		MaxLogFiles:       defaultMaxLogFiles,
		MaxLogFileSize:    defaultMaxLogFileSize,
		WSPingInterval:    lnrpc.DefaultPingInterval,
		WSPongWait:        lnrpc.DefaultPongWait,
		Bitcoin:           &lncfg.Chain{},
		SubRPCServers: &subRPCServerConfigs{
			SignRPC: &signrpc.Config{},
		},
		Workers: &lncfg.Workers{
			Read:  lncfg.DefaultReadWorkers,
			Write: lncfg.DefaultWriteWorkers,
			Sig:   lncfg.DefaultSigWorkers,
		},
		Prometheus: lncfg.DefaultPrometheus(),
		HealthChecks: &lncfg.HealthCheckConfig{
			DiskCheck: &lncfg.DiskCheckConfig{
				RequiredRemaining: defaultRequiredDisk,
				CheckConfig: &lncfg.CheckConfig{
					Interval: defaultDiskInterval,
					Attempts: defaultDiskAttempts,
					Timeout:  defaultDiskTimeout,
					Backoff:  defaultDiskBackoff,
				},
			},
			TLSCheck: &lncfg.CheckConfig{
				Interval: defaultTLSInterval,
				Timeout:  defaultTLSTimeout,
				Attempts: defaultTLSAttempts,
				Backoff:  defaultTLSBackoff,
			},
		},
		LogWriter:        build.NewRotatingLogWriter(),
		DB:               lncfg.DefaultDB(),
		Cluster:          lncfg.DefaultCluster(),
		RPCMiddleware:    lncfg.DefaultRPCMiddleware(),
		registeredChains: chainreg.NewChainRegistry(),
		ActiveNetParams:  chainreg.BitcoinTestNetParams,
	}
}

// LoadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
//  1. Start with a default config with sane settings
//  2. Pre-parse the command line to check for an alternative config file
//  3. Load configuration file overwriting defaults with any specified options
//  4. Parse CLI options and overwrite/add any specified options
func LoadConfig(interceptor signal.Interceptor) (*Config, error) {
	// Pre-parse the command line options to pick up an alternative config
	// file.
	preCfg := DefaultConfig()
	if _, err := flags.Parse(&preCfg); err != nil {
		return nil, err
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)
	if preCfg.ShowVersion {
		fmt.Println(appName, "version", build.Version(),
			"commit="+build.Commit)
		os.Exit(0)
	}

	// If the config file path has not been modified by the user, then we'll
	// use the default config file path. However, if the user has modified
	// their lnddir, then we should assume they intend to use the config
	// file within it.
	configFileDir := CleanAndExpandPath(preCfg.LndDir)
	configFilePath := CleanAndExpandPath(preCfg.ConfigFile)
	switch {
	// User specified --lnddir but no --configfile. Update the config file
	// path to the lnd config directory, but don't require it to exist.
	case configFileDir != DefaultLndDir &&
		configFilePath == DefaultConfigFile:

		configFilePath = filepath.Join(
			configFileDir, lncfg.DefaultConfigFilename,
		)

	// User did specify an explicit --configfile, so we check that it does
	// exist under that path to avoid surprises.
	case configFilePath != DefaultConfigFile:
		if !fileExists(configFilePath) {
			return nil, fmt.Errorf("specified config file does "+
				"not exist in %s", configFilePath)
		}
	}

	// Next, load any additional configuration options from the file.
	var configFileError error
	cfg := preCfg
	fileParser := flags.NewParser(&cfg, flags.Default)
	err := flags.NewIniParser(fileParser).ParseFile(configFilePath)
	if err != nil {
		// If it's a parsing related error, then we'll return
		// immediately, otherwise we can proceed as possibly the config
		// file doesn't exist which is OK.
		if _, ok := err.(*flags.IniError); ok {
			return nil, err
		}

		configFileError = err
	}

	// Finally, parse the remaining command line options again to ensure
	// they take precedence.
	flagParser := flags.NewParser(&cfg, flags.Default)
	if _, err := flagParser.Parse(); err != nil {
		return nil, err
	}

	// Make sure everything we just loaded makes sense.
	cleanCfg, err := ValidateConfig(
		cfg, interceptor, fileParser, flagParser,
	)
	if usageErr, ok := err.(*usageError); ok {
		// The logging system might not yet be initialized, so we also
		// write to stderr to make sure the error appears somewhere.
		_, _ = fmt.Fprintln(os.Stderr, usageMessage)
		ltndLog.Warnf("Incorrect usage: %v", usageMessage)

		// The log subsystem might not yet be initialized. But we still
		// try to log the error there since some packaging solutions
		// might only look at the log and not stdout/stderr.
		ltndLog.Warnf("Error validating config: %v", usageErr.err)

		return nil, usageErr.err
	}
	if err != nil {
		// The log subsystem might not yet be initialized. But we still
		// try to log the error there since some packaging solutions
		// might only look at the log and not stdout/stderr.
		ltndLog.Warnf("Error validating config: %v", err)

		return nil, err
	}

	// Warn about missing config file only after all other configuration is
	// done. This prevents the warning on help messages and invalid options.
	// Note this should go directly before the return.
	if configFileError != nil {
		ltndLog.Warnf("%v", configFileError)
	}

	return cleanCfg, nil
}

// usageError is an error type that signals a problem with the supplied flags.
type usageError struct {
	err error
}

// Error returns the error string.
//
// NOTE: This is part of the error interface.
func (u *usageError) Error() string {
	return u.err.Error()
}

// ValidateConfig check the given configuration to be sane. This makes sure no
// illegal values or combination of values are set. All file system paths are
// normalized. The cleaned up config is returned on success.
func ValidateConfig(cfg Config, interceptor signal.Interceptor, fileParser,
	flagParser *flags.Parser) (*Config, error) {

	// If the provided lnd directory is not the default, we'll modify the
	// path to all of the files and directories that will live within it.
	lndDir := CleanAndExpandPath(cfg.LndDir)
	if lndDir != DefaultLndDir {
		cfg.DataDir = filepath.Join(lndDir, defaultDataDirname)
		cfg.LetsEncryptDir = filepath.Join(
			lndDir, defaultLetsEncryptDirname,
		)
		cfg.TLSCertPath = filepath.Join(lndDir, defaultTLSCertFilename)
		cfg.TLSKeyPath = filepath.Join(lndDir, defaultTLSKeyFilename)
		cfg.LogDir = filepath.Join(lndDir, defaultLogDirname)
	}

	funcName := "ValidateConfig"
	mkErr := func(format string, args ...interface{}) error {
		return fmt.Errorf(funcName+": "+format, args...)
	}
	makeDirectory := func(dir string) error {
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			// Show a nicer error message if it's because a symlink
			// is linked to a directory that does not exist
			// (probably because it's not mounted).
			if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
				link, lerr := os.Readlink(e.Path)
				if lerr == nil {
					str := "is symlink %s -> %s mounted?"
					err = fmt.Errorf(str, e.Path, link)
				}
			}

			str := "Failed to create lnd directory '%s': %v"
			return mkErr(str, dir, err)
		}

		return nil
	}

	// IsSet returns true if an option has been set in either the config
	// file or by a flag.
	isSet := func(field string) (bool, error) {
		fieldName, ok := reflect.TypeOf(Config{}).FieldByName(field)
		if !ok {
			str := "could not find field %s"
			return false, mkErr(str, field)
		}

		long, ok := fieldName.Tag.Lookup("long")
		if !ok {
			str := "field %s does not have a long tag"
			return false, mkErr(str, field)
		}

		// The user has the option to set the flag in either the config
		// file or as a command line flag. If any is set, we consider it
		// to be set, not applying any precedence rules here (since it
		// is a boolean the default is false anyway which would screw up
		// any precedence rules). Additionally, we need to also support
		// the use case where the config struct is embedded _within_
		// another struct with a prefix (as is the case with
		// lightning-terminal).
		fileOption := fileParser.FindOptionByLongName(long)
		fileOptionNested := fileParser.FindOptionByLongName(
			"lnd." + long,
		)
		flagOption := flagParser.FindOptionByLongName(long)
		flagOptionNested := flagParser.FindOptionByLongName(
			"lnd." + long,
		)

		return (fileOption != nil && fileOption.IsSet()) ||
				(fileOptionNested != nil && fileOptionNested.IsSet()) ||
				(flagOption != nil && flagOption.IsSet()) ||
				(flagOptionNested != nil && flagOptionNested.IsSet()),
			nil
	}

	// As soon as we're done parsing configuration options, ensure all paths
	// to directories and files are cleaned and expanded before attempting
	// to use them later on.
	cfg.DataDir = CleanAndExpandPath(cfg.DataDir)
	cfg.TLSCertPath = CleanAndExpandPath(cfg.TLSCertPath)
	cfg.TLSKeyPath = CleanAndExpandPath(cfg.TLSKeyPath)
	cfg.LetsEncryptDir = CleanAndExpandPath(cfg.LetsEncryptDir)
	cfg.AdminMacPath = CleanAndExpandPath(cfg.AdminMacPath)
	cfg.ReadMacPath = CleanAndExpandPath(cfg.ReadMacPath)
	cfg.LogDir = CleanAndExpandPath(cfg.LogDir)
	cfg.WalletUnlockPasswordFile = CleanAndExpandPath(
		cfg.WalletUnlockPasswordFile,
	)

	// Multiple networks can't be selected simultaneously.  Count
	// number of network flags passed; assign active network params
	// while we're at it.
	numNets := 0
	if cfg.Bitcoin.MainNet {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinMainNetParams
	}
	if cfg.Bitcoin.TestNet3 {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinTestNetParams
	}
	if cfg.Bitcoin.RegTest {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinRegTestNetParams
	}
	if cfg.Bitcoin.SimNet {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinSimNetParams
	}
	if cfg.Bitcoin.SigNet {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinSigNetParams

		// Let the user overwrite the default signet parameters.
		// The challenge defines the actual signet network to
		// join and the seed nodes are needed for network
		// discovery.
		sigNetChallenge := chaincfg.DefaultSignetChallenge
		sigNetSeeds := chaincfg.DefaultSignetDNSSeeds
		if cfg.Bitcoin.SigNetChallenge != "" {
			challenge, err := hex.DecodeString(
				cfg.Bitcoin.SigNetChallenge,
			)
			if err != nil {
				return nil, mkErr("Invalid "+
					"signet challenge, hex decode "+
					"failed: %v", err)
			}
			sigNetChallenge = challenge
		}

		if len(cfg.Bitcoin.SigNetSeedNode) > 0 {
			sigNetSeeds = make([]chaincfg.DNSSeed, len(
				cfg.Bitcoin.SigNetSeedNode,
			))
			for idx, seed := range cfg.Bitcoin.SigNetSeedNode {
				sigNetSeeds[idx] = chaincfg.DNSSeed{
					Host:         seed,
					HasFiltering: false,
				}
			}
		}

		chainParams := chaincfg.CustomSignetParams(
			sigNetChallenge, sigNetSeeds,
		)
		cfg.ActiveNetParams.Params = &chainParams
	}
	if numNets > 1 {
		str := "The mainnet, testnet, regtest, and simnet " +
			"params can't be used together -- choose one " +
			"of the four"
		return nil, mkErr(str)
	}

	// The target network must be provided, otherwise, we won't
	// know how to initialize the daemon.
	if numNets == 0 {
		str := "either --bitcoin.mainnet, or bitcoin.testnet," +
			"bitcoin.simnet, or bitcoin.regtest " +
			"must be specified"
		return nil, mkErr(str)
	}

	cfg.Bitcoin.ChainDir = filepath.Join(
		cfg.DataDir, defaultChainSubDirname,
		chainreg.BitcoinChain.String(),
	)

	// Finally we'll register the bitcoin chain as our current
	// primary chain.
	cfg.registeredChains.RegisterPrimaryChain(chainreg.BitcoinChain)

	// Validate profile port or host:port.
	if cfg.Profile != "" {
		str := "%s: The profile port must be between 1024 and 65535"

		// Try to parse Profile as a host:port.
		_, hostPort, err := net.SplitHostPort(cfg.Profile)
		if err == nil {
			// Determine if the port is valid.
			profilePort, err := strconv.Atoi(hostPort)
			if err != nil || profilePort < 1024 || profilePort > 65535 {
				return nil, &usageError{mkErr(str)}
			}
		} else {
			// Try to parse Profile as a port.
			profilePort, err := strconv.Atoi(cfg.Profile)
			if err != nil || profilePort < 1024 || profilePort > 65535 {
				return nil, &usageError{mkErr(str)}
			}

			// Since the user just set a port, we will serve debugging
			// information over localhost.
			cfg.Profile = net.JoinHostPort("127.0.0.1", cfg.Profile)
		}
	}

	// We'll now construct the network directory which will be where we
	// store all the data specific to this chain/network.
	cfg.networkDir = filepath.Join(
		cfg.DataDir, defaultChainSubDirname,
		cfg.registeredChains.PrimaryChain().String(),
		lncfg.NormalizeNetwork(cfg.ActiveNetParams.Name),
	)

	// If a custom macaroon directory wasn't specified and the data
	// directory has changed from the default path, then we'll also update
	// the path for the macaroons to be generated.
	if cfg.AdminMacPath == "" {
		cfg.AdminMacPath = filepath.Join(
			cfg.networkDir, defaultAdminMacFilename,
		)
	}
	if cfg.ReadMacPath == "" {
		cfg.ReadMacPath = filepath.Join(
			cfg.networkDir, defaultReadMacFilename,
		)
	}

	// Create the lnd directory and all other sub-directories if they don't
	// already exist. This makes sure that directory trees are also created
	// for files that point to outside the lnddir.
	dirs := []string{
		lndDir, cfg.DataDir, cfg.networkDir,
		cfg.LetsEncryptDir, filepath.Dir(cfg.TLSCertPath),
		filepath.Dir(cfg.TLSKeyPath), filepath.Dir(cfg.AdminMacPath),
		filepath.Dir(cfg.ReadMacPath),
	}
	for _, dir := range dirs {
		if err := makeDirectory(dir); err != nil {
			return nil, err
		}
	}

	// Append the network type to the log directory so it is "namespaced"
	// per network in the same fashion as the data directory.
	cfg.LogDir = filepath.Join(
		cfg.LogDir, cfg.registeredChains.PrimaryChain().String(),
		lncfg.NormalizeNetwork(cfg.ActiveNetParams.Name),
	)

	// A log writer must be passed in, otherwise we can't function and would
	// run into a panic later on.
	if cfg.LogWriter == nil {
		return nil, mkErr("log writer missing in config")
	}

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems",
			cfg.LogWriter.SupportedSubsystems())
		os.Exit(0)
	}

	// Initialize logging at the default logging level.
	SetupLoggers(cfg.LogWriter, interceptor)
	err := cfg.LogWriter.InitLogRotator(
		filepath.Join(cfg.LogDir, defaultLogFilename),
		cfg.MaxLogFileSize, cfg.MaxLogFiles,
	)
	if err != nil {
		str := "log rotation setup failed: %v"
		return nil, mkErr(str, err)
	}

	// Parse, validate, and set debug log level(s).
	err = build.ParseAndSetDebugLevels(cfg.DebugLevel, cfg.LogWriter)
	if err != nil {
		str := "error parsing debug level: %v"
		return nil, &usageError{mkErr(str, err)}
	}

	// At least one RPCListener is required. So listen on localhost per
	// default.
	if len(cfg.RawRPCListeners) == 0 {
		addr := fmt.Sprintf("localhost:%d", defaultRPCPort)
		cfg.RawRPCListeners = append(cfg.RawRPCListeners, addr)
	}

	// Listen on localhost if no REST listeners were specified.
	if len(cfg.RawRESTListeners) == 0 {
		addr := fmt.Sprintf("localhost:%d", defaultRESTPort)
		cfg.RawRESTListeners = append(cfg.RawRESTListeners, addr)
	}

	// Add default port to all RPC listener addresses if needed and remove
	// duplicate addresses.
	cfg.RPCListeners, err = lncfg.NormalizeAddresses(
		cfg.RawRPCListeners, strconv.Itoa(defaultRPCPort),
		net.ResolveTCPAddr,
	)
	if err != nil {
		return nil, mkErr("error normalizing RPC listen addrs: %v", err)
	}

	// Add default port to all REST listener addresses if needed and remove
	// duplicate addresses.
	cfg.RESTListeners, err = lncfg.NormalizeAddresses(
		cfg.RawRESTListeners, strconv.Itoa(defaultRESTPort),
		net.ResolveTCPAddr,
	)
	if err != nil {
		return nil, mkErr("error normalizing REST listen addrs: %v", err)
	}

	switch {

	// The "allow-create" flag cannot be set without the auto unlock file.
	case cfg.WalletUnlockAllowCreate && cfg.WalletUnlockPasswordFile == "":
		return nil, mkErr("cannot set wallet-unlock-allow-create " +
			"without wallet-unlock-password-file")

	// If a password file was specified, we need it to exist.
	case cfg.WalletUnlockPasswordFile != "" &&
		!lnrpc.FileExists(cfg.WalletUnlockPasswordFile):

		return nil, mkErr("wallet unlock password file %s does "+
			"not exist", cfg.WalletUnlockPasswordFile)
	}

	// For each of the RPC listeners (REST+gRPC), we'll ensure that users
	// have specified a safe combo for authentication. If not, we'll bail
	// out with an error. Since we don't allow disabling TLS for gRPC
	// connections we pass in tlsActive=true.
	err = lncfg.EnforceSafeAuthentication(
		cfg.RPCListeners, !cfg.NoMacaroons, true,
	)
	if err != nil {
		return nil, mkErr("error enforcing safe authentication on "+
			"RPC ports: %v", err)
	}

	if cfg.DisableRest {
		ltndLog.Infof("REST API is disabled!")
		cfg.RESTListeners = nil
	} else {
		err = lncfg.EnforceSafeAuthentication(
			cfg.RESTListeners, !cfg.NoMacaroons, !cfg.DisableRestTLS,
		)
		if err != nil {
			return nil, mkErr("error enforcing safe "+
				"authentication on REST ports: %v", err)
		}
	}

	// Newer versions of lnd added a new sub-config for bolt-specific
	// parameters. However, we want to also allow existing users to use the
	// value on the top-level config. If the outer config value is set,
	// then we'll use that directly.
	flagSet, err := isSet("SyncFreelist")
	if err != nil {
		return nil, mkErr("error parsing freelist sync flag: %v", err)
	}
	if flagSet {
		cfg.DB.Bolt.NoFreelistSync = !cfg.SyncFreelist
	}

	// Validate the subconfigs for workers, caches, and the tower client.
	err = lncfg.Validate(
		cfg.Workers,
		cfg.DB,
		cfg.Cluster,
		cfg.HealthChecks,
		cfg.RPCMiddleware,
	)
	if err != nil {
		return nil, err
	}

	// All good, return the sanitized result.
	return &cfg, nil
}

// ImplementationConfig returns the configuration of what actual implementations
// should be used when creating the main lnd instance.
func (c *Config) ImplementationConfig(
	interceptor signal.Interceptor) *ImplementationCfg {

	defaultImpl := NewDefaultWalletImpl(c, ltndLog, interceptor, false)
	return &ImplementationCfg{
		GrpcRegistrar:       defaultImpl,
		ExternalValidator:   defaultImpl,
		DatabaseBuilder:     NewDefaultDatabaseBuilder(c, ltndLog),
		WalletConfigBuilder: defaultImpl,
		ChainControlBuilder: defaultImpl,
	}
}

// CleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func CleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string
		u, err := user.Current()
		if err == nil {
			homeDir = u.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}
