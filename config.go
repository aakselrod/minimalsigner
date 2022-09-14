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
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	flags "github.com/jessevdk/go-flags"
	"github.com/lightningnetwork/lnd/lncfg"
)

const (
	defaultConfigFilename  = "signer.conf"
	defaultTLSCertFilename = "tls.cert"
	defaultTLSKeyFilename  = "tls.key"
	defaultLogLevel        = "info"
	defaultLogDirname      = "logs"
	defaultLogFilename     = "signer.log"
	defaultRPCPort         = 10009
	defaultRPCHost         = "localhost"

	defaultMaxLogFiles    = 3
	defaultMaxLogFileSize = 10

	// DefaultAutogenValidity is the default validity of a self-signed
	// certificate. The value corresponds to 14 months
	// (14 months * 30 days * 24 hours).
	defaultTLSCertDuration = 14 * 30 * 24 * time.Hour

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
	// DefaultSignerDir is the default directory where lnd tries to find its
	// configuration file and store its data. This is a directory in the
	// user's application data, for example:
	//   C:\Users\<username>\AppData\Local\Signer on Windows
	//   ~/.signer on Linux
	//   ~/Library/Application Support/Signer on MacOS
	DefaultSignerDir = btcutil.AppDataDir("signer", false)

	// DefaultConfigFile is the default full path of lnd's configuration
	// file.
	DefaultConfigFile = filepath.Join(DefaultSignerDir, defaultConfigFilename)

	defaultLogDir = filepath.Join(DefaultSignerDir, defaultLogDirname)

	defaultTLSCertPath = filepath.Join(DefaultSignerDir, defaultTLSCertFilename)
	defaultTLSKeyPath  = filepath.Join(DefaultSignerDir, defaultTLSKeyFilename)
)

// Config defines the configuration options for lnd.
//
// See LoadConfig for further details regarding the configuration
// loading+parsing process.
type Config struct {
	SignerDir  string `long:"lnddir" description:"The base directory that contains signer's data, logs, configuration file, etc."`
	ConfigFile string `short:"C" long:"configfile" description:"Path to configuration file"`

	TLSCertPath        string        `long:"tlscertpath" description:"Path to write the TLS certificate for lnd's RPC services"`
	TLSKeyPath         string        `long:"tlskeypath" description:"Path to write the TLS private key for lnd's RPC services"`
	TLSExtraIPs        []string      `long:"tlsextraip" description:"Adds an extra ip to the generated certificate"`
	TLSExtraDomains    []string      `long:"tlsextradomain" description:"Adds an extra domain to the generated certificate"`
	TLSAutoRefresh     bool          `long:"tlsautorefresh" description:"Re-generate TLS certificate and key if the IPs or domains are changed"`
	TLSDisableAutofill bool          `long:"tlsdisableautofill" description:"Do not include the interface IPs or the system hostname in TLS certificate, use first --tlsextradomain as Common Name instead, if set"`
	TLSCertDuration    time.Duration `long:"tlscertduration" description:"The duration for which the auto-generated TLS certificate will be valid for"`

	OutputMacaroon string `long:"outputmacaroon" description:"Path to write a signer macaroon for the watch-only node"`
	OutputAccounts string `long:"outputaccounts" description:"Path to write a JSON file with xpubs for the watch-only node"`

	LogDir         string `long:"logdir" description:"Directory to log output."`
	MaxLogFiles    int    `long:"maxlogfiles" description:"Maximum logfiles to keep (0 for no rotation)"`
	MaxLogFileSize int    `long:"maxlogfilesize" description:"Maximum logfile size in MB"`

	// We'll parse these 'raw' string arguments into real net.Addrs in the
	// loadConfig function. We need to expose the 'raw' strings so the
	// command line library can access them.
	// Only the parsed net.Addrs should be used!
	RawRPCListeners []string `long:"rpclisten" description:"Add an interface/port/socket to listen for RPC connections"`
	RPCListeners    []net.Addr

	DebugLevel string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical}"`

	MainNet         bool     `long:"mainnet" description:"Use the main network"`
	TestNet3        bool     `long:"testnet" description:"Use the test network"`
	SimNet          bool     `long:"simnet" description:"Use the simulation test network"`
	RegTest         bool     `long:"regtest" description:"Use the regression test network"`
	SigNet          bool     `long:"signet" description:"Use the signet test network"`
	SigNetChallenge string   `long:"signetchallenge" description:"Connect to a custom signet network defined by this challenge instead of using the global default signet test network -- Can be specified multiple times"`
	SigNetSeedNode  []string `long:"signetseednode" description:"Specify a seed node for the signet network instead of using the global default signet network seed nodes"`

	// ActiveNetParams contains parameters of the target chain.
	ActiveNetParams chaincfg.Params
}

// DefaultConfig returns all default values for the Config struct.
func DefaultConfig() Config {
	return Config{
		SignerDir:       DefaultSignerDir,
		ConfigFile:      DefaultConfigFile,
		DebugLevel:      defaultLogLevel,
		TLSCertPath:     defaultTLSCertPath,
		TLSKeyPath:      defaultTLSKeyPath,
		TLSCertDuration: defaultTLSCertDuration,
		LogDir:          defaultLogDir,
		MaxLogFiles:     defaultMaxLogFiles,
		MaxLogFileSize:  defaultMaxLogFileSize,
		ActiveNetParams: chaincfg.RegressionNetParams,
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
func LoadConfig() (*Config, error) {
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

	// If the config file path has not been modified by the user, then we'll
	// use the default config file path. However, if the user has modified
	// their lnddir, then we should assume they intend to use the config
	// file within it.
	configFileDir := CleanAndExpandPath(preCfg.SignerDir)
	configFilePath := CleanAndExpandPath(preCfg.ConfigFile)
	switch {
	// User specified --lnddir but no --configfile. Update the config file
	// path to the lnd config directory, but don't require it to exist.
	case configFileDir != DefaultSignerDir &&
		configFilePath == DefaultConfigFile:

		configFilePath = filepath.Join(
			configFileDir, defaultConfigFilename,
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
		cfg, fileParser, flagParser,
	)
	if usageErr, ok := err.(*usageError); ok {
		// The logging system might not yet be initialized, so we also
		// write to stderr to make sure the error appears somewhere.
		_, _ = fmt.Fprintln(os.Stderr, usageMessage)
		signerLog.Warnf("Incorrect usage: %v", usageMessage)

		// The log subsystem might not yet be initialized. But we still
		// try to log the error there since some packaging solutions
		// might only look at the log and not stdout/stderr.
		signerLog.Warnf("Error validating config: %v", usageErr.err)

		return nil, usageErr.err
	}
	if err != nil {
		// The log subsystem might not yet be initialized. But we still
		// try to log the error there since some packaging solutions
		// might only look at the log and not stdout/stderr.
		signerLog.Warnf("Error validating config: %v", err)

		return nil, err
	}

	// Warn about missing config file only after all other configuration is
	// done. This prevents the warning on help messages and invalid options.
	// Note this should go directly before the return.
	if configFileError != nil {
		signerLog.Warnf("%v", configFileError)
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
func ValidateConfig(cfg Config, fileParser, flagParser *flags.Parser) (
	*Config, error) {

	// If the provided lnd directory is not the default, we'll modify the
	// path to all of the files and directories that will live within it.
	signerDir := CleanAndExpandPath(cfg.SignerDir)
	if signerDir != DefaultSignerDir {
		cfg.TLSCertPath = filepath.Join(signerDir, defaultTLSCertFilename)
		cfg.TLSKeyPath = filepath.Join(signerDir, defaultTLSKeyFilename)
		cfg.LogDir = filepath.Join(signerDir, defaultLogDirname)
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

	// As soon as we're done parsing configuration options, ensure all paths
	// to directories and files are cleaned and expanded before attempting
	// to use them later on.
	cfg.TLSCertPath = CleanAndExpandPath(cfg.TLSCertPath)
	cfg.TLSKeyPath = CleanAndExpandPath(cfg.TLSKeyPath)
	cfg.LogDir = CleanAndExpandPath(cfg.LogDir)

	// Multiple networks can't be selected simultaneously.  Count
	// number of network flags passed; assign active network params
	// while we're at it.
	numNets := 0
	if cfg.MainNet {
		numNets++
		cfg.ActiveNetParams = chaincfg.MainNetParams
	}
	if cfg.TestNet3 {
		numNets++
		cfg.ActiveNetParams = chaincfg.TestNet3Params
	}
	if cfg.RegTest {
		numNets++
		cfg.ActiveNetParams = chaincfg.RegressionNetParams
	}
	if cfg.SimNet {
		numNets++
		cfg.ActiveNetParams = chaincfg.SimNetParams
	}
	if cfg.SigNet {
		numNets++
		cfg.ActiveNetParams = chaincfg.SigNetParams

		// Let the user overwrite the default signet parameters.
		// The challenge defines the actual signet network to
		// join and the seed nodes are needed for network
		// discovery.
		sigNetChallenge := chaincfg.DefaultSignetChallenge
		sigNetSeeds := chaincfg.DefaultSignetDNSSeeds
		if cfg.SigNetChallenge != "" {
			challenge, err := hex.DecodeString(
				cfg.SigNetChallenge,
			)
			if err != nil {
				return nil, mkErr("Invalid "+
					"signet challenge, hex decode "+
					"failed: %v", err)
			}
			sigNetChallenge = challenge
		}

		if len(cfg.SigNetSeedNode) > 0 {
			sigNetSeeds = make([]chaincfg.DNSSeed, len(
				cfg.SigNetSeedNode,
			))
			for idx, seed := range cfg.SigNetSeedNode {
				sigNetSeeds[idx] = chaincfg.DNSSeed{
					Host:         seed,
					HasFiltering: false,
				}
			}
		}

		chainParams := chaincfg.CustomSignetParams(
			sigNetChallenge, sigNetSeeds,
		)
		cfg.ActiveNetParams = chainParams
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

	// Create the lnd directory and all other sub-directories if they don't
	// already exist. This makes sure that directory trees are also created
	// for files that point to outside the lnddir.
	dirs := []string{
		signerDir, filepath.Dir(cfg.TLSCertPath),
		filepath.Dir(cfg.TLSKeyPath), filepath.Dir(cfg.OutputMacaroon),
	}
	for _, dir := range dirs {
		if err := makeDirectory(dir); err != nil {
			return nil, err
		}
	}

	err := setLogLevel(cfg.DebugLevel)
	if err != nil {
		return nil, mkErr("error setting debug level: %v", err)
	}

	// At least one RPCListener is required. So listen on localhost per
	// default.
	if len(cfg.RawRPCListeners) == 0 {
		addr := fmt.Sprintf("localhost:%d", defaultRPCPort)
		cfg.RawRPCListeners = append(cfg.RawRPCListeners, addr)
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

	// All good, return the sanitized result.
	return &cfg, nil
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
