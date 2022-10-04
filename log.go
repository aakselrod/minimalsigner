package minimalsigner

import (
	"errors"
	"os"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btclog"
)

var (
	backend     = btclog.NewBackend(os.Stdout)
	signerLog   = backend.Logger("SIGNER")
	txscriptLog = backend.Logger("TXSCRIPT")
	keyringLog  = backend.Logger("KEYRING")
)

func setLogLevel(level string) error {
	logLevel, ok := btclog.LevelFromString(level)
	if !ok {
		return errors.New("invalid log level: " + level)
	}

	signerLog.SetLevel(logLevel)

	txscriptLog.SetLevel(logLevel)
	txscript.UseLogger(txscriptLog)

	return nil
}
