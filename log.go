package minimalsigner

import (
	"errors"
	"os"

	"github.com/btcsuite/btclog"
)

var signerLog = btclog.NewBackend(os.Stdout).Logger("SIGNER")

func setLogLevel(level string) error {
	logLevel, ok := btclog.LevelFromString(level)
	if !ok {
		return errors.New("invalid log level: " + level)
	}

	signerLog.SetLevel(logLevel)

	return nil
}
