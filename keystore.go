package main

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/keystore"
)

// SaveKeystore encrypts priv with passphrase using the standard (strong)
// scrypt parameters and writes it to outputDir as a geth-compatible
// UTC--<timestamp>--<address> keystore file. It returns the path written.
//
// priv.D is zeroed after import so the raw scalar doesn't linger in memory
// longer than necessary.
func SaveKeystore(priv *ecdsa.PrivateKey, passphrase, outputDir string) (string, error) {
	defer priv.D.SetInt64(0)

	ks := keystore.NewKeyStore(outputDir, keystore.StandardScryptN, keystore.StandardScryptP)
	account, err := ks.ImportECDSA(priv, passphrase)
	if err != nil {
		return "", fmt.Errorf("saving keystore: %w", err)
	}
	return account.URL.Path, nil
}
