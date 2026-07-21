# Vanity address generator (`eth-vanity`)

A simple go-based Ethereum account generator that searches for and generates a private key coresponding to a public address with your specified "vanity" bytes as a prefix and/or suffix.

## Usage

Use `--prefix` and/or `--suffix` to set desired vanity bytes. If neither is specified, a new random account is generated.

```
$ eth-vanity \
  --prefix "0000" \   # vanity bytes at the begining of the public address
  --suffix "666" \    # vanity bytes at the end of the public address
  --passphrase "pwd"  # encryption key for the keystore output (required)
  --output . \        # location to save the encrypted keystore (default current directory)
  --threads 50        # the number of concurrent go-routines to spawn to search for a matching account (default 50)
```

And in short form:
```
$ eth-vanity \
  -p "0000" \
  -s "0000" \
  -k "your passphrase" \
  -o . \
  -t 50
