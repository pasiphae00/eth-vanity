# Vanity address generator (`eth-vanity`)

A simple go-based Ethereum account generator that searches for and generates a private key coresponding to a public address with your specified "vanity" bytes as a prefix and/or suffix.

## Usage

Use `--prefix` (`-p`) and/or `--suffix` (`-s`) to set desired vanity bytes. If neither is specified, a new random account is generated.

When a matching account is found, you will be prompted to set an encryption key (passphrase) and then a keystore JSON will be saved to the specified output location (default is current directory).

Since Ethereum public addresses use hexidecimal encoding, the characters you can chose from are:

```
A B C D E F 0 1 2 3 4 5 6 7 8 9
```

Alphabetic characters are case-insenstivie. Distinguishing `fedbad` from `fedBAD` with checksum'd addresses would make successful generation unlikely due to a much larger search space.

## Examples

```
$ eth-vanity \
  --prefix "6967" \   # vanity bytes at the begining of the public address
  --suffix "0000" \    # vanity bytes at the end of the public address
  --output . \        # location to save the encrypted keystore (default current directory)
  --threads 16        # the number of concurrent go-routines to spawn to search for a matching account (default: number of CPUs)
```

And in short form:
```
$ eth-vanity \
  -p "1111" \
  -s "1111" \
  -o . \
  -t 16
