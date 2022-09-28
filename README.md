# minimalsigner
`minimalsigner` is a proof of concept of a stateless remote signer for lnd. Currently, it can do the following:
- [x] import wallet seed and macaroon root key from environment variables
- [x] export account list and macaroon for watch-only lnd instance
- [x] sign messages for network announcements
- [x] derive shared keys for peer connections
- [x] sign PSBTs for on-chain transactions, channel openings/closes, HTLC updates, etc.
- [x] verify macaroons on grpc request
- [ ] perform musig2 ops
- [ ] add and verify macaroon caveats (like expiration or ip address restriction)
- [ ] allow an interceptor to determine whether or not to sign
- [ ] run unit tests and itests, do automated builds
- [ ] log and gather metrics coherently

## Usage

Ensure you have `bitcoind` and `lnd` installed. Build `signer` using Go 1.18+ from this directory:

`go install ./cmd/...`

Create a directory `~/.signer` with a `signer.conf` similar to:

```
rpclisten=tcp://127.0.0.1:10021
regtest=true
```

Create a `~/.lnd-watchonly` with a `lnd.conf` similar to:

```
[bitcoin]
bitcoin.active=true
bitcoin.regtest=true
bitcoin.node=bitcoind

[remotesigner]
remotesigner.enable=true
remotesigner.rpchost=127.0.0.1:10021
remotesigner.tlscertpath=/home/user/.signer/tls.cert
remotesigner.macaroonpath=/home/user/.signer/signer.custom.macaroon
```

Run as follows, with the wallet seed in `SIGNER_SEED` and the macaroon root key in `SIGNER_MAC_ROOT_KEY`:

```
~/.signer$ SIGNER_SEED=1111111111222222222233333333334444444444555555555566666666661234 \
              SIGNER_MAC_ROOT_KEY=6666666666555555555544444444443333333333222222222211111111114321 \
              signer --outputmacaroon=signer.custom.macaroon --outputaccounts=accounts.json
```

Now, run `lnd` in watch-only mode:

`~/.lnd-watchonly$ lnd --lnddir=.`

Create the watch-only wallet:

`~$ lncli createwatchonly .signer/accounts.json`

For more information regarding remotesigner mode in `lnd`, see [the lnd docs](https://github.com/lightningnetwork/lnd/blob/v0.15.1-beta/docs/remote-signing.md).
