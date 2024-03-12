# Brc20 Inscription Demo

A pure rust demo for p2tr address to inscripting brc20 with Signet.

## Guides to run on your local machine

- Install [Docker][docker] and [Rust][rust] on your machine.

[docker]: https://www.docker.com/products/docker-desktop/
[rust]: https://www.rust-lang.org/tools/install

- Start a Signet node with docker:

  ```shell
  git clone https://github.com/oneforalone/bitcoin-core-docker.git
  cd bitcoin-core-docker
  ./rpcauth.py alice alice | grep "^rpcauth" | tee -a bitcoin/bitcoin.conf
  docker compose --file docker-compose.signet.yaml up -d
  ```

  Wait for the node to synchronize. The total size of Signet is about 1.5 GiB,
  it won't take long time like testnet or mainnet.

- Create a new wallet and generate a new p2tr address in docker:

  ```shell
  alias bcli="bitcoin-cli -rpcconnect=127.0.0.1 -rpcport=38332 \
    -rpcuser=alice -prcpassword=alice"
  bcli -named createwallet "alice" load_on_startup=true
  alias alice="bcli -rpcwallet=alice"
  alice -named getnewaddress address_type=bech32m
  ```

- Get some sBTC from faucet:

  - https://signetfaucet.com/
  - https://alt.signetfaucet.com/

- Get the unspent txid for your address and xpriv key

  ```shell
  alice listdescriptors true
  alice listunspent
  ```

  Change the `xpriv_desc`, `txid` and `unspent_value` in `src/main.rs` to your
  own value, For more info about xpriv, please refere to [descriptor][descriptor]
  and [bip32][bip32].

[descriptor]: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
[bip32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

- Run the program
  ```shell
  cargo run
  ```

If you act correctly, then you'll find your inscription transaction on Signet.
