# Tapyrusrb [![Build Status](https://github.com/chaintope/tapyrusrb/actions/workflows/ruby.yml/badge.svg?branch=master)](https://github.com/chaintope/tapyrusrb/actions/workflows/ruby.yml) [![Gem Version](https://badge.fury.io/rb/tapyrus.svg)](https://badge.fury.io/rb/tapyrus) [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)

Tapyrusrb is a Ruby implementation of [Tapyrus](https://github.com/chaintope/tapyrus-core) Protocol.

NOTE: Tapyrusrb work in progress, and there is a possibility of incompatible change.

## Features

Tapyrusrb supports following feature:

- Tapyrus script interpreter
- De/serialization of Tapyrus protocol network messages
- De/serialization of blocks and transactions
- Key generation and verification for Schnorr and ECDSA (including [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) and [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) supports).
- ECDSA signature(RFC6979 -Deterministic ECDSA, LOW-S, LOW-R support)
- Schnorr signature
- Partially Signed Tapyrus Transaction ([TIP-0174](https://github.com/chaintope/tips/blob/master/tip-0174.md))

## Requirements

### use Node implementation

If you use node features, please install level DB as follows.

#### install LevelDB

- for Ubuntu

  $ sudo apt-get install libleveldb-dev

* for Mac

  $ brew install leveldb

and put `leveldb-native` in your Gemfile and run bundle install.

```
gem leveldb-native
```

## Installation

Add this line to your application's Gemfile:

```ruby
gem "tapyrus"
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install tapyrus

And then add to your .rb file:

    require 'tapyrus'

## Usage

### Chain selection

The parameters of the blockchain are managed by `Tapyrus::ChainParams`. Switch chain parameters as follows:

- prod

```ruby
Tapyrus.chain_params = :prod
```

This parameter is described in https://github.com/chaintope/tapyrusrb/blob/master/lib/tapyrus/chainparams/prod.yml.

- dev

```ruby
Tapyrus.chain_params = :dev
```

This parameter is described in https://github.com/chaintope/tapyrusrb/blob/master/lib/tapyrus/chainparams/dev.yml.

### PSTT (Partially Signed Tapyrus Transaction)

`Tapyrus::PSTT` implements the format [TIP-0174](https://github.com/chaintope/tips/blob/master/tip-0174.md) defines.
Its methods follow the roles of the TIP: Creator, Constructor, Updater, Signer, Combiner, Input Finalizer and
Transaction Extractor.

```ruby
# Creator
pstt =
  Tapyrus::PSTT::Tx.new(
    inputs: [Tapyrus::PSTT::Input.new(out_point: out_point, utxo: prev_tx)],
    outputs: [Tapyrus::PSTT::Output.new(amount: 99_000, script_pubkey: script_pubkey)]
  )

# Signer. The signature hash is computed from the fields of the PSTT.
pstt.sign(0, key) # ECDSA. Pass algo: :schnorr for a Schnorr signature.

# Input Finalizer and Transaction Extractor
pstt.finalize!
tx = pstt.extract_tx

# For text transport
Tapyrus::PSTT::Tx.from_base64(pstt.to_base64)
```

A PSTT which other parties will extend is created with `tx_modifiable`, so that a Constructor can add inputs and
outputs afterwards. This is what a fee provider, which supplies the TPC that pays the fee of a Colored Coin
transaction, needs:

```ruby
# The user leaves the inputs modifiable and signs with SIGHASH_ALL | SIGHASH_ANYONECANPAY.
pstt = Tapyrus::PSTT::Tx.new(tx_modifiable: Tapyrus::PSTT::TxModifiable::INPUTS, inputs: inputs, outputs: outputs)
pstt.sign(0, key, sighash_type: Tapyrus::SIGHASH_TYPE[:all] | Tapyrus::SIGHASH_TYPE[:anyonecanpay])

# The fee provider verifies the amounts per color, then adds its TPC input and signs with SIGHASH_ALL.
pstt.input_amounts # => { Tapyrus::Color::ColorIdentifier => amount }
pstt.fee
pstt.add_input(Tapyrus::PSTT::Input.new(out_point: fee_out_point, utxo: fee_tx))
pstt.sign(1, provider_key)
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/tapyrusrb. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
