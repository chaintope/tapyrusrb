# Tapyrusrb [![Build Status](https://travis-ci.org/chaintope/tapyrusrb.svg?branch=master)](https://travis-ci.org/chaintope/tapyrusrb) [![Gem Version](https://badge.fury.io/rb/tapyrus.svg)](https://badge.fury.io/rb/tapyrus) [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)


Tapyrusrb is a Ruby implementation of [Tapyrus](https://github.com/chaintope/tapyrus-core) Protocol.

NOTE: Tapyrusrb work in progress, and there is a possibility of incompatible change. 

## Features

Tapyrusrb supports following feature:

* Tapyrus script interpreter
* De/serialization of Tapyrus protocol network messages
* De/serialization of blocks and transactions
* Key generation and verification for Schnorr and ECDSA (including [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) and [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) supports).
* ECDSA signature(RFC6979 -Deterministic ECDSA, LOW-S, LOW-R support)
* [WIP] SPV node
* [WIP] 0ff-chain protocol

## Requirements

### use Node implementation

If you use node features, please install level DB as follows.

#### install LevelDB

* for Ubuntu

    $ sudo apt-get install libleveldb-dev

+ for Mac

    $ brew install leveldb

and put `leveldb-native` in your Gemfile and run bundle install.

```
gem leveldb-native
```

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'tapyrus'
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

* prod

```ruby
Tapyrus.chain_params = :prod
```

This parameter is described in https://github.com/chaintope/tapyrusrb/blob/master/lib/tapyrus/chainparams/prod.yml.

* dev

```ruby
Tapyrus.chain_params = :dev
```

This parameter is described in https://github.com/chaintope/tapyrusrb/blob/master/lib/tapyrus/chainparams/dev.yml.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/tapyrusrb. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

