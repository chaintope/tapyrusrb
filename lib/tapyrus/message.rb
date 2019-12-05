module Tapyrus
  module Message

    autoload :Base, 'tapyrus/message/base'
    autoload :Inventory, 'tapyrus/message/inventory'
    autoload :InventoriesParser, 'tapyrus/message/inventories_parser'
    autoload :HeadersParser, 'tapyrus/message/headers_parser'
    autoload :Version, 'tapyrus/message/version'
    autoload :VerAck, 'tapyrus/message/ver_ack'
    autoload :Addr, 'tapyrus/message/addr'
    autoload :NetworkAddr, 'tapyrus/message/network_addr'
    autoload :Block, 'tapyrus/message/block'
    autoload :FilterLoad, 'tapyrus/message/filter_load'
    autoload :FilterAdd, 'tapyrus/message/filter_add'
    autoload :FilterClear, 'tapyrus/message/filter_clear'
    autoload :MerkleBlock, 'tapyrus/message/merkle_block'
    autoload :Tx, 'tapyrus/message/tx'
    autoload :Ping, 'tapyrus/message/ping'
    autoload :Pong, 'tapyrus/message/pong'
    autoload :Inv, 'tapyrus/message/inv'
    autoload :GetBlocks, 'tapyrus/message/get_blocks'
    autoload :GetHeaders, 'tapyrus/message/get_headers'
    autoload :Headers, 'tapyrus/message/headers'
    autoload :GetAddr, 'tapyrus/message/get_addr'
    autoload :GetData, 'tapyrus/message/get_data'
    autoload :SendHeaders, 'tapyrus/message/send_headers'
    autoload :FeeFilter, 'tapyrus/message/fee_filter'
    autoload :MemPool, 'tapyrus/message/mem_pool'
    autoload :NotFound, 'tapyrus/message/not_found'
    autoload :Error, 'tapyrus/message/error'
    autoload :Reject, 'tapyrus/message/reject'
    autoload :SendCmpct, 'tapyrus/message/send_cmpct'
    autoload :CmpctBlock, 'tapyrus/message/cmpct_block'
    autoload :HeaderAndShortIDs, 'tapyrus/message/header_and_short_ids'
    autoload :PrefilledTx, 'tapyrus/message/prefilled_tx'
    autoload :GetBlockTxn, 'tapyrus/message/get_block_txn'
    autoload :BlockTransactionRequest, 'tapyrus/message/block_transaction_request'
    autoload :BlockTxn, 'tapyrus/message/block_txn'
    autoload :BlockTransactions, 'tapyrus/message/block_transactions'

    USER_AGENT = "/tapyrusrb:#{Tapyrus::VERSION}/"

    SERVICE_FLAGS = {
        none: 0,
        network: 1 << 0,  # the node is capable of serving the block chain. It is currently set by all Bitcoin Core node, and is unset by SPV clients or other peers that just want network services but don't provide them.
        # getutxo: 1 << 1, # BIP-64. not implemented in Bitcoin Core.
        bloom: 1 << 2,    # the node is capable and willing to handle bloom-filtered connections. Bitcoin Core node used to support this by default, without advertising this bit, but no longer do as of protocol version 70011 (= NO_BLOOM_VERSION)
        #witness: 1 << 3,  # the node can be asked for blocks and transactions including witness data.
        # xthin: 1 << 4 # support Xtreme Thinblocks. not implemented in Bitcoin Core
    }

    # DEFAULT_SERVICE_FLAGS = SERVICE_FLAGS[:network] | SERVICE_FLAGS[:bloom] | SERVICE_FLAGS[:witness]

    DEFAULT_SERVICE_FLAGS = SERVICE_FLAGS[:none]

    DEFAULT_STOP_HASH = "00"*32

    # the protocol version.
    VERSION = {
        headers: 31800,
        pong: 60001,
        bloom: 70011,
        send_headers: 70012,
        fee_filter: 70013,
        compact: 70014,
        compact_witness: 70015
    }

  end
end
