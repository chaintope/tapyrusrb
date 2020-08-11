module Tapyrus

  module Store

    KEY_PREFIX = {
        entry: 'e',             # key: block hash, value: Tapyrus::Store::ChainEntry payload
        height: 'h',            # key: block height, value: block hash.
        best: 'B',              # value: best block hash.
        next: 'n',              # key: block hash, value: A hash of the next block of the specified hash
        agg_pubkey: 'a',        # key: index, value: Activated block height | aggregated public key.
        latest_agg_pubkey: 'g'  # value: latest agg pubkey index.
    }

    class SPVChain

      attr_reader :db
      attr_reader :logger

      # initialize spv chain
      # @param[Tapyrus::Store::DB::LevelDB] db
      # @param[Tapyrus::Block] genesis genesis block
      def initialize(db = Tapyrus::Store::DB::LevelDB.new, genesis: nil)
        raise ArgumentError, 'genesis block should be specified.' unless genesis
        @db = db # TODO multiple db switch
        @logger = Tapyrus::Logger.create(:debug)
        initialize_block(genesis)
      end

      # get latest block in the store.
      # @return[Tapyrus::Store::ChainEntry]
      def latest_block
        hash = db.best_hash
        return nil unless hash
        find_entry_by_hash(hash)
      end

      # find block entry with the specified height.
      def find_entry_by_height(height)
        find_entry_by_hash(db.get_hash_from_height(height))
      end

      # find block entry with the specified hash
      def find_entry_by_hash(hash)
        payload = db.get_entry_payload_from_hash(hash)
        return nil unless payload
        ChainEntry.parse_from_payload(payload)
      end

      # append block header to chain.
      # @param [Tapyrus::BlockHeader] header a block header.
      # @return [Tapyrus::Store::ChainEntry] appended block header entry.
      def append_header(header)
        logger.info("append header #{header.block_id}")
        best_block = latest_block
        current_height = best_block.height
        raise "this header is invalid. #{header.block_hash}" unless header.valid?(db.agg_pubkey_with_height(current_height + 1))
        if best_block.block_hash == header.prev_hash
          entry = Tapyrus::Store::ChainEntry.new(header, current_height + 1)
          db.save_entry(entry)
          entry
        else
          unless find_entry_by_hash(header.block_hash)
            # TODO implements recovery process
            raise "header's previous hash(#{header.prev_hash}) does not match current best block's(#{best_block.block_hash})."
          end
        end
      end

      # get next block hash for specified +hash+
      # @param [String] hash the block hash(little endian)
      # @return [String] the next block hash. If it does not exist yet, return nil.
      def next_hash(hash)
        db.next_hash(hash)
      end

      # get median time past for specified block +hash+
      # @param [String] hash the block hash.
      # @return [Integer] the median time past value.
      def mtp(hash)
        time = []
        Tapyrus::MEDIAN_TIME_SPAN.times do
          entry = find_entry_by_hash(hash)
          break unless entry

          time << entry.header.time
          hash = entry.header.prev_hash
        end
        time.sort!
        time[time.size / 2]
      end

      # Add aggregated public key.
      # @param [Integer] active_height
      # @param [String] agg_pubkey aggregated public key with hex format.
      def add_agg_pubkey(active_height, agg_pubkey)
        db.add_agg_pubkey(active_height, agg_pubkey)
      end

      # get aggregated public key keys.
      # @return [Array[Array(height, agg_pubkey)]] the list of public keys.
      def agg_pubkeys
        db.agg_pubkeys
      end

      private

      # if database is empty, put genesis block.
      # @param [Tapyrus::Block] genesis genesis block
      def initialize_block(genesis)
        unless latest_block
          db.save_entry(ChainEntry.new(genesis.header, 0))
        end
      end

    end

  end

end