require 'leveldb-native'

module Tapyrus
  module Store
    module DB

      class LevelDB

        attr_reader :db
        attr_reader :logger

        def initialize(path = "#{Tapyrus.base_dir}/db/spv")
          # @logger = Tapyrus::Logger.create(:debug)
          FileUtils.mkdir_p(path)
          @db = ::LevelDBNative::DB.new(path)
          # logger.debug 'Opened LevelDB successfully.'
        end

        # put data into LevelDB.
        # @param [Object] key a key.
        # @param [Object] value a value.
        def put(key, value)
          # logger.debug "put #{key} data"
          db.put(key, value)
        end

        # get value from specified key.
        # @param [Object] key a key.
        # @return[Object] the stored value.
        def get(key)
          db.get(key)
        end

        # get best block hash.
        def best_hash
          db.get(KEY_PREFIX[:best])
        end

        # delete specified key data.
        def delete(key)
          db.delete(key)
        end

        # get block hash specified +height+
        def get_hash_from_height(height)
          db.get(height_key(height))
        end

        # get next block hash specified +hash+
        def next_hash(hash)
          db.get(KEY_PREFIX[:next] + hash)
        end

        # get entry payload
        # @param [String] hash the hash with hex format.
        # @return [String] the ChainEntry payload.
        def get_entry_payload_from_hash(hash)
          db.get(KEY_PREFIX[:entry] + hash)
        end

        # Save entry.
        # @param [Tapyrus::Store::ChainEntry]
        def save_entry(entry)
          db.batch do
            db.put(entry.key ,entry.to_payload)
            db.put(height_key(entry.height), entry.block_hash)
            add_agg_pubkey(entry.height == 0 ? 0 : entry.height + 1, entry.header.x_field) if entry.header.upgrade_agg_pubkey?
            connect_entry(entry)
          end
        end

        # Add aggregated public key.
        # @param [Integer] activate_height
        # @param [String] agg_pubkey aggregated public key with hex format.
        def add_agg_pubkey(activate_height, agg_pubkey)
          payload = activate_height.to_even_length_hex + agg_pubkey
          index = latest_agg_pubkey_index
          next_index = (index.nil? ? 0 : index + 1).to_even_length_hex
          db.batch do
            db.put(KEY_PREFIX[:agg_pubkey] + next_index, payload)
            db.put(KEY_PREFIX[:latest_agg_pubkey], next_index)
          end
        end

        # Get aggregated public key by specifying +index+.
        # @param [Integer] index
        # @return [Array] tupple of activate height and aggregated public key.
        def agg_pubkey(index)
          payload = db.get(KEY_PREFIX[:agg_pubkey] + index.to_even_length_hex)
          [payload[0...(payload.length - 66)].to_i(16), payload[(payload.length - 66)..-1]]
        end

        # Get aggregated public key by specifying block +height+.
        # @param [Integer] height block height.
        # @return [String] aggregated public key with hex format.
        def agg_pubkey_with_height(height)
          index = latest_agg_pubkey_index
          index ||= 0
          (index + 1).times do |i|
            target = index - i
            active_height, pubkey = agg_pubkey(target)
            return pubkey unless active_height > height
          end
        end

        # Get latest aggregated public key.
        # @return [Array] aggregated public key with hex format.
        def latest_agg_pubkey
          agg_pubkey(latest_agg_pubkey_index)[1]
        end

        # Get aggregated public key list.
        # @return [Array[Array]] list of public key and index
        def agg_pubkeys
          index = latest_agg_pubkey_index
          (index + 1).times.map { |i| agg_pubkey(i) }
        end

        def close
          db.close
        end

        private

        # generate height key
        def height_key(height)
          height = height.to_even_length_hex
          KEY_PREFIX[:height] + height.rhex
        end

        def connect_entry(entry)
          unless entry.genesis?
            tip_block = Tapyrus::Store::ChainEntry.parse_from_payload(get_entry_payload_from_hash(best_hash))
            unless tip_block.block_hash == entry.prev_hash
              raise "entry(#{entry.block_hash}) does not reference current best block hash(#{tip_block.block_hash})"
            end
            unless tip_block.height + 1 == entry.height
              raise "block height is small than current best block."
            end
          end
          db.put(KEY_PREFIX[:best], entry.block_hash)
          db.put(KEY_PREFIX[:next] + entry.prev_hash, entry.block_hash)
        end

        # Get latest aggregated public key index.
        # @return [Integer] key index
        def latest_agg_pubkey_index
          index = db.get(KEY_PREFIX[:latest_agg_pubkey])
          index&.to_i(16)
        end

      end

    end
  end
end
