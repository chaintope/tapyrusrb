module Tapyrus
  module Network
    # remote peer class.
    class Peer
      # Interval for pinging peers.
      PING_INTERVAL = 2 * 60

      attr_reader :logger
      attr_accessor :id
      attr_accessor :local_version
      attr_accessor :last_send
      attr_accessor :last_recv
      attr_accessor :bytes_sent
      attr_accessor :bytes_recv
      attr_accessor :conn_time
      attr_accessor :last_ping
      attr_accessor :last_ping_nonce
      attr_accessor :last_pong
      attr_accessor :min_ping
      attr_accessor :outbound # TODO need implements to accept inbound connection
      attr_accessor :best_hash
      attr_accessor :best_height

      # remote peer info
      attr_reader :host
      attr_reader :port

      # remote peer connection
      attr_accessor :conn
      attr_accessor :connected
      attr_accessor :primary

      # parent pool
      attr_reader :pool
      attr_reader :chain
      attr_accessor :fee_rate

      def initialize(host, port, pool, configuration)
        @host = host
        @port = port
        @pool = pool
        @chain = pool.chain
        @connected = false
        @primary = false
        @logger = Tapyrus::Logger.create(:debug)
        @outbound = true
        @best_hash = -1
        @best_height = -1
        @min_ping = -1
        @bytes_sent = 0
        @bytes_recv = 0
        @relay = configuration.conf[:relay]
        current_height = @chain.latest_block.height
        remote_addr = Tapyrus::Message::NetworkAddr.new(ip: host, port: port, time: nil)
        @local_version =
          Tapyrus::Message::Version.new(remote_addr: remote_addr, start_height: current_height, relay: @relay)
      end

      def connect
        self.conn ||= EM.connect(host, port, Tapyrus::Network::Connection, self)
      end

      def connected?
        @connected
      end

      def outbound?
        @outbound
      end

      def addr
        "#{host}:#{port}"
      end

      # calculate ping-pong time.
      def ping_time
        last_pong ? (last_pong - last_ping) / 1e6 : -1
      end

      # set last pong
      def last_pong=(time)
        @last_pong = time
        @min_ping = ping_time if min_ping == -1 || ping_time < min_ping
      end

      def post_handshake
        @connected = true
        pool.handle_new_peer(self)

        # require remote peer to use headers message instead fo inv message.
        conn.send_message(Tapyrus::Message::SendHeaders.new)
        EM.add_periodic_timer(PING_INTERVAL) { send_ping }
      end

      # start block header download
      def start_block_header_download
        logger.info("[#{addr}] start block header download.")
        get_headers =
          Tapyrus::Message::GetHeaders.new(Tapyrus.chain_params.protocol_version, [chain.latest_block.block_hash])
        conn.send_message(get_headers)
      end

      # broadcast tx.
      def broadcast_tx(tx)
        conn.send_message(Tapyrus::Message::Tx.new(tx))
      end

      # get peer's block type.
      def block_type
        Tapyrus::Message::Inventory::MSG_FILTERED_BLOCK # TODO need other implementation
      end

      # get remote peer's version message.
      # @return [Tapyrus::Message::Version]
      def remote_version
        conn.version
      end

      # Whether to try and download blocks and transactions from this peer.
      def primary?
        primary
      end

      # handle headers message
      # @params [Tapyrus::Message::Headers]
      def handle_headers(headers)
        headers.headers.each do |header|
          break unless header.valid?
          entry = chain.append_header(header)
          next unless entry
          @best_hash = entry.block_hash
          @best_height = entry.height
        end
        pool.changed
        pool.notify_observers(:header, { hash: @best_hash, height: @best_height })
        start_block_header_download if headers.headers.size > 0 # next header download
      end

      # handle error
      def handle_error(e)
        pool.handle_error(e)
      end

      def unbind
        pool.handle_close_peer(self)
      end

      # close peer connection.
      def close(msg = '')
        conn.close(msg)
      end

      # generate Tapyrus::Message::NetworkAddr object from this peer info.
      # @return [Tapyrus::Message::NetworkAddr]
      def to_network_addr
        v = remote_version
        Tapyrus::Message::NetworkAddr.new(ip: host, port: port, services: v.services, time: v.timestamp)
      end

      # send +addr+ message to remote peer
      def send_addrs
        addrs = pool.peers.select { |p| p != self }.map(&:to_network_addr)
        conn.send_message(Tapyrus::Message::Addr.new(addrs))
      end

      # handle block inv message.
      def handle_block_inv(hashes)
        getdata = Tapyrus::Message::GetData.new(hashes.map { |h| Tapyrus::Message::Inventory.new(block_type, h) })
        conn.send_message(getdata)
      end

      def handle_tx(tx)
        pool.changed
        pool.notify_observers(:tx, tx)
      end

      def handle_merkle_block(merkle_block)
        pool.changed
        pool.notify_observers(:merkleblock, merkle_block)
      end

      # send ping message.
      def send_ping
        ping = Tapyrus::Message::Ping.new
        @last_ping = Time.now.to_i
        @last_pong = -1
        @last_ping_nonce = ping.nonce
        conn.send_message(ping)
      end

      # send filterload message.
      def send_filter_load(bloom)
        filter_load = Tapyrus::Message::FilterLoad.new(bloom, Tapyrus::Message::FilterLoad::BLOOM_UPDATE_ALL)
        conn.send_message(filter_load)
      end

      # send filteradd message.
      def send_filter_add(element)
        filter_add = Tapyrus::Message::FilterAdd.new(element)
        conn.send_message(filter_add)
      end

      # send filterclear message.
      def send_filter_clear
        filter_clear = Tapyrus::Message::FilterClear.new
        conn.send_message(filter_clear)
      end
    end
  end
end
