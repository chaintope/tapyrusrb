module Tapyrus
  module Network

    # P2P message handler used by peer connection class.
    module MessageHandler

      # handle p2p message.
      def handle(message)
        peer.last_recv = Time.now.to_i
        peer.bytes_recv += message.bytesize
        begin
          parse(message)
        rescue Tapyrus::Message::Error => e
          logger.error("invalid header magic. #{e.message}")
          close
        end
      end

      def parse(message)
        @message += message
        command, payload, rest = parse_header
        return unless command

        defer_handle_command(command, payload)
        @message = ""
        parse(rest) if rest && rest.bytesize > 0
      end

      def parse_header
        head_magic = Tapyrus.chain_params.magic_head
        return if @message.nil? || @message.size < MESSAGE_HEADER_SIZE

        magic, command, length, checksum = @message.unpack('a4A12Va4')
        raise Tapyrus::Message::Error, "invalid header magic. #{magic.bth}" unless magic.bth == head_magic

        payload = @message[MESSAGE_HEADER_SIZE...(MESSAGE_HEADER_SIZE + length)]
        return if payload.size < length
        raise Tapyrus::Message::Error, "header checksum mismatch. #{checksum.bth}" unless Tapyrus.double_sha256(payload)[0...4] == checksum

        rest = @message[(MESSAGE_HEADER_SIZE + length)..-1]
        [command, payload, rest]
      end

      # handle command with EM#defer
      def defer_handle_command(command, payload)
        operation = proc {handle_command(command, payload)}
        callback = proc{|result|}
        errback = proc{|e|
          logger.error("error occurred. #{e.message}")
          logger.error(e.backtrace)
          peer.handle_error(e)
        }
        EM.defer(operation, callback, errback)
      end

      def handle_command(command, payload)
        logger.info("[#{addr}] process command #{command}.")
        case command
          when Tapyrus::Message::Version::COMMAND
            on_version(Tapyrus::Message::Version.parse_from_payload(payload))
          when Tapyrus::Message::VerAck::COMMAND
            on_ver_ack
          when Tapyrus::Message::GetAddr::COMMAND
            on_get_addr
          when Tapyrus::Message::Addr::COMMAND
            on_addr(Tapyrus::Message::Addr.parse_from_payload(payload))
          when Tapyrus::Message::SendHeaders::COMMAND
            on_send_headers
          when Tapyrus::Message::FeeFilter::COMMAND
            on_fee_filter(Tapyrus::Message::FeeFilter.parse_from_payload(payload))
          when Tapyrus::Message::Ping::COMMAND
            on_ping(Tapyrus::Message::Ping.parse_from_payload(payload))
          when Tapyrus::Message::Pong::COMMAND
            on_pong(Tapyrus::Message::Pong.parse_from_payload(payload))
          when Tapyrus::Message::GetHeaders::COMMAND
            on_get_headers(Tapyrus::Message::GetHeaders.parse_from_payload(payload))
          when Tapyrus::Message::Headers::COMMAND
            on_headers(Tapyrus::Message::Headers.parse_from_payload(payload))
          when Tapyrus::Message::Block::COMMAND
            on_block(Tapyrus::Message::Block.parse_from_payload(payload))
          when Tapyrus::Message::Tx::COMMAND
            on_tx(Tapyrus::Message::Tx.parse_from_payload(payload))
          when Tapyrus::Message::NotFound::COMMAND
            on_not_found(Tapyrus::Message::NotFound.parse_from_payload(payload))
          when Tapyrus::Message::MemPool::COMMAND
            on_mem_pool
          when Tapyrus::Message::Reject::COMMAND
            on_reject(Tapyrus::Message::Reject.parse_from_payload(payload))
          when Tapyrus::Message::SendCmpct::COMMAND
            on_send_cmpct(Tapyrus::Message::SendCmpct.parse_from_payload(payload))
          when Tapyrus::Message::Inv::COMMAND
            on_inv(Tapyrus::Message::Inv.parse_from_payload(payload))
          when Tapyrus::Message::MerkleBlock::COMMAND
            on_merkle_block(Tapyrus::Message::MerkleBlock.parse_from_payload(payload))
          when Tapyrus::Message::CmpctBlock::COMMAND
            on_cmpct_block(Tapyrus::Message::CmpctBlock.parse_from_payload(payload))
          when Tapyrus::Message::GetData::COMMAND
            on_get_data(Tapyrus::Message::GetData.parse_from_payload(payload))
          else
            logger.warn("unsupported command received. command: #{command}, payload: #{payload.bth}")
            close("with command #{command}")
        end
      end

      def send_message(msg)
        logger.info "send message #{msg.class::COMMAND}"
        pkt = msg.to_pkt
        peer.last_send = Time.now.to_i
        peer.bytes_sent = pkt.bytesize
        send_data(pkt)
      end

      def handshake_done
        return unless @incomming_handshake && @outgoing_handshake
        logger.info 'handshake finished.'
        @connected = true
        post_handshake
      end

      def on_version(version)
        logger.info("receive version message. #{version.build_json}")
        @version = version
        send_message(Tapyrus::Message::VerAck.new)
        @incomming_handshake = true
        handshake_done
      end

      def on_ver_ack
        logger.info('receive verack message.')
        @outgoing_handshake = true
        handshake_done
      end

      def on_get_addr
        logger.info('receive getaddr message.')
        peer.send_addrs
      end

      def on_addr(addr)
        logger.info("receive addr message. #{addr.build_json}")
        # TODO
      end

      def on_send_headers
        logger.info('receive sendheaders message.')
        @sendheaders = true
      end

      def on_fee_filter(fee_filter)
        logger.info("receive feefilter message. #{fee_filter.build_json}")
        @fee_rate = fee_filter.fee_rate
      end

      def on_ping(ping)
        logger.info("receive ping message. #{ping.build_json}")
        send_message(ping.to_response)
      end

      def on_pong(pong)
        logger.info("receive pong message. #{pong.build_json}")
        if pong.nonce == peer.last_ping_nonce
          peer.last_ping_nonce = nil
          peer.last_pong = Time.now.to_i
        else
          logger.debug "The remote peer sent the wrong nonce (#{pong.nonce})."
        end
      end

      def on_get_headers(headers)
        logger.info('receive getheaders message.')
        # TODO
      end

      def on_headers(headers)
        logger.info('receive headers message.')
        peer.handle_headers(headers)
      end

      def on_block(block)
        logger.info('receive block message.')
        # TODO
      end

      def on_tx(tx)
        logger.info("receive tx message. #{tx.build_json}")
        peer.handle_tx(tx)
      end

      def on_not_found(not_found)
        logger.info("receive notfound message. #{not_found.build_json}")
        # TODO
      end

      def on_mem_pool
        logger.info('receive mempool message.')
        # TODO return mempool tx
      end

      def on_reject(reject)
        logger.warn("receive reject message. #{reject.build_json}")
        # TODO
      end

      def on_send_cmpct(cmpct)
        logger.info("receive sendcmpct message. #{cmpct.build_json}")
        # TODO if mode is high and version is 1, relay block with cmpctblock message
      end

      def on_inv(inv)
        logger.info('receive inv message.')
        blocks = []
        txs = []
        inv.inventories.each do |i|
          case i.identifier
            when Tapyrus::Message::Inventory::MSG_TX
              txs << i.hash
            when Tapyrus::Message::Inventory::MSG_BLOCK
              blocks << i.hash
            else
              logger.warn("[#{addr}] peer sent unknown inv type: #{i.identifier}")
          end
        end
        logger.info("receive block= #{blocks.size}, txs: #{txs.size}")
        peer.handle_block_inv(blocks) unless blocks.empty?
      end

      def on_merkle_block(merkle_block)
        logger.info("receive merkle block message. #{merkle_block.build_json}")
        peer.handle_merkle_block(merkle_block)
      end

      def on_cmpct_block(cmpct_block)
        logger.info("receive cmpct_block message. #{cmpct_block.build_json}")
      end

      def on_get_data(get_data)
        logger.info("receive get data message. #{get_data.build_json}")
      end
    end
  end
end
