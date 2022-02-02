require 'net/http'
require 'json/pure'

module Tapyrus
  module RPC
    # Throw when happened anything http's error with connect to server.
    #
    # Almost case this exception happened from 401 Unauthorized or 500 Internal Server Error.
    # And also, throw by cause of other http's errors.
    #
    # You can pull RPC error message when happened 500 Internal Server Error, like below:
    #
    # rescue Tapyrus::RPC::Error => ex
    #   if ex.message.response_code == 500
    #     puts ex.message[:rpc_error]
    #   end
    # end
    class Error < StandardError
      attr_reader :response_code, :response_msg, :rpc_error

      def initialize(response_code, response_msg, rpc_error)
        @response_code = response_code
        @response_msg = response_msg
        @rpc_error = rpc_error
      end

      # Return response object as Hash
      # @return [Hash] response
      # @option response_code [Integer] HTTP status code
      # @option response_msg [String] HTTP response body
      # @option rpc_error [String] error message received from Tapyrus Core
      def response
        @response ||=
          begin
            m = { response_code: response_code, response_msg: response_msg }
            m.merge!(rpc_error: rpc_error) if rpc_error
            m
          end
      end

      # Return string that represents error message.
      # @return [String] error message
      def message
        response.to_s
      end

      def to_s
        message.to_s
      end
    end

    # Client implementation for RPC to Tapyrus Core.
    #
    # [Usage]
    # config = {schema: 'http', host: 'localhost', port: 18332, user: 'xxx', password: 'yyy'}
    # client = Tapyrus::RPC::TapyrusCoreClient.new(config)
    #
    # You can execute the CLI command supported by Tapyrus Core as follows:
    #
    # client.listunspent
    # client.getblockchaininfo
    #
    class TapyrusCoreClient
      attr_reader :config

      # @param [Hash] config a configuration required to connect to Bitcoin Core.
      def initialize(config)
        @config = config

        commands =
          request(:help)
            .split("\n")
            .inject([]) do |memo_ary, line|
              memo_ary << line.split(' ').first.to_sym if !line.empty? && !line.start_with?('==')
              memo_ary
            end
        TapyrusCoreClient.class_eval do
          commands.each { |command| define_method(command) { |*params| request(command, *params) } }
        end
      end

      private

      def server_url
        url = "#{config[:schema]}://#{config[:user]}:#{config[:password]}@#{config[:host]}:#{config[:port]}"
        url += "/wallet/#{config[:wallet]}" if !config[:wallet].nil? && !config[:wallet].empty?
        url
      end

      def request(command, *params)
        data = { method: command, params: params, id: 'jsonrpc' }
        uri = URI.parse(server_url)
        http = Net::HTTP.new(uri.hostname, uri.port)
        http.use_ssl = uri.scheme === 'https'
        request = Net::HTTP::Post.new(uri.path.empty? ? '/' : uri.path)
        request.basic_auth(uri.user, uri.password)
        request.content_type = 'application/json'
        request.body = data.to_json
        response = http.request(request)
        raise error!(response) unless response.is_a? Net::HTTPOK
        response = Tapyrus::RPC.response_body2json(response.body)
        response['result']
      end

      def error!(response)
        rpc_error =
          begin
            Tapyrus::RPC.response_body2json(response.body)['error']
          rescue JSON::ParserError => _
            # if RPC server don't send error message.
          end

        raise Error.new(response.code, response.msg, rpc_error)
      end
    end

    def response_body2json(body)
      Tapyrus::Ext::JsonParser.new(
        body.gsub(/\\u([\da-fA-F]{4})/) do
          [$1].pack('H*').unpack('n*').pack('U*').encode('ISO-8859-1').force_encoding('UTF-8')
        end
      ).parse
    end

    module_function :response_body2json
  end
end
