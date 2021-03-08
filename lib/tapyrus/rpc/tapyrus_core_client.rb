require 'net/http'
require 'json/pure'

module Tapyrus
  module RPC

    # Throw when happened anything http's error with connect to server.
    #
    # Almost case this exception happened from 401 Unauthorized.
    # And also, throw by cause of other http's errors.
    #
    # You can get raw response as cause, like as:
    #
    # rescue TapyrusClientConnectionError => ex
    #   ex.response
    # end
    class Error < StandardError
      attr_reader :response
      attr_reader :message

      def initialize(response)
        raise ArgumentError, "Must set response as cause." unless response
        @response = response

        # set message from response body or status code.
        begin
          @message = Tapyrus::RPC::response_body2json(response.body)['error']
        rescue JSON::ParserError => _
          # if RPC server don't send error message, then set http status message.
          @message = "#{response&.code} #{response&.msg}"
        end
      end

      def to_s
        @message.to_s
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

        commands = request(:help).split("\n").inject([]) do |memo_ary, line|
          if !line.empty? && !line.start_with?('==')
            memo_ary << line.split(' ').first.to_sym
          end
          memo_ary
        end
        TapyrusCoreClient.class_eval do
          commands.each do |command|
            define_method(command) do |*params|
              request(command, *params)
            end
          end
        end
      end

      private

      def server_url
        url = "#{config[:schema]}://#{config[:user]}:#{config[:password]}@#{config[:host]}:#{config[:port]}"
        if !config[:wallet].nil? && !config[:wallet].empty?
          url += "/wallet/#{config[:wallet]}"
        end
        url
      end

      def request(command, *params)
        data = {
            :method => command,
            :params => params,
            :id => 'jsonrpc'
        }
        uri = URI.parse(server_url)
        http = Net::HTTP.new(uri.hostname, uri.port)
        http.use_ssl = uri.scheme === "https"
        request = Net::HTTP::Post.new(uri.path.empty? ? '/' : uri.path)
        request.basic_auth(uri.user, uri.password)
        request.content_type = 'application/json'
        request.body = data.to_json
        response = http.request(request)
        raise Error.new(response) unless response.is_a? Net::HTTPOK
        response = Tapyrus::RPC::response_body2json(response.body)
        response['result']
      end

    end

    def response_body2json(body)
      Tapyrus::Ext::JsonParser.new(body.gsub(/\\u([\da-fA-F]{4})/) { [$1].pack('H*').unpack('n*').pack('U*').encode('ISO-8859-1').force_encoding('UTF-8') }).parse
    end

    module_function :response_body2json
  end
end
