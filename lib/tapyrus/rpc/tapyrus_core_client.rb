require 'net/http'
require 'json/pure'

module Tapyrus
  module RPC

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
        body = response.body
        response = Tapyrus::Ext::JsonParser.new(body.gsub(/\\u([\da-fA-F]{4})/) { [$1].pack('H*').unpack('n*').pack('U*').encode('ISO-8859-1').force_encoding('UTF-8') }).parse
        raise response['error'].to_s if response['error']
        response['result']
      end

    end

  end
end