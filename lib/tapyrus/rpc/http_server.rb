require 'evma_httpserver'
require 'json'

module Tapyrus
  module RPC
    # Tapyrusrb RPC server.
    class HttpServer < EM::Connection
      include EM::HttpServer
      include RequestHandler

      attr_reader :node
      attr_accessor :logger

      def initialize(node)
        @node = node
        @logger = Tapyrus::Logger.create(:debug)
      end

      def post_init
        super
        logger.debug 'start http server.'
      end

      def self.run(node, port = 8332)
        EM.start_server('0.0.0.0', port, HttpServer, node)
      end

      # process http request.
      def process_http_request
        operation =
          proc do
            command, args = parse_json_params
            logger.debug("process http request. command = #{command}")
            begin
              send(command, *args).to_json
            rescue Exception => e
              e
            end
          end
        callback =
          proc do |result|
            response = EM::DelegatedHttpResponse.new(self)
            if result.is_a?(Exception)
              response.status = 500
              response.content = result.message
            else
              response.status = 200
              response.content = result
            end
            response.content_type 'application/json'
            response.send_response
          end
        EM.defer(operation, callback)
      end

      # parse request parameter.
      # @return [Array] the array of command and args
      def parse_json_params
        params = JSON.parse(@http_post_content)
        [params['method'], params['params']]
      end
    end
  end
end
