require 'iniparse'

module Tapyrus
  module Node
    class Configuration

      attr_reader :conf

      def initialize(opts = {})
        # TODO apply configuration file.
        opts[:network] = :prod unless opts[:network]
        opts[:relay] = false unless opts[:relay]
        Tapyrus.chain_params = opts[:network]

        begin
          ini_file = IniParse.parse(File.read("#{Tapyrus.base_dir}/tapyrusrb.conf"))
          @conf = Hash[ ini_file.to_h['__anonymous__'].map{|k,v| [k.to_sym, v] } ]
        rescue => e
          @conf = {}
        end
        @conf.merge!(opts)
      end

      def host
        'localhost'
      end

      def port
        Tapyrus.chain_params.default_port - 1
      end

      def server_url
        "http://#{host}:#{port}"
      end

    end
  end
end
