require 'eventmachine'

module Tapyrus
  module Network

    autoload :MessageHandler, 'tapyrus/network/message_handler'
    autoload :Connection, 'tapyrus/network/connection'
    autoload :Pool, 'tapyrus/network/pool'
    autoload :Peer, 'tapyrus/network/peer'
    autoload :PeerDiscovery, 'tapyrus/network/peer_discovery'

  end
end
