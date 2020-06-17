require 'spec_helper'

describe Tapyrus::Network::Peer do

  class ConnectionMock
    attr_accessor :version, :sendheaders, :fee_rate
  end

  let(:chain) { create_test_chain }
  subject {
    chain_mock = double('chain mock')
    node_mock = double('node mock')
    configuration = Tapyrus::Node::Configuration.new(network: :dev)
    peer = Tapyrus::Network::Peer.new('210.196.254.100', 18333,
                                      Tapyrus::Network::Pool.new(node_mock, chain, configuration), configuration)
    peer.conn = ConnectionMock.new
    allow(peer).to receive(:chain).and_return(chain_mock)
    peer
  }
  after { chain.db.close }

  describe '#to_network_addr' do
    before {
      opts = {version:70015, services: 13, timestamp: 1507879363, local_addr: "0.0.0.0:0", remote_addr: "94.130.106.254:63446", nonce: 1561841459448609851, user_agent: "/Satoshi:0.14.2/", start_height: 1210117, relay: true}
      subject.conn.version = Tapyrus::Message::Version.new(opts)
    }
    it 'should be generate' do
      network_addr = subject.to_network_addr
      expect(network_addr.ip).to eq('210.196.254.100')
      expect(network_addr.port).to eq(18333)
      expect(network_addr.services).to eq(13)
      expect(network_addr.time).to eq(1507879363)
    end
  end

  describe '#handle_headers' do
    context 'IBD finished' do
      it 'should not send next getheaders' do
        expect(subject).not_to receive(:start_block_header_download)
        subject.handle_headers(Tapyrus::Message::Headers.new)
      end
    end
    it 'should call update with :header' do
      listener = double('listener')
      expect(listener).to receive(:update).with(:header, {hash:-1, height: -1})
      subject.pool.add_observer(listener)
      subject.handle_headers(Tapyrus::Message::Headers.new)

      subject.pool.delete_observer(listener)
      expect(listener).not_to receive(:update)
      subject.handle_headers(Tapyrus::Message::Headers.new)
    end
  end

  describe '#handle_block_inv' do
    it 'should send getdadta message' do
      hash = '00000000e0f952393cbb1874aa4ee18e81eaa057292a22e822eb9c80eed37dc8'
      inventory = Tapyrus::Message::Inventory.new( 3, hash)
      expect(subject.conn).not_to receive(:send_message).with(
          custom_object(Tapyrus::Message::GetData, inventories: [inventory]))
      subject.handle_block_inv([hash])
    end
  end

  describe '#handler_tx' do
    it 'should call update with :tx' do
      listener = double('listener')
      payload = "0100000001d58708dc89a5649c41985d2a2c9b83b641f7955b37454e177813c2262189b342010000006a47304402200958e5ef78bf22fd6335a4335cfe4bf2e5199cab79e2174a272a9f768a0eb36c02204a602e72d3a158e9e9217f690d7837e3f1cdc8e5f2ad0fcfbd230a351889eb5f0121033d5c2875c9bd116875a71a5db64cffcb13396b163d039b1d9327824891804334ffffffff02d2020000000000001976a914e7c1345fc8f87c68170b3aa798a956c2fe6a9eff88ac2672ea04000000001976a914990ef60d63b5b5964a1c2282061af45123e93fcb88ac00000000".htb
      tx = Tapyrus::Message::Tx.new(Tapyrus::Tx.parse_from_payload(payload))
      expect(listener).to receive(:update).with(:tx, tx)
      subject.pool.add_observer(listener)
      subject.handle_tx(tx)

      subject.pool.delete_observer(listener)
      expect(listener).not_to receive(:update)
      subject.handle_tx(tx)
    end
  end

  describe '#handler_merkle_block' do
    it 'should call update with :merkleblock' do
      listener = double('listener')
      payload = "0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b852907000000043612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b6541ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d06820d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf011d".htb
      merkle_block = Tapyrus::Message::MerkleBlock.parse_from_payload(payload)
      expect(listener).to receive(:update).with(:merkleblock, merkle_block)
      subject.pool.add_observer(listener)
      subject.handle_merkle_block(merkle_block)

      subject.pool.delete_observer(listener)
      expect(listener).not_to receive(:update)
      subject.handle_merkle_block(merkle_block)
    end
  end
end
