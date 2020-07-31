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
      payload = "01000000c0ea2fe2ef262bd0b4661677c2eea212f9cdcea12836950dc981479b1c855346a8a954d31f94c74584b9c015b76916e80baf80bfe8871048e57955b6eb6629565a39e01e190191aac81b640c0c68898e3e4036f1c72353da9133e4d30a68447af5aa235f00409bfc6803a40cd77d45379d58768e766beb564a29929259f816747ab8b667a49c548e89d37ed3fb86a1317cecf9dc92819766a26942fb33c02d60089cee5a757a0500000004b7b5d6976ce6bcd385c1f17253f94f48f7cae86aa760af92580293bd6ed9c3cf3b65b0931a566abc20eb0cdc55497ed24a8a7547df98a70cc2290e2fa8e1be6a10dd441ee8f7e3ca6739d56146e794c0fdb401b2764526f43aea79d4f116e466c220f471a5798cd345cf50e2d3f840edf16b3801d105cb3664f16dbe3531e176011b".htb
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
