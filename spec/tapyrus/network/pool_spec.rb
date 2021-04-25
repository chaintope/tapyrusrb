require 'spec_helper'

describe Tapyrus::Network::Pool do
  let(:chain) { create_test_chain }
  let(:pool) { Tapyrus::Network::Pool.new(node_mock, chain, configuration) }
  let(:node_mock) { double('node mock') }
  let(:configuration) { Tapyrus::Node::Configuration.new }
  let(:peer1) { Tapyrus::Network::Peer.new('192.168.0.1', 18_333, pool, configuration) }
  let(:peer2) { Tapyrus::Network::Peer.new('192.168.0.2', 18_333, pool, configuration) }
  let(:peer3) { Tapyrus::Network::Peer.new('192.168.0.3', 18_333, pool, configuration) }

  before do
    threads = []
    allow(node_mock).to receive(:wallet).and_return(nil)
    [peer1, peer2, peer3].each do |peer|
      allow(peer).to receive(:start_block_header_download) { sleep(1) }
      threads << Thread.start(peer) { |p| pool.handle_new_peer(peer) }
    end
    threads.each(&:join)
  end

  after { chain.db.close }

  describe '#allocate_peer_id' do
    subject { pool }

    it 'should allocate peer id' do
      expect(subject.peers.size).to eq(3)
      expect(subject.peers[0].id).to eq(0)
      expect(subject.peers[1].id).to eq(1)
      expect(subject.peers[2].id).to eq(2)
    end

    context 'when allocate again after disconnect' do
      subject do
        pool.started = true
        allow(pool).to receive(:connect).and_return(nil)

        # delete second peer and register again.
        peer = pool.peers[1]
        pool.handle_close_peer(peer)
        pool.handle_new_peer(peer)
        pool
      end
      it 'should allocate peer id' do
        expect(subject.peers.size).to eq(3)
        expect(subject.peers[0].id).to eq(0)
        expect(subject.peers[1].id).to eq(2)
        expect(subject.peers[2].id).to eq(1)
      end
    end
  end

  describe '#handle_new_peer' do
    subject { pool }

    it 'primary peer is unique' do
      expect(subject.peers.select(&:primary?).size).to eq 1
    end
  end

  describe '#handle_close_peer' do
    subject do
      pool.started = true
      allow(pool).to receive(:connect).and_return(nil)
      pool.handle_close_peer(peer2)
      pool
    end

    it { expect { subject }.to change(pool.peers, :size).from(3).to(2) }
    it { expect(subject.peers.map(&:host)).to match_array ['192.168.0.1', '192.168.0.3'] }
  end
end
