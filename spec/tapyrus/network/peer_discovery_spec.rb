require 'spec_helper'

describe Tapyrus::Network::PeerDiscovery do
  describe '#peers' do
    let(:dns_seeds) { [] }
    let(:configuration) { Tapyrus::Node::Configuration.new }
    subject do
      peer_discovery = Tapyrus::Network::PeerDiscovery.new(configuration)
      allow(peer_discovery).to receive(:dns_seeds).and_return(dns_seeds)
      peer_discovery
    end
    context 'dns_seeds is empty' do
      context 'connect nodes is empty' do
        it 'should be empty' do
          expect(subject.peers).to eq []
        end
      end
      context 'one connect node exists' do
        let(:configuration) { Tapyrus::Node::Configuration.new(connect: '123.123.123.123') }
        it 'should return one node' do
          expect(subject.peers).to eq ['123.123.123.123']
        end
      end
      context 'multiple connect nodes exist' do
        let(:configuration) do
          Tapyrus::Node::Configuration.new(connect: ['123.123.123.123', '123.123.123.124', '123.123.123.125'])
        end
        it 'should return multiple node' do
          expect(subject.peers).to eq ['123.123.123.123', '123.123.123.124', '123.123.123.125']
        end
      end
      context 'duplidate nodes exist' do
        let(:configuration) { Tapyrus::Node::Configuration.new(connect: ['123.123.123.123', '123.123.123.123']) }
        it 'should return only unique node' do
          expect(subject.peers).to eq ['123.123.123.123']
        end
      end
    end
  end
end
