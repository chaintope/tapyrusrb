require 'spec_helper'

describe Tapyrus::ChainParams do

  describe 'load params' do

    context 'prod' do
      subject{Tapyrus::ChainParams.prod}
      it do
        expect(subject.address_version).to eq('00')
        expect(subject.prod?).to be true
        expect(subject.dev?).to be false
        expect(subject.genesis_block.header.to_payload.bth).to eq('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c')
        expect(subject.genesis_block.header.block_hash).to eq('6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000')
        expect(subject.dust_relay_fee).to eq(Tapyrus::DUST_RELAY_TX_FEE)
      end
    end

    context 'dev' do
      subject{Tapyrus::ChainParams.dev}
      it do
        expect(subject.address_version).to eq('6f')
        expect(subject.prod?).to be false
        expect(subject.dev?).to be true
        expect(subject.genesis_block.header.to_payload.bth).to eq('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18')
        expect(subject.genesis_block.header.block_hash).to eq('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000')
        expect(subject.dust_relay_fee).to eq(Tapyrus::DUST_RELAY_TX_FEE)
      end
    end

  end

end