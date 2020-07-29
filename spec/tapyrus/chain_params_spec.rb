require 'spec_helper'

describe Tapyrus::ChainParams do

  describe 'load params' do

    context 'prod' do
      subject{Tapyrus::ChainParams.prod}
      it do
        expect(subject.address_version).to eq('00')
        expect(subject.prod?).to be true
        expect(subject.dev?).to be false
        expect(subject.dust_relay_fee).to eq(Tapyrus::DUST_RELAY_TX_FEE)
      end
    end

    context 'dev' do
      subject{Tapyrus::ChainParams.dev}
      it do
        expect(subject.address_version).to eq('6f')
        expect(subject.prod?).to be false
        expect(subject.dev?).to be true
        expect(subject.dust_relay_fee).to eq(Tapyrus::DUST_RELAY_TX_FEE)
      end
    end

  end

end