require 'spec_helper'
include Tapyrus::Opcodes

describe 'Tapyrus::Color::ColorIdentifier' do
  describe '#to_paylaod' do
    subject { color.to_payload.bth }

    let(:color) { Tapyrus::Color::ColorIdentifier.nft(Tapyrus::OutPoint.new("01" * 32, 1)) }

    it { is_expected.to eq "03ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46" }
  end

  describe '.parse_from_payload' do
    subject { Tapyrus::Color::ColorIdentifier.parse_from_payload(payload.htb) }

    let(:payload) { "03ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46" }

    it { expect(subject.type).to eq Tapyrus::Color::TokenTypes::NFT }
    it { expect(subject.payload.bth).to eq "ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46" }
  end

  describe '#valid?' do
    subject { Tapyrus::Color::ColorIdentifier.parse_from_payload(payload.htb).valid? }

    let(:payload) { "03ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46" }

    it { is_expected.to be_truthy }

    context 'invalid type' do
      let(:payload) { "04ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46" }

      it { is_expected.to be_falsy }
    end

    context 'invalid payload' do
      let(:payload) { "03ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b4600" }

      it { is_expected.to be_falsy }
    end
  end
end

