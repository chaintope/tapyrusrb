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

describe 'Tapyrus::Color::ColoredOutput' do
  subject { Tapyrus::TxOut.new(value: 1, script_pubkey: script_pubkey) }

  let(:script_pubkey) { Tapyrus::Script.to_cp2sh(color, '7620a79e8657d066cff10e21228bf983cf546ac6') }

  context 'reissuable' do
    let(:color) { Tapyrus::Color::ColorIdentifier.reissuable(Tapyrus::Script.new) }

    it { expect(subject.colored?).to be_truthy }
    it { expect(subject.reissuable?).to be_truthy }
    it { expect(subject.non_reissuable?).to be_falsy }
    it { expect(subject.nft?).to be_falsy }
  end

  context 'non_reissuable' do
    let(:color) { Tapyrus::Color::ColorIdentifier.non_reissuable(Tapyrus::OutPoint.new("01" * 32, 1)) }

    it { expect(subject.colored?).to be_truthy }
    it { expect(subject.reissuable?).to be_falsy }
    it { expect(subject.non_reissuable?).to be_truthy }
    it { expect(subject.nft?).to be_falsy }
  end

  context 'nft' do
    let(:color) { Tapyrus::Color::ColorIdentifier.nft(Tapyrus::OutPoint.new("01" * 32, 1)) }

    it { expect(subject.colored?).to be_truthy }
    it { expect(subject.reissuable?).to be_falsy }
    it { expect(subject.non_reissuable?).to be_falsy }
    it { expect(subject.nft?).to be_truthy }
  end

  context 'none' do
    let(:script_pubkey) { Tapyrus::Script.to_p2sh('7620a79e8657d066cff10e21228bf983cf546ac6') }

    it { expect(subject.colored?).to be_falsy }
    it { expect(subject.reissuable?).to be_falsy }
    it { expect(subject.non_reissuable?).to be_falsy }
    it { expect(subject.nft?).to be_falsy }
  end
end