require 'spec_helper'

describe Tapyrus::Message::Reject do
  describe 'parse from payload' do
    subject do
      Tapyrus::Message::Reject.parse_from_payload(
        '0274781008636f696e62617365b593848d99f41a45e9d29054993139f0582025bb45191986bc0d81327fc4ed4e'.htb
      )
    end
    it 'should be parsed' do
      expect(subject.message).to eq('tx')
      expect(subject.code).to eq(0x10)
      expect(subject.reason).to eq('coinbase')
      expect(subject.extra).to eq('b593848d99f41a45e9d29054993139f0582025bb45191986bc0d81327fc4ed4e')
      expect(subject.to_payload).to eq(
        '0274781008636f696e62617365b593848d99f41a45e9d29054993139f0582025bb45191986bc0d81327fc4ed4e'.htb
      )
    end
  end

  describe 'to_pkt' do
    subject do
      Tapyrus::Message::Reject.new(
        'tx',
        Tapyrus::Message::Reject::CODE_INVALID,
        'coinbase',
        'b593848d99f41a45e9d29054993139f0582025bb45191986bc0d81327fc4ed4e'
      ).to_pkt
    end
    it 'should be generate' do
      expect(subject).to eq(
        '0b11090772656a6563740000000000002d0000005b2e22a70274781008636f696e62617365b593848d99f41a45e9d29054993139f0582025bb45191986bc0d81327fc4ed4e'
          .htb
      )
    end
  end
end
