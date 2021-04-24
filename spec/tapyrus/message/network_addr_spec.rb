require 'spec_helper'

describe Tapyrus::Message::NetworkAddr do
  describe '#parse_from_payload' do
    subject do
      Tapyrus::Message::NetworkAddr.parse_from_payload('010000000000000000000000000000000000ffffc61b6409208d'.htb)
    end
    it 'should be parsed' do
      expect(subject.ip).to eq('198.27.100.9')
      expect(subject.port).to eq(8333)
      expect(subject.services).to eq(1)
      expect(subject.to_payload(true).bth).to eq('010000000000000000000000000000000000ffffc61b6409208d')
    end
  end

  describe '#to_payload' do
    subject do
      p = Tapyrus::Message::NetworkAddr.new(port: 18_333).to_payload(true)
      Tapyrus::Message::NetworkAddr.parse_from_payload(p)
    end
    it 'should be generate payload' do
      expect(subject.port).to eq(18_333)
      expect(subject.ip).to eq('127.0.0.1')
      expect(subject.services).to eq(Tapyrus::Message::DEFAULT_SERVICE_FLAGS)
    end
  end
end
