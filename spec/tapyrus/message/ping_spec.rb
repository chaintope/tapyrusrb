require 'spec_helper'

describe Tapyrus::Message::Ping do
  describe 'to_pkt' do
    subject { Tapyrus::Message::Ping.new(2_989_705_664).to_pkt }
    it 'should be generate' do
      expect(subject.bth).to eq('0b11090770696e670000000000000000080000006d539cecc04933b200000000')
    end
  end

  describe 'parse from payload' do
    subject { Tapyrus::Message::Ping.parse_from_payload('c04933b200000000'.htb) }
    it 'should be parsed' do
      expect(subject.nonce).to eq(2_989_705_664)
    end
  end
end
