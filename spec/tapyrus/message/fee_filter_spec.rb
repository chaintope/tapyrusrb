require 'spec_helper'

describe Tapyrus::Message::FeeFilter do
  describe 'to_pkt' do
    subject { Tapyrus::Message::FeeFilter.new(1_000).to_pkt }
    it 'generate pkt' do
      expect(subject).to eq('0b11090766656566696c74657200000008000000e80fd19fe803000000000000'.htb)
    end
  end

  describe 'parse from payload' do
    subject { Tapyrus::Message::FeeFilter.parse_from_payload('e803000000000000'.htb) }
    it 'should be parsed' do
      expect(subject.fee_rate).to eq(1_000)
    end
  end
end
