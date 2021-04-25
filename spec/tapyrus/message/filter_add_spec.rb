require 'spec_helper'

describe Tapyrus::Message::FilterAdd do
  describe 'parse from payload' do
    subject do
      Tapyrus::Message::FilterAdd.parse_from_payload(
        '20fdacf9b3eb077412e7a968d2e4f11b9a9dee312d666187ed77ee7d26af16cb0b'.htb
      )
    end
    it 'should be parsed' do
      expect(subject.element).to eq('fdacf9b3eb077412e7a968d2e4f11b9a9dee312d666187ed77ee7d26af16cb0b')
    end
  end

  describe 'to_pkt' do
    subject do
      Tapyrus::Message::FilterAdd.new('fdacf9b3eb077412e7a968d2e4f11b9a9dee312d666187ed77ee7d26af16cb0b').to_pkt
    end
    it 'should be generate' do
      expect(subject).to eq(
        '0b11090766696c7465726164640000002100000072851a0a20fdacf9b3eb077412e7a968d2e4f11b9a9dee312d666187ed77ee7d26af16cb0b'
          .htb
      )
    end
  end
end
