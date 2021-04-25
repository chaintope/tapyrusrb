require 'spec_helper'

describe Tapyrus::Message::NotFound do
  describe 'parse_from_payload' do
    subject do
      Tapyrus::Message::NotFound.parse_from_payload(
        '0101000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab'.htb
      )
    end
    it do
      expect(subject.inventories[0].identifier).to eq(1)
      expect(subject.inventories[0].hash).to eq('cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab')
    end
  end

  describe 'to_pkt' do
    subject do
      invs = [Tapyrus::Message::Inventory.new(1, 'cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab')]
      Tapyrus::Message::NotFound.new(invs).to_pkt
    end
    it do
      expect(subject).to eq(
        '0b1109076e6f74666f756e640000000025000000e969f2210101000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab'
          .htb
      )
    end
  end
end
