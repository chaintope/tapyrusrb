require 'spec_helper'

describe Tapyrus::Message::Inv do
  describe 'parse' do
    subject do
      Tapyrus::Message::Inv.parse_from_payload(
        '0201000000099c332dc6d71c968a3f47d6ffd43436062c72dad477b515ce2e108e1e6f109601000000e6cf87650476e8677543885e388761f09c732e66d479501f9d9c19cdb2b50e05'
          .htb
      )
    end
    it do
      expect(subject.inventories.length).to eq(2)
      expect(subject.inventories[0].hash).to eq('099c332dc6d71c968a3f47d6ffd43436062c72dad477b515ce2e108e1e6f1096')
      expect(subject.inventories[0].identifier).to eq(1)
      expect(subject.inventories[1].hash).to eq('e6cf87650476e8677543885e388761f09c732e66d479501f9d9c19cdb2b50e05')
      expect(subject.inventories[1].identifier).to eq(1)
    end
  end

  describe 'to_pkt' do
    subject do
      inv = Tapyrus::Message::Inv.new
      inv.inventories <<
        Tapyrus::Message::Inventory.new(1, '099c332dc6d71c968a3f47d6ffd43436062c72dad477b515ce2e108e1e6f1096')
      inv.inventories <<
        Tapyrus::Message::Inventory.new(1, 'e6cf87650476e8677543885e388761f09c732e66d479501f9d9c19cdb2b50e05')
      inv.to_pkt
    end
    it do
      expect(subject.bth).to eq(
        '0b110907696e760000000000000000004900000075a56c590201000000099c332dc6d71c968a3f47d6ffd43436062c72dad477b515ce2e108e1e6f109601000000e6cf87650476e8677543885e388761f09c732e66d479501f9d9c19cdb2b50e05'
      )
    end
  end
end
