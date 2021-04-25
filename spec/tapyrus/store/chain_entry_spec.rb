require 'spec_helper'

describe Tapyrus::Store::ChainEntry do
  describe '#to_payload' do
    it 'should be parsed' do
      header =
        Tapyrus::BlockHeader.parse_from_payload(
          '01000000f62d08535b0df780676256ad4f6dbb7ac5c9b8e86150e26425330b853d8796a2abd52ce318e5c5d6c3aeb3aea278ebf7fc8b8fe8cb5535543a76d4fd903589742ecee1ba9a3d25123dada6041c6bafff1423b3dd4f561816adcf245736004698f1f40f5f00403b9b731cb77c87078c0bdc8f1f2dc91406b42f082f9d8f095be16b5b0dd68f549b5ad1dda9e01ff87d022404b1f80dd40d40e0d3accc69fb9180fd8db30b5064'
            .htb
        )
      entry1 = Tapyrus::Store::ChainEntry.new(header, 1_209_901)
      expect(entry1.to_hex).to eq(
        '032d761201000000f62d08535b0df780676256ad4f6dbb7ac5c9b8e86150e26425330b853d8796a2abd52ce318e5c5d6c3aeb3aea278ebf7fc8b8fe8cb5535543a76d4fd903589742ecee1ba9a3d25123dada6041c6bafff1423b3dd4f561816adcf245736004698f1f40f5f00403b9b731cb77c87078c0bdc8f1f2dc91406b42f082f9d8f095be16b5b0dd68f549b5ad1dda9e01ff87d022404b1f80dd40d40e0d3accc69fb9180fd8db30b5064'
      )

      header2 =
        Tapyrus::BlockHeader.parse_from_payload(
          '01000000f62d08535b0df780676256ad4f6dbb7ac5c9b8e86150e26425330b853d8796a2abd52ce318e5c5d6c3aeb3aea278ebf7fc8b8fe8cb5535543a76d4fd903589742ecee1ba9a3d25123dada6041c6bafff1423b3dd4f561816adcf245736004698f1f40f5f00403b9b731cb77c87078c0bdc8f1f2dc91406b42f082f9d8f095be16b5b0dd68f549b5ad1dda9e01ff87d022404b1f80dd40d40e0d3accc69fb9180fd8db30b5064'
            .htb
        )
      entry2 = Tapyrus::Store::ChainEntry.new(header2, 1)
      expect(entry2.to_hex).to eq(
        '010101000000f62d08535b0df780676256ad4f6dbb7ac5c9b8e86150e26425330b853d8796a2abd52ce318e5c5d6c3aeb3aea278ebf7fc8b8fe8cb5535543a76d4fd903589742ecee1ba9a3d25123dada6041c6bafff1423b3dd4f561816adcf245736004698f1f40f5f00403b9b731cb77c87078c0bdc8f1f2dc91406b42f082f9d8f095be16b5b0dd68f549b5ad1dda9e01ff87d022404b1f80dd40d40e0d3accc69fb9180fd8db30b5064'
      )
    end
  end

  describe '#parse_from_payload' do
    it 'should be parsed' do
      entry1 =
        Tapyrus::Store::ChainEntry.parse_from_payload(
          '032d761201000000f62d08535b0df780676256ad4f6dbb7ac5c9b8e86150e26425330b853d8796a2abd52ce318e5c5d6c3aeb3aea278ebf7fc8b8fe8cb5535543a76d4fd903589742ecee1ba9a3d25123dada6041c6bafff1423b3dd4f561816adcf245736004698f1f40f5f00403b9b731cb77c87078c0bdc8f1f2dc91406b42f082f9d8f095be16b5b0dd68f549b5ad1dda9e01ff87d022404b1f80dd40d40e0d3accc69fb9180fd8db30b5064'
            .htb
        )
      expect(entry1.height).to eq(1_209_901)
      expect(entry1.header.to_hex).to eq(
        '01000000f62d08535b0df780676256ad4f6dbb7ac5c9b8e86150e26425330b853d8796a2abd52ce318e5c5d6c3aeb3aea278ebf7fc8b8fe8cb5535543a76d4fd903589742ecee1ba9a3d25123dada6041c6bafff1423b3dd4f561816adcf245736004698f1f40f5f00403b9b731cb77c87078c0bdc8f1f2dc91406b42f082f9d8f095be16b5b0dd68f549b5ad1dda9e01ff87d022404b1f80dd40d40e0d3accc69fb9180fd8db30b5064'
      )

      entry2 =
        Tapyrus::Store::ChainEntry.parse_from_payload(
          '010101000000f62d08535b0df780676256ad4f6dbb7ac5c9b8e86150e26425330b853d8796a2abd52ce318e5c5d6c3aeb3aea278ebf7fc8b8fe8cb5535543a76d4fd903589742ecee1ba9a3d25123dada6041c6bafff1423b3dd4f561816adcf245736004698f1f40f5f00403b9b731cb77c87078c0bdc8f1f2dc91406b42f082f9d8f095be16b5b0dd68f549b5ad1dda9e01ff87d022404b1f80dd40d40e0d3accc69fb9180fd8db30b5064'
            .htb
        )
      expect(entry2.height).to eq(1)
      expect(entry2.header.to_hex).to eq(
        '01000000f62d08535b0df780676256ad4f6dbb7ac5c9b8e86150e26425330b853d8796a2abd52ce318e5c5d6c3aeb3aea278ebf7fc8b8fe8cb5535543a76d4fd903589742ecee1ba9a3d25123dada6041c6bafff1423b3dd4f561816adcf245736004698f1f40f5f00403b9b731cb77c87078c0bdc8f1f2dc91406b42f082f9d8f095be16b5b0dd68f549b5ad1dda9e01ff87d022404b1f80dd40d40e0d3accc69fb9180fd8db30b5064'
      )
    end
  end
end
