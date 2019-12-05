require 'spec_helper'

describe Tapyrus::Block do

  subject {
    payload = load_block('0000000001be84d00475b5cf0148c3dfb9b7c2a770f788f22b0d96085b0f0e84').htb
    Tapyrus::Message::Block.parse_from_payload(payload).to_block
  }

  describe '#valid_merkle_root?' do
    context 'valid' do
      it 'should be true' do
        expect(subject.valid_merkle_root?).to be true
      end
    end

    context 'when block has coinbase tx only(genesis block)' do
      subject {
        payload = load_block('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f').htb
        Tapyrus::Message::Block.parse_from_payload(payload).to_block
      }
      it 'should be true' do
        expect(subject.valid_merkle_root?).to be true
      end
    end

    context 'invalid' do
      it 'should be false' do
        block = subject
        coinbase_tx = block.transactions[0]
        coinbase_tx.inputs[0].script_sig = (coinbase_tx.inputs[0].script_sig << '00')
        expect(subject.valid_merkle_root?).to be false
      end
    end
  end

  describe '#height' do
    context 'block version 2' do
      subject { # height is 21106. testnet first version 2 block.
        payload = load_block('0000000070b701a5b6a1b965f6a38e0472e70b2bb31b973e4638dec400877581').htb
        Tapyrus::Message::Block.parse_from_payload(payload).to_block
      }
      it 'return block height' do
        expect(subject.height).to eq(21106)
      end
    end

    context 'block versoin 1' do
      subject { # height is 21105. testnet last version 1 block.
        payload = load_block('000000009020a075cc7af813d46a1ef24eb2b0035e131937153146cc3711542a').htb
        Tapyrus::Message::Block.parse_from_payload(payload).to_block
      }
      it 'return nil' do
        expect(subject.height).to be nil
      end
    end
  end

end