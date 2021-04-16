require 'spec_helper'

describe 'Tapyrus::TxBuilder' do
  let(:txb) { Tapyrus::TxBuilder.new.fee(1_000) }
  let(:p2pkh) { Tapyrus::Script.parse_from_payload('76a91492b7cc6e97407258428c23e1c936753ce41bbfbf88ac'.htb) }
  let(:change_script_pubkey) { Tapyrus::Script.parse_from_payload('76a914078eb33618f15d0a1ce400f91074485d37dd987a88ac'.htb) }

  let(:utxo1) do
    {
      script_pubkey: p2pkh,
      txid: 'e1fb3255ead43dccd3ae0ac2c4f81b32260ca52749936a739669918bbb895411',
      index: 0,
      value: 3_000
    }
  end

  let(:address) { 'n4jKJN5UMLsAejL1M5CTzQ8npeWoLBLCAH' }

  describe '#add_utxo' do
    subject(:tx) { txb.add_utxo(utxo1).build }

    it { expect(tx.inputs.size).to eq 1 }
    it { expect(tx.inputs[0].out_point).to eq Tapyrus::OutPoint.from_txid('e1fb3255ead43dccd3ae0ac2c4f81b32260ca52749936a739669918bbb895411', 0) }
  end

  describe '#reissuable' do
    subject(:tx) do
      txb
        .add_utxo(utxo1)
        .reissuable(utxo1[:script_pubkey], address, 10_000)
        .change_script_pubkey(change_script_pubkey)
        .build
    end

    it { expect(tx.outputs.size).to eq 2 }
    # token output
    it { expect(tx.outputs[0].value).to eq  10_000 }
    it { expect(tx.outputs[0].script_pubkey.to_hex).to eq '21c1058f891e11dd6e67f8ea54f9bc80b7268313319572033d48218af91c5355c4f9bc76a914fea16b404e5c76d17e690ec08000eb55952c777988ac' }
    # change output
    it { expect(tx.outputs[1].value).to eq  2_000 }
    it { expect(tx.outputs[1].script_pubkey).to eq change_script_pubkey }
  end

  describe '#non_reissuable' do
    subject(:tx) do
      out_point = Tapyrus::OutPoint.from_txid(utxo1[:txid], utxo1[:index])
      txb
        .add_utxo(utxo1)
        .non_reissuable(out_point, address, 10_000)
        .build
    end

    it { expect(tx.outputs.size).to eq 1 }
    # token output
    it { expect(tx.outputs[0].value).to eq  10_000 }
    it { expect(tx.outputs[0].script_pubkey.to_hex).to eq '21c2beb3290e67a30ce8cb42b553d20d4adf2493285c88d8adcb8289bd27f575cd75bc76a914fea16b404e5c76d17e690ec08000eb55952c777988ac' }
  end

  describe '#nft' do
    subject(:tx) do
      out_point = Tapyrus::OutPoint.from_txid(utxo1[:txid], utxo1[:index])
      txb
        .add_utxo(utxo1)
        .nft(out_point, address)
        .build
    end

    it { expect(tx.outputs.size).to eq 1 }
    # token output
    it { expect(tx.outputs[0].value).to eq  1 }
    it { expect(tx.outputs[0].script_pubkey.to_hex).to eq '21c3beb3290e67a30ce8cb42b553d20d4adf2493285c88d8adcb8289bd27f575cd75bc76a914fea16b404e5c76d17e690ec08000eb55952c777988ac' }
  end

  describe '#pay' do
    context 'send tpc' do
      subject(:tx) do
        txb
          .add_utxo(utxo1)
          .change_script_pubkey(change_script_pubkey)
          .pay(address, 1_000)
          .build
      end

      it { expect(tx.inputs.size).to eq 1 }
      it { expect(tx.outputs.size).to eq 2 }
      # tpc output
      it { expect(tx.outputs[0].value).to eq  1_000 }
      it { expect(tx.outputs[0].script_pubkey.to_hex).to eq '76a914fea16b404e5c76d17e690ec08000eb55952c777988ac' }
      # change output
      it { expect(tx.outputs[1].value).to eq  1_000 }
      it { expect(tx.outputs[1].script_pubkey.to_hex).to eq '76a914078eb33618f15d0a1ce400f91074485d37dd987a88ac' }
    end

    context 'send colored coin' do
      subject(:tx) do
        txb
          .add_utxo(utxo1)
          .add_utxo(utxo2)
          .change_script_pubkey(change_script_pubkey)
          .pay(address, 1_000, color_id)
          .build
      end

      let(:out_point) { Tapyrus::OutPoint.from_txid(utxo1[:txid], utxo1[:index]) }
      let(:color_id) { Tapyrus::Color::ColorIdentifier.nft(out_point) }
      let(:utxo2) do
        {
          script_pubkey: Tapyrus::Script.parse_from_payload('76a9141654c4fcb23c1b50fa0270249eb6120a133cd32e88ac'.htb).add_color(color_id),
          color_id: color_id,
          txid: 'e1fb3255ead43dccd3ae0ac2c4f81b32260ca52749936a739669918bbb895411',
          index: 0,
          value: 3_000
        }
      end

      it { expect(tx.inputs.size).to eq 2 }
      it { expect(tx.outputs.size).to eq 3 }
      # token output
      it { expect(tx.outputs[0].value).to eq  1_000 }
      it { expect(tx.outputs[0].script_pubkey.to_hex).to eq '21c3beb3290e67a30ce8cb42b553d20d4adf2493285c88d8adcb8289bd27f575cd75bc76a914fea16b404e5c76d17e690ec08000eb55952c777988ac' }
      # change output
      it { expect(tx.outputs[1].value).to eq  2_000 }
      it { expect(tx.outputs[1].script_pubkey.to_hex).to eq '76a914078eb33618f15d0a1ce400f91074485d37dd987a88ac' }
      # token change output
      it { expect(tx.outputs[2].value).to eq  2_000 }
      it { expect(tx.outputs[2].script_pubkey.to_hex).to eq '21c3beb3290e67a30ce8cb42b553d20d4adf2493285c88d8adcb8289bd27f575cd75bc76a914078eb33618f15d0a1ce400f91074485d37dd987a88ac' }
    end
  end

  describe '#data' do
    subject(:tx) { txb.data(content).build }

    context 'data is hex' do
      let(:content) { "0001" }

      it { expect(tx.outputs.size).to eq 1 }
      it { expect(tx.outputs[0].value).to eq  0 }
      it { expect(tx.outputs[0].script_pubkey.to_hex).to eq  '6a020001' }
    end

    context 'data has multiple contents' do
      subject(:tx) { txb.data("0001", "0002", "03").build }

      it { expect(tx.outputs.size).to eq 1 }
      it { expect(tx.outputs[0].value).to eq  0 }
      it { expect(tx.outputs[0].script_pubkey.to_hex).to eq  '6a050001000203' }
    end
  end

  describe '#change_script_pubkey' do
    context 'if cp2pkh' do
      subject { txb.change_script_pubkey(script) }

      let(:script) { Tapyrus::Script.parse_from_payload('21c3beb3290e67a30ce8cb42b553d20d4adf2493285c88d8adcb8289bd27f575cd75bc76a914fea16b404e5c76d17e690ec08000eb55952c777988ac'.htb) }

      it { expect { subject }.to raise_error(ArgumentError) }
    end
  end

  describe '#build' do
    context 'issue tokens, transfer tokens and push data' do
      subject(:tx) do
        txb
          .add_utxo(utxo1)
          .add_utxo(utxo2)
          .reissuable(utxo1[:script_pubkey], address, 10_000)
          .nft(Tapyrus::OutPoint.from_txid(utxo1[:txid], utxo1[:index]), address)
          .pay(address, 1_000, color_id)
          .data("01")
          .build
      end

      let(:out_point) { Tapyrus::OutPoint.from_txid("0000000000000000000000000000000000000000000000000000000000000000", 0) }
      let(:color_id) { Tapyrus::Color::ColorIdentifier.nft(out_point) }
      let(:utxo2) do
        {
          script_pubkey: Tapyrus::Script.parse_from_payload('76a9141654c4fcb23c1b50fa0270249eb6120a133cd32e88ac'.htb).add_color(color_id),
          color_id: color_id,
          txid: 'e1fb3255ead43dccd3ae0ac2c4f81b32260ca52749936a739669918bbb895411',
          index: 0,
          value: 3_000
        }
      end

      it { expect(tx.outputs.size).to eq 4 }
      it { expect(tx.outputs[0].value).to eq 10_000 }
      it { expect(tx.outputs[0].script_pubkey.to_hex).to eq '21c1058f891e11dd6e67f8ea54f9bc80b7268313319572033d48218af91c5355c4f9bc76a914fea16b404e5c76d17e690ec08000eb55952c777988ac' }
      it { expect(tx.outputs[1].value).to eq 1 }
      it { expect(tx.outputs[1].script_pubkey.to_hex).to eq '21c3beb3290e67a30ce8cb42b553d20d4adf2493285c88d8adcb8289bd27f575cd75bc76a914fea16b404e5c76d17e690ec08000eb55952c777988ac' }
      it { expect(tx.outputs[2].value).to eq 1_000 }
      it { expect(tx.outputs[2].script_pubkey.to_hex).to eq '21c36db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0ebc76a914fea16b404e5c76d17e690ec08000eb55952c777988ac' }
      it { expect(tx.outputs[3].value).to eq 0 }
      it { expect(tx.outputs[3].script_pubkey.to_hex).to eq '6a0101' }
    end
  end
end
