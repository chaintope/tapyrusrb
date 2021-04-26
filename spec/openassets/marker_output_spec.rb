require 'spec_helper'
include Tapyrus::Opcodes

describe OpenAssets::MarkerOutput do
  describe '#open_assets_marker?' do
    context 'valid' do
      it 'should be true' do
        script =
          Tapyrus::Script.new << OP_RETURN << '4f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71'
        expect(Tapyrus::TxOut.new(script_pubkey: script).open_assets_marker?).to be true
      end
    end

    context 'invalid' do
      it 'should be false' do
        expect(Tapyrus::TxOut.new(script_pubkey: Tapyrus::Script.new).open_assets_marker?).to be false

        # p2pkh
        script = Tapyrus::Script.parse_from_payload('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb)
        expect(Tapyrus::TxOut.new(script_pubkey: script).open_assets_marker?).to be false

        # invalid marker
        script =
          Tapyrus::Script.new << OP_RETURN << '4f4201000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71'
        expect(Tapyrus::TxOut.new(script_pubkey: script).open_assets_marker?).to be false

        # invalid version
        script =
          Tapyrus::Script.new << OP_RETURN << '4f4100000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71'
        expect(Tapyrus::TxOut.new(script_pubkey: script).open_assets_marker?).to be false
        script =
          Tapyrus::Script.new << OP_RETURN << '4f4102000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71'
        expect(Tapyrus::TxOut.new(script_pubkey: script).open_assets_marker?).to be false

        # can not parse varint
        script = Tapyrus::Script.new << OP_RETURN << '4f410100ff'
        expect(Tapyrus::TxOut.new(script_pubkey: script).open_assets_marker?).to be false

        # can not decode leb128 data(invalid format)
        script = Tapyrus::Script.new << OP_RETURN << '4f410100018f8f'
        expect(Tapyrus::TxOut.new(script_pubkey: script).open_assets_marker?).to be false

        # can not decode leb128 data(EOFError)
        script = Tapyrus::Script.new << OP_RETURN << '4f410100028f7f'
        expect(Tapyrus::TxOut.new(script_pubkey: script).open_assets_marker?).to be false

        # no metadata length
        script = Tapyrus::Script.new << OP_RETURN << '4f410100018f7f'
        expect(Tapyrus::TxOut.new(script_pubkey: script).open_assets_marker?).to be false

        # invalid metadata length
        script =
          Tapyrus::Script.new << OP_RETURN << '4f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d' # short
        expect(Tapyrus::TxOut.new(script_pubkey: script).open_assets_marker?).to be false
      end
    end
  end
end
