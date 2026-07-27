require "spec_helper"

RSpec.describe Tapyrus::PSTT do
  let(:keys) { 6.times.map { Tapyrus::Key.generate } }

  # Build a transaction which pays +outputs+, so that it can be referenced as PSTT_IN_UTXO.
  def funding_tx(*outputs)
    tx = Tapyrus::Tx.new
    tx.inputs << Tapyrus::TxIn.new(out_point: Tapyrus::OutPoint.from_txid(SecureRandom.hex(32), 0))
    outputs.each { |value, script| tx.outputs << Tapyrus::TxOut.new(value: value, script_pubkey: script) }
    tx
  end

  def p2pkh(key)
    Tapyrus::Script.to_p2pkh(key.hash160)
  end

  def pstt_input(tx, index)
    Tapyrus::PSTT::Input.new(out_point: Tapyrus::OutPoint.from_txid(tx.txid, index), utxo: tx)
  end

  def pstt_output(value, script)
    Tapyrus::PSTT::Output.new(amount: value, script_pubkey: script)
  end

  # The records of every map of +payload+, sorted so that two PSTTs which differ only in the
  # order of their records compare equal.
  def records_of(payload)
    buf = StringIO.new(payload)
    Tapyrus::PSTT.read_bytes(buf, Tapyrus::PSTT::MAGIC.bytesize)
    maps = []
    maps << Tapyrus::PSTT.parse_map(buf).map { |r| [r.type, r.keydata.bth, r.value.bth] }.sort until buf.eof?
    maps
  end

  describe "TIP-0174 test vectors" do
    describe "invalid.json" do
      fixture_file("tip0174/invalid.json").each do |vector|
        context "with #{vector["id"]}" do
          subject { Tapyrus::PSTT::Tx.from_base64(vector["pstt"]) }

          if vector["expected"]["stage"] == "parse"
            it "is rejected while parsing: #{vector["expected"]["reason"]}" do
              expect { subject }.to raise_error(Tapyrus::PSTT::Error)
            end
          else
            it "parses, but violates a role rule: #{vector["expected"]["reason"]}" do
              expect { subject }.not_to raise_error
            end
          end
        end
      end

      it "detects an unmatched PSTT_IN_UTXO" do
        pstt = Tapyrus::PSTT::Tx.from_base64(invalid_vector("utxo-txid-mismatch"))
        expect { pstt.sighash_for_input(0) }.to raise_error(
          Tapyrus::PSTT::Error,
          "The txid of PSTT_IN_UTXO does not match PSTT_IN_PREVIOUS_TXID."
        )
      end

      it "detects contradictory required locktimes" do
        pstt = Tapyrus::PSTT::Tx.from_base64(invalid_vector("contradictory-locktimes"))
        expect { pstt.locktime }.to raise_error(
          Tapyrus::PSTT::Error,
          "No locktime kind is acceptable to every input which requires a locktime."
        )
      end

      it "detects SIGHASH_SINGLE without a corresponding output" do
        pstt = Tapyrus::PSTT::Tx.from_base64(invalid_vector("single-without-corresponding-output"))
        index = pstt.inputs.index { |input| !input.partial_sigs.empty? }
        expect(index).to be >= pstt.outputs.size
        expect { pstt.sighash_for_input(index, sighash_type: Tapyrus::SIGHASH_TYPE[:single]) }.to raise_error(
          Tapyrus::PSTT::Error,
          "SIGHASH_SINGLE must not be used for an input which has no corresponding output."
        )
      end

      it "detects a redeem script which does not hash to the committed value" do
        pstt = Tapyrus::PSTT::Tx.from_base64(invalid_vector("redeem-script-hash-mismatch"))
        expect { pstt.sighash_for_input(0) }.to raise_error(
          Tapyrus::PSTT::Error,
          "PSTT_IN_REDEEM_SCRIPT does not hash to the value committed in the scriptPubKey."
        )
      end

      it "detects a map count which does not match the declared counts" do
        expect { Tapyrus::PSTT::Tx.from_base64(invalid_vector("count-mismatch")) }.to raise_error(
          Tapyrus::PSTT::Error,
          "The number of maps does not match PSTT_GLOBAL_INPUT_COUNT and PSTT_GLOBAL_OUTPUT_COUNT."
        )
      end

      it "detects a keytype which is not minimally encoded" do
        expect { Tapyrus::PSTT::Tx.from_base64(invalid_vector("non-minimal-keytype")) }.to raise_error(
          Tapyrus::PSTT::Error,
          "compact size is not minimally encoded."
        )
      end

      def invalid_vector(id)
        fixture_file("tip0174/invalid.json").find { |v| v["id"] == id }["pstt"]
      end
    end

    describe "valid.json" do
      fixture_file("tip0174/valid.json").each do |series|
        context "with #{series["id"]}" do
          let(:stages) { series["stages"].map { |stage| Tapyrus::PSTT::Tx.from_base64(stage["pstt"]) } }

          it "parses every stage and survives a round trip" do
            series["stages"].each_with_index do |stage, i|
              pstt = stages[i]
              # The records themselves are compared first: a field this implementation silently
              # dropped shows up here, with a readable difference.
              expect(records_of(pstt.to_payload)).to eq(records_of(stage["pstt"].unpack1("m0")))
              # The round trip is then byte-exact, because every map is re-emitted in the order
              # it was read. TIP-0174 prescribes no order, but reproducing the bytes lets a
              # caller hash, cache or diff a PSTT without normalizing it first.
              expect(pstt.to_payload).to eq(stage["pstt"].unpack1("m0"))
              expect(Tapyrus::PSTT::Tx.parse_from_payload(pstt.to_payload)).to eq(pstt)
              expect(Tapyrus::PSTT::Tx.from_base64(pstt.to_base64)).to eq(pstt)
              expect(pstt.identification_txid).to eq(stage["identification_txid"]) if stage["identification_txid"]
              # A stage which declares 0 asserts that every modifiable flag has been cleared.
              expect(pstt.tx_modifiable).to eq(stage["tx_modifiable"]) unless stage["tx_modifiable"].nil?
            end
          end

          it "extracts the final transaction" do
            tx = stages.last.extract_tx
            expect(tx.to_hex).to eq(series["extracted_tx"])
            expect(tx.txid).to eq(series["final_txid"])
          end

          it "computes the scriptCode, the signature hash and verifies the signatures" do
            signed = stages.select { |pstt| pstt.inputs.any? { |input| !input.partial_sigs.empty? } }.last
            expect(signed).not_to be_nil
            series["intermediates"].each do |intermediate|
              index = intermediate["input"]
              expect(signed.script_code(index).to_hex).to eq(intermediate["script_code"])
              sighash = signed.sighash_for_input(index, sighash_type: intermediate["sighash_type"])
              expect(sighash.bth).to eq(intermediate["sighash"])
              sig = signed.inputs[index].partial_sigs[intermediate["pubkey"]]
              expect(sig.bth).to eq(intermediate["signature"])
              expect(sig[-1].unpack1("C")).to eq(intermediate["sighash_type"])
              algo = sig.bytesize == 65 ? :schnorr : :ecdsa
              key = Tapyrus::Key.new(pubkey: intermediate["pubkey"])
              expect(key.verify(sig[0...-1], sighash, algo: algo)).to be true
            end
          end
        end
      end
    end
  end

  describe "container format" do
    # A PSTT which carries one P2PKH input and one output, for the payloads assembled by hand.
    def one_input_pstt
      Tapyrus::PSTT::Tx.new(
        inputs: [pstt_input(funding_tx([100_000, p2pkh(keys[0])]), 0)],
        outputs: [pstt_output(99_000, p2pkh(keys[1]))]
      )
    end

    # Replace the first occurrence of +from+ in +payload+ with +to+.
    def mangle(payload, from, to)
      index = payload.index(from)
      expect(index).not_to be_nil
      payload[0...index] + to + payload[(index + from.bytesize)..]
    end

    def parse_error_of(payload)
      Tapyrus::PSTT::Tx.parse_from_payload(payload)
      nil
    rescue Tapyrus::PSTT::Error => e
      e.message
    end

    it "begins with the pstt magic" do
      pstt = Tapyrus::PSTT::Tx.new
      expect(pstt.to_payload[0...5].bth).to eq("70737474ff")
    end

    it "rejects a payload which does not begin with the magic" do
      payload = Tapyrus::PSTT::Tx.new.to_payload
      payload[0...5] = "70736274ff".htb # the Bitcoin PSBT magic
      expect { Tapyrus::PSTT::Tx.parse_from_payload(payload) }.to raise_error(
        Tapyrus::PSTT::Error,
        /Invalid PSTT magic/
      )
    end

    it "rejects a compact size which is not minimally encoded" do
      # PSTT_GLOBAL_TX_FEATURES is <keylen=01> <keytype=02> <valuelen=04> <features>.
      payload = one_input_pstt.to_payload
      not_minimal = "compact size is not minimally encoded."
      expect(parse_error_of(mangle(payload, "\x01\x02\x04".b, "\xfd\x01\x00\x02\x04".b))).to eq(not_minimal)
      expect(parse_error_of(mangle(payload, "\x01\x02\x04".b, "\x01\x02\xfd\x04\x00".b))).to eq(not_minimal)
    end

    it "rejects a map separator which is not a single 0x00 byte" do
      # 0xfd 0x00 0x00 encodes the same 0, so a parser which only compared the value would read
      # it as the separator and accept two byte strings as the same PSTT.
      records = Tapyrus::PSTT::Tx.new.global_records
      payload = Tapyrus::PSTT::MAGIC + records.map(&:to_payload).join + "\xfd\x00\x00".b
      expect(parse_error_of(payload)).to eq("compact size is not minimally encoded.")
    end

    it "rejects a count which is not minimally encoded" do
      pstt = one_input_pstt
      records = pstt.global_records
      records.find { |r| r.type == Tapyrus::PSTT::GlobalTypes::INPUT_COUNT }.value = "\xfd\x01\x00".b
      payload =
        Tapyrus::PSTT::MAGIC + Tapyrus::PSTT.serialize_map(records) + pstt.inputs.map(&:to_payload).join +
          pstt.outputs.map(&:to_payload).join
      expect(parse_error_of(payload)).to eq("compact size is not minimally encoded.")
    end

    it "rejects a PSTT whose number of maps does not match the declared counts" do
      pstt = one_input_pstt
      records = pstt.global_records
      records.find { |r| r.type == Tapyrus::PSTT::GlobalTypes::INPUT_COUNT }.value = Tapyrus.pack_var_int(2)
      payload =
        Tapyrus::PSTT::MAGIC + Tapyrus::PSTT.serialize_map(records) + pstt.inputs.map(&:to_payload).join +
          pstt.outputs.map(&:to_payload).join
      expect(parse_error_of(payload)).to eq(
        "The number of maps does not match PSTT_GLOBAL_INPUT_COUNT and PSTT_GLOBAL_OUTPUT_COUNT."
      )
    end

    it "re-emits the records of a map in the order they were read" do
      pstt = one_input_pstt
      # An order this implementation would never generate on its own.
      order = pstt.global_records.reverse.map(&:key)
      payload =
        Tapyrus::PSTT::MAGIC + Tapyrus::PSTT.serialize_map(pstt.global_records, order) +
          pstt.inputs.map(&:to_payload).join + pstt.outputs.map(&:to_payload).join
      parsed = Tapyrus::PSTT::Tx.parse_from_payload(payload)
      expect(parsed.global_record_order).to eq(order)
      expect(parsed.to_payload).to eq(payload)
    end

    it "puts a record collected after parsing behind the records which were read" do
      parsed = Tapyrus::PSTT::Tx.parse_from_payload(one_input_pstt.to_payload)
      before = input_keys_of(parsed.to_payload)
      parsed.sign(0, keys[0])
      after = input_keys_of(parsed.to_payload)
      expect(after.first(before.size)).to eq(before)
      expect(after.last).to eq(Tapyrus.pack_var_int(Tapyrus::PSTT::InputTypes::PARTIAL_SIG) + keys[0].pubkey.htb)
    end

    # The complete keys of the first input map of +payload+, in the order they are emitted.
    def input_keys_of(payload)
      buf = StringIO.new(payload)
      Tapyrus::PSTT.read_bytes(buf, Tapyrus::PSTT::MAGIC.bytesize)
      Tapyrus::PSTT.parse_map(buf)
      Tapyrus::PSTT.parse_map(buf).map(&:key)
    end

    it "keeps unknown records through a round trip" do
      pstt = Tapyrus::PSTT::Tx.new
      pstt.unknowns[Tapyrus.pack_var_int(0x20)] = "future-field"
      pstt.inputs << pstt_input(funding_tx([1_000, p2pkh(keys[0])]), 0)
      pstt.inputs.first.unknowns[Tapyrus.pack_var_int(0x21) + "01".htb] = "future-input-field"
      pstt.outputs << pstt_output(900, p2pkh(keys[1]))
      pstt.outputs.first.unknowns[Tapyrus.pack_var_int(0x22)] = "future-output-field"
      parsed = Tapyrus::PSTT::Tx.parse_from_payload(pstt.to_payload)
      expect(parsed.unknowns[Tapyrus.pack_var_int(0x20)]).to eq("future-field")
      expect(parsed.inputs.first.unknowns.values).to eq(["future-input-field"])
      expect(parsed.outputs.first.unknowns.values).to eq(["future-output-field"])
    end

    it "rejects a version greater than 0, both when writing and when reading" do
      expect { Tapyrus::PSTT::Tx.new(version: 1).to_payload }.to raise_error(
        Tapyrus::PSTT::Error,
        "PSTT version 1 is not supported."
      )
      pstt = Tapyrus::PSTT::Tx.new
      records = pstt.global_records << Tapyrus::PSTT::KeyValue.new(0xfb, "".b, [1].pack("V"))
      payload = Tapyrus::PSTT::MAGIC + Tapyrus::PSTT.serialize_map(records)
      expect { Tapyrus::PSTT::Tx.parse_from_payload(payload) }.to raise_error(
        Tapyrus::PSTT::Error,
        "PSTT version 1 is not supported."
      )
    end

    it "rejects a reserved bit of PSTT_GLOBAL_TX_MODIFIABLE, both when writing and when reading" do
      expect { Tapyrus::PSTT::Tx.new(tx_modifiable: 0x08).to_payload }.to raise_error(
        Tapyrus::PSTT::Error,
        "The reserved bits of PSTT_GLOBAL_TX_MODIFIABLE must be 0."
      )
    end

    it "reports a malformed PSTT_IN_UTXO as a PSTT error" do
      pstt =
        Tapyrus::PSTT::Tx.new(
          inputs: [pstt_input(funding_tx([1_000, p2pkh(keys[0])]), 0)],
          outputs: [pstt_output(900, p2pkh(keys[1]))]
        )
      records = pstt.inputs.first.to_records
      records.find { |r| r.type == Tapyrus::PSTT::InputTypes::UTXO }.value = "deadbeef".htb
      payload =
        Tapyrus::PSTT::MAGIC + Tapyrus::PSTT.serialize_map(pstt.global_records) + Tapyrus::PSTT.serialize_map(records) +
          pstt.outputs.map(&:to_payload).join
      expect { Tapyrus::PSTT::Tx.parse_from_payload(payload) }.to raise_error(
        Tapyrus::PSTT::Error,
        /PSTT_IN_UTXO is malformed/
      )
    end

    it "reports a malformed PSTT_GLOBAL_XPUB as a PSTT error" do
      records = Tapyrus::PSTT::Tx.new.global_records
      records << Tapyrus::PSTT::KeyValue.new(0x01, "ff".htb * 78, "00".htb * 4)
      payload = Tapyrus::PSTT::MAGIC + Tapyrus::PSTT.serialize_map(records)
      expect { Tapyrus::PSTT::Tx.parse_from_payload(payload) }.to raise_error(
        Tapyrus::PSTT::Error,
        /PSTT_GLOBAL_XPUB is malformed/
      )
    end

    it "rejects an empty PSTT_IN_PARTIAL_SIG" do
      pstt =
        Tapyrus::PSTT::Tx.new(
          inputs: [pstt_input(funding_tx([1_000, p2pkh(keys[0])]), 0)],
          outputs: [pstt_output(900, p2pkh(keys[1]))]
        )
      pstt.inputs.first.partial_sigs[keys[0].pubkey] = "".b
      expect { Tapyrus::PSTT::Tx.parse_from_payload(pstt.to_payload) }.to raise_error(
        Tapyrus::PSTT::Error,
        /PSTT_IN_PARTIAL_SIG must carry a signature/
      )
    end

    it "does not let an empty PSTT_IN_PARTIAL_SIG break the sequence number rule" do
      pstt =
        Tapyrus::PSTT::Tx.new(
          inputs: [
            pstt_input(funding_tx([1_000, p2pkh(keys[0])]), 0),
            pstt_input(funding_tx([1_000, p2pkh(keys[1])]), 0)
          ],
          outputs: [pstt_output(1_900, p2pkh(keys[2]))]
        )
      pstt.inputs.last.partial_sigs[keys[1].pubkey] = "".b
      expect { pstt.set_sequence(0, 0xfffffffe) }.not_to raise_error
    end

    it "rejects an out-of-range PSTT_OUT_AMOUNT, both when writing and when reading" do
      pstt =
        Tapyrus::PSTT::Tx.new(
          inputs: [pstt_input(funding_tx([1_000, p2pkh(keys[0])]), 0)],
          outputs: [pstt_output(-1, p2pkh(keys[1]))]
        )
      expect { pstt.to_payload }.to raise_error(Tapyrus::PSTT::Error, /PSTT_OUT_AMOUNT must be between/)

      pstt.outputs.first.amount = 1
      records = pstt.outputs.first.to_records
      records.find { |r| r.type == Tapyrus::PSTT::OutputTypes::AMOUNT }.value = [-1].pack("q<")
      payload =
        Tapyrus::PSTT::MAGIC + Tapyrus::PSTT.serialize_map(pstt.global_records) + pstt.inputs.map(&:to_payload).join +
          Tapyrus::PSTT.serialize_map(records)
      expect { Tapyrus::PSTT::Tx.parse_from_payload(payload) }.to raise_error(
        Tapyrus::PSTT::Error,
        /PSTT_OUT_AMOUNT must be between/
      )
    end
  end

  describe "P2PKH workflow" do
    let(:prev_tx) { funding_tx([100_000, p2pkh(keys[0])]) }

    it "walks from creation to extraction with an ECDSA signature" do
      pstt =
        Tapyrus::PSTT::Tx.new(
          inputs: [pstt_input(prev_tx, 0)],
          outputs: [pstt_output(70_000, p2pkh(keys[1])), pstt_output(29_000, p2pkh(keys[2]))]
        )
      expect(pstt.fee).to eq(1_000)
      expect(pstt.script_code(0)).to eq(p2pkh(keys[0]))

      pstt.sign(0, keys[0])
      expect(pstt.inputs.first.partial_sigs.size).to eq(1)

      pstt.finalize!
      tx = pstt.extract_tx
      # The identifier is computed with every sequence number set to 0, so it differs from the final txid.
      expect(tx.txid).not_to eq(pstt.identification_txid)
      expect(tx.verify_input_sig(0, prev_tx.outputs.first.script_pubkey)).to be true
    end

    it "signs with the Tapyrus Schnorr scheme" do
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      sig = pstt.sign(0, keys[0], algo: :schnorr)
      expect(sig.bytesize).to eq(65)
      expect(keys[0].verify(sig[0...-1], pstt.sighash_for_input(0), algo: :schnorr)).to be true
      pstt.finalize!
      expect(pstt.extract_tx.verify_input_sig(0, prev_tx.outputs.first.script_pubkey)).to be true
    end

    it "does not sign an input which has no PSTT_IN_UTXO" do
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      pstt.inputs.first.utxo = nil
      expect { pstt.sign(0, keys[0]) }.to raise_error(Tapyrus::PSTT::Error, "PSTT_IN_UTXO is required.")
    end

    it "does not sign an input whose PSTT_IN_UTXO does not match the outpoint" do
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      pstt.inputs.first.utxo = funding_tx([100_000, p2pkh(keys[0])])
      expect { pstt.sign(0, keys[0]) }.to raise_error(
        Tapyrus::PSTT::Error,
        "The txid of PSTT_IN_UTXO does not match PSTT_IN_PREVIOUS_TXID."
      )
    end

    it "uses the sighash type PSTT_IN_SIGHASH_TYPE requires" do
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      pstt.inputs.first.sighash_type = Tapyrus::SIGHASH_TYPE[:none]
      sig = pstt.sign(0, keys[0])
      expect(sig[-1].unpack1("C")).to eq(Tapyrus::SIGHASH_TYPE[:none])
      expect { pstt.sign(0, keys[0], sighash_type: Tapyrus::SIGHASH_TYPE[:all]) }.to raise_error(
        Tapyrus::PSTT::Error,
        /sighash type of this input is fixed/
      )
    end

    it "does not sign with a sighash type TIP-0174 does not define" do
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      # Only the low byte reaches the signature, while the whole value is committed to by the
      # signature hash, so a value which does not fit in a byte would yield an unverifiable signature.
      expect { pstt.sign(0, keys[0], sighash_type: 0x0101) }.to raise_error(
        Tapyrus::PSTT::Error,
        "Sighash type 0x101 is not defined by TIP-0174."
      )
      expect { pstt.sign(0, keys[0], sighash_type: 0x04) }.to raise_error(
        Tapyrus::PSTT::Error,
        /is not defined by TIP-0174/
      )
      # The same holds when the sighash type comes from PSTT_IN_SIGHASH_TYPE instead of the caller.
      pstt.inputs.first.sighash_type = 0x0101
      expect { pstt.sign(0, keys[0]) }.to raise_error(Tapyrus::PSTT::Error, /is not defined by TIP-0174/)
    end

    it "rejects a PSTT_IN_SIGHASH_TYPE which TIP-0174 does not define, both when writing and when reading" do
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      records =
        pstt.inputs.first.to_records << Tapyrus::PSTT::KeyValue.new(
          Tapyrus::PSTT::InputTypes::SIGHASH_TYPE,
          "".b,
          [0x04].pack("V")
        )
      payload =
        Tapyrus::PSTT::MAGIC + Tapyrus::PSTT.serialize_map(pstt.global_records) + Tapyrus::PSTT.serialize_map(records) +
          pstt.outputs.map(&:to_payload).join
      expect { Tapyrus::PSTT::Tx.parse_from_payload(payload) }.to raise_error(
        Tapyrus::PSTT::Error,
        "Sighash type 0x4 is not defined by TIP-0174."
      )

      pstt.inputs.first.sighash_type = 0x04
      expect { pstt.to_payload }.to raise_error(Tapyrus::PSTT::Error, /is not defined by TIP-0174/)
    end

    it "rejects a signature whose sighash type contradicts PSTT_IN_SIGHASH_TYPE" do
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      pstt.sign(0, keys[0], sighash_type: Tapyrus::SIGHASH_TYPE[:all])
      records =
        pstt.inputs.first.to_records << Tapyrus::PSTT::KeyValue.new(
          Tapyrus::PSTT::InputTypes::SIGHASH_TYPE,
          "".b,
          [Tapyrus::SIGHASH_TYPE[:none]].pack("V")
        )
      payload =
        Tapyrus::PSTT::MAGIC + Tapyrus::PSTT.serialize_map(pstt.global_records) + Tapyrus::PSTT.serialize_map(records) +
          pstt.outputs.map(&:to_payload).join
      expect { Tapyrus::PSTT::Tx.parse_from_payload(payload) }.to raise_error(
        Tapyrus::PSTT::Error,
        /uses sighash type 0x1, but PSTT_IN_SIGHASH_TYPE requires 0x2/
      )

      pstt.inputs.first.sighash_type = Tapyrus::SIGHASH_TYPE[:none]
      expect { pstt.to_payload }.to raise_error(Tapyrus::PSTT::Error, /uses sighash type 0x1/)
      expect { pstt.sighash_for_input(0, sighash_type: Tapyrus::SIGHASH_TYPE[:none]) }.to raise_error(
        Tapyrus::PSTT::Error,
        /uses sighash type 0x1/
      )
    end

    it "signs with every sighash type TIP-0174 defines" do
      Tapyrus::PSTT::SIGHASH_TYPES.each do |hash_type|
        pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
        sig = pstt.sign(0, keys[0], sighash_type: hash_type)
        expect(sig[-1].unpack1("C")).to eq(hash_type)
        sighash = pstt.sighash_for_input(0, sighash_type: hash_type)
        expect(keys[0].verify(sig[0...-1], sighash)).to be true
      end
    end
  end

  describe "Colored Coin workflow" do
    let(:color_id) { Tapyrus::Color::ColorIdentifier.reissuable(p2pkh(keys[0])) }
    let(:cp2pkh) { Tapyrus::Script.to_cp2pkh(color_id, keys[0].hash160) }
    let(:token_tx) { funding_tx([100, cp2pkh]) }
    let(:fee_tx) { funding_tx([10_000, p2pkh(keys[3])]) }

    it "transfers tokens with a TPC input which pays the fee" do
      pstt =
        Tapyrus::PSTT::Tx.new(
          inputs: [pstt_input(token_tx, 0), pstt_input(fee_tx, 0)],
          outputs: [
            pstt_output(100, Tapyrus::Script.to_cp2pkh(color_id, keys[1].hash160)),
            pstt_output(9_000, p2pkh(keys[3]))
          ]
        )
      expect(pstt.input_amounts[color_id]).to eq(100)
      expect(pstt.output_amounts[color_id]).to eq(100)
      expect(pstt.fee).to eq(1_000)

      # The scriptCode of a CP2PKH input is the full scriptPubKey, including the color prefix.
      expect(pstt.script_code(0)).to eq(cp2pkh)
      expect(pstt.script_code(0).colored?).to be true

      pstt.sign(0, keys[0])
      pstt.sign(1, keys[3])
      pstt.finalize!
      tx = pstt.extract_tx
      expect(tx.verify_input_sig(0, cp2pkh)).to be true
      expect(tx.verify_input_sig(1, p2pkh(keys[3]))).to be true
    end

    it "signs a 2-of-2 CP2SH multisig input in parallel and combines the results" do
      redeem_script = Tapyrus::Script.to_multisig_script(2, [keys[0].pubkey, keys[1].pubkey])
      cp2sh = Tapyrus::Script.to_cp2sh(color_id, redeem_script.to_hash160)
      prev_tx = funding_tx([50, cp2sh])

      base =
        Tapyrus::PSTT::Tx.new(
          inputs: [pstt_input(prev_tx, 0)],
          outputs: [pstt_output(50, Tapyrus::Script.to_cp2pkh(color_id, keys[2].hash160))]
        )
      base.inputs.first.redeem_script = redeem_script
      # The scriptCode of a CP2SH input is the redeem script, without the color identifier prefix.
      expect(base.script_code(0)).to eq(redeem_script)
      expect(base.script_code(0).colored?).to be false

      alice = Tapyrus::PSTT::Tx.parse_from_payload(base.to_payload)
      bob = Tapyrus::PSTT::Tx.parse_from_payload(base.to_payload)
      alice.sign(0, keys[0])
      bob.sign(0, keys[1])

      combined = alice.combine(bob)
      expect(combined.inputs.first.partial_sigs.keys).to contain_exactly(keys[0].pubkey, keys[1].pubkey)

      sighash = combined.sighash_for_input(0)
      combined.inputs.first.partial_sigs.each do |pubkey, sig|
        expect(Tapyrus::Key.new(pubkey: pubkey).verify(sig[0...-1], sighash)).to be true
      end

      combined.finalize!
      expect(combined.inputs.first.partial_sigs).to be_empty
      expect(combined.inputs.first.redeem_script).to be_nil
      # OP_0 <sig> <sig> <redeem script>
      script_sig = combined.extract_tx.inputs.first.script_sig
      expect(script_sig.chunks.size).to eq(4)
      expect(script_sig.chunks.first.opcode).to eq(Tapyrus::Opcodes::OP_0)
      expect(script_sig.chunks.last.pushed_data).to eq(redeem_script.to_payload)
    end

    it "finalizes a 2-of-2 P2SH multisig input into a spendable scriptSig" do
      redeem_script = Tapyrus::Script.to_multisig_script(2, [keys[0].pubkey, keys[1].pubkey])
      p2sh = Tapyrus::Script.to_p2sh(redeem_script.to_hash160)
      prev_tx = funding_tx([100_000, p2sh])
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[2]))])
      pstt.inputs.first.redeem_script = redeem_script
      expect(pstt.script_code(0)).to eq(redeem_script)
      pstt.sign(0, keys[0])
      pstt.sign(0, keys[1])
      pstt.finalize!
      expect(pstt.extract_tx.verify_input_sig(0, p2sh)).to be true
    end

    it "does not sign when the redeem script does not hash to the committed value" do
      redeem_script = Tapyrus::Script.to_multisig_script(2, [keys[0].pubkey, keys[1].pubkey])
      prev_tx = funding_tx([100_000, Tapyrus::Script.to_p2sh(redeem_script.to_hash160)])
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[2]))])
      pstt.inputs.first.redeem_script = Tapyrus::Script.to_multisig_script(2, [keys[0].pubkey, keys[2].pubkey])
      expect { pstt.sign(0, keys[0]) }.to raise_error(
        Tapyrus::PSTT::Error,
        "PSTT_IN_REDEEM_SCRIPT does not hash to the value committed in the scriptPubKey."
      )
    end

    it "does not mix ECDSA and Schnorr signatures within one input" do
      redeem_script = Tapyrus::Script.to_multisig_script(2, [keys[0].pubkey, keys[1].pubkey])
      prev_tx = funding_tx([50, Tapyrus::Script.to_p2sh(redeem_script.to_hash160)])
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(40, p2pkh(keys[2]))])
      pstt.inputs.first.redeem_script = redeem_script
      pstt.sign(0, keys[0], algo: :ecdsa)
      expect { pstt.sign(0, keys[1], algo: :schnorr) }.to raise_error(Tapyrus::PSTT::Error, /must not be mixed/)
    end
  end

  describe "construction" do
    let(:prev_tx) { funding_tx([100_000, p2pkh(keys[0])]) }

    it "adds inputs and outputs while the modifiable flags are set" do
      pstt = Tapyrus::PSTT::Tx.new(tx_modifiable: Tapyrus::PSTT::TxModifiable::ALL & ~4)
      expect(pstt.inputs_modifiable?).to be true
      expect(pstt.outputs_modifiable?).to be true

      empty_id = pstt.identification_txid
      pstt.add_input(pstt_input(prev_tx, 0))
      expect(pstt.identification_txid).not_to eq(empty_id)
      pstt.add_output(pstt_output(99_000, p2pkh(keys[1])))

      parsed = Tapyrus::PSTT::Tx.parse_from_payload(pstt.to_payload)
      expect(parsed.inputs.size).to eq(1)
      expect(parsed.outputs.size).to eq(1)

      pstt.finish_construction!
      expect(pstt.inputs_modifiable?).to be false
      expect(pstt.outputs_modifiable?).to be false
      expect { pstt.add_output(pstt_output(1, p2pkh(keys[2]))) }.to raise_error(
        Tapyrus::PSTT::Error,
        "Outputs are not modifiable."
      )
    end

    it "does not add an input when the Inputs Modifiable flag is clear" do
      pstt = Tapyrus::PSTT::Tx.new
      expect { pstt.add_input(pstt_input(prev_tx, 0)) }.to raise_error(
        Tapyrus::PSTT::Error,
        "Inputs are not modifiable."
      )
    end

    it "does not finalize while the PSTT is still modifiable" do
      pstt =
        Tapyrus::PSTT::Tx.new(
          tx_modifiable: Tapyrus::PSTT::TxModifiable::INPUTS,
          inputs: [pstt_input(prev_tx, 0)],
          outputs: [pstt_output(99_000, p2pkh(keys[1]))]
        )
      expect { pstt.finalize! }.to raise_error(
        Tapyrus::PSTT::Error,
        "A PSTT must not be finalized while it is still modifiable."
      )
    end

    it "does not add an input which changes the locktime of a PSTT that already holds signatures" do
      pstt =
        Tapyrus::PSTT::Tx.new(
          tx_modifiable: Tapyrus::PSTT::TxModifiable::INPUTS,
          inputs: [pstt_input(prev_tx, 0)],
          outputs: [pstt_output(99_000, p2pkh(keys[1]))]
        )
      pstt.sign(0, keys[0], sighash_type: Tapyrus::SIGHASH_TYPE[:all] | Tapyrus::SIGHASH_TYPE[:anyonecanpay])
      added = pstt_input(funding_tx([5_000, p2pkh(keys[2])]), 0)
      added.required_height_locktime = 100
      expect { pstt.add_input(added) }.to raise_error(
        Tapyrus::PSTT::Error,
        "The added input changes the locktime of a PSTT which already contains signatures."
      )
      expect(pstt.inputs.size).to eq(1)
    end

    it "keeps inputs and outputs paired once a SIGHASH_SINGLE signature is present" do
      pstt =
        Tapyrus::PSTT::Tx.new(
          tx_modifiable: Tapyrus::PSTT::TxModifiable::INPUTS | Tapyrus::PSTT::TxModifiable::OUTPUTS,
          inputs: [pstt_input(prev_tx, 0)],
          outputs: [pstt_output(99_000, p2pkh(keys[1]))]
        )
      pstt.sign(0, keys[0], sighash_type: Tapyrus::SIGHASH_TYPE[:single] | Tapyrus::SIGHASH_TYPE[:anyonecanpay])
      expect(pstt.has_sighash_single?).to be true
      expect(pstt.inputs_modifiable?).to be true
      expect(pstt.outputs_modifiable?).to be false

      other_tx = funding_tx([5_000, p2pkh(keys[2])])
      expect { pstt.add_input(pstt_input(other_tx, 0)) }.to raise_error(Tapyrus::PSTT::Error, /add_pair/)
      # Signing cleared the Outputs Modifiable flag, and that must not be undone to make room
      # for the pair: the flags record what the collected signatures still allow.
      expect { pstt.tx_modifiable |= Tapyrus::PSTT::TxModifiable::OUTPUTS }.to raise_error(
        Tapyrus::PSTT::Error,
        /must not be relaxed/
      )
    end

    it "adds an input and an output as a pair while the Has SIGHASH_SINGLE flag is set" do
      # Both modifiable flags are still set, so no signature of this PSTT is at stake and the
      # Constructor may still extend it - in pairs, because the flag demands it.
      pstt =
        Tapyrus::PSTT::Tx.new(
          tx_modifiable: Tapyrus::PSTT::TxModifiable::ALL,
          inputs: [pstt_input(prev_tx, 0)],
          outputs: [pstt_output(99_000, p2pkh(keys[1]))]
        )
      other_tx = funding_tx([5_000, p2pkh(keys[2])])
      expect { pstt.add_input(pstt_input(other_tx, 0)) }.to raise_error(Tapyrus::PSTT::Error, /add_pair/)

      pstt.add_pair(pstt_input(other_tx, 0), pstt_output(4_000, p2pkh(keys[3])))
      expect(pstt.inputs.size).to eq(2)
      expect(pstt.outputs.size).to eq(2)
    end

    it "adds a pair while the PSTT has more outputs than inputs" do
      # Input 1 gets output 1, which is already there; the added output extends the tail. Every
      # input still has an output at its own position, which is all SIGHASH_SINGLE asks for.
      pstt =
        Tapyrus::PSTT::Tx.new(
          tx_modifiable: Tapyrus::PSTT::TxModifiable::ALL,
          inputs: [pstt_input(prev_tx, 0)],
          outputs: [pstt_output(50_000, p2pkh(keys[1])), pstt_output(49_000, p2pkh(keys[2]))]
        )
      pstt.add_pair(pstt_input(funding_tx([5_000, p2pkh(keys[3])]), 0), pstt_output(4_000, p2pkh(keys[4])))
      expect(pstt.inputs.size).to eq(2)
      expect(pstt.outputs.size).to eq(3)
    end

    it "does not add a pair which would leave an input without a corresponding output" do
      pstt =
        Tapyrus::PSTT::Tx.new(
          tx_modifiable: Tapyrus::PSTT::TxModifiable::ALL,
          inputs: [pstt_input(prev_tx, 0), pstt_input(funding_tx([5_000, p2pkh(keys[1])]), 0)],
          outputs: [pstt_output(99_000, p2pkh(keys[2]))]
        )
      expect { pstt.add_pair(pstt_input(funding_tx([1, p2pkh(keys[3])]), 0), pstt_output(1, p2pkh(keys[4]))) }.to(
        raise_error(Tapyrus::PSTT::Error, "The added input would have no corresponding output at a matching position.")
      )
      expect(pstt.inputs.size).to eq(2)
      expect(pstt.outputs.size).to eq(1)
    end

    it "does not finalize or extract a PSTT which has no inputs" do
      pstt = Tapyrus::PSTT::Tx.new(outputs: [pstt_output(1_000, p2pkh(keys[0]))])
      expect { pstt.finalize! }.to raise_error(Tapyrus::PSTT::Error, "This PSTT has no inputs to finalize.")
      expect { pstt.extract_tx }.to raise_error(Tapyrus::PSTT::Error, /This PSTT has no inputs/)
    end
  end

  describe "the fields a signature commits to" do
    let(:prev_tx) { funding_tx([100_000, p2pkh(keys[0])]) }

    def signed_pstt(tx_modifiable: nil, input: pstt_input(prev_tx, 0), sighash_type: nil)
      pstt =
        Tapyrus::PSTT::Tx.new(
          tx_modifiable: tx_modifiable,
          inputs: [input],
          outputs: [pstt_output(99_000, p2pkh(keys[1]))]
        )
      pstt.sign(0, keys[0], sighash_type: sighash_type)
      pstt
    end

    it "does not change the features once a signature has been collected" do
      pstt = signed_pstt
      expect { pstt.features = 2 }.to raise_error(
        Tapyrus::PSTT::Error,
        "The features of a PSTT which already contains signatures must not be changed."
      )
      expect(pstt.features).to eq(1)
    end

    it "does not change PSTT_GLOBAL_FALLBACK_LOCKTIME once a signature has been collected" do
      pstt = signed_pstt
      sighash = pstt.sighash_for_input(0)
      expect { pstt.fallback_locktime = 500 }.to raise_error(
        Tapyrus::PSTT::Error,
        /PSTT_GLOBAL_FALLBACK_LOCKTIME changes the locktime/
      )
      expect(pstt.fallback_locktime).to be_nil
      expect(pstt.sighash_for_input(0)).to eq(sighash)
    end

    it "changes PSTT_GLOBAL_FALLBACK_LOCKTIME when no input consults it" do
      # The guard is about the locktime the PSTT resolves to, not about the field itself.
      input = pstt_input(prev_tx, 0).tap { |i| i.required_height_locktime = 100 }
      pstt = signed_pstt(input: input)
      expect(pstt.locktime).to eq(100)
      pstt.fallback_locktime = 500
      expect(pstt.locktime).to eq(100)
    end

    it "does not relax PSTT_GLOBAL_TX_MODIFIABLE once a signature has been collected" do
      pstt = signed_pstt(tx_modifiable: Tapyrus::PSTT::TxModifiable::INPUTS | Tapyrus::PSTT::TxModifiable::OUTPUTS)
      expect(pstt.tx_modifiable).to eq(0)
      expect { pstt.tx_modifiable = Tapyrus::PSTT::TxModifiable::INPUTS }.to raise_error(
        Tapyrus::PSTT::Error,
        "PSTT_GLOBAL_TX_MODIFIABLE must not be relaxed once the PSTT contains signatures."
      )
      expect(pstt.tx_modifiable).to eq(0)
    end

    it "does not clear the Has SIGHASH_SINGLE flag once a signature has been collected" do
      pstt =
        signed_pstt(
          tx_modifiable: Tapyrus::PSTT::TxModifiable::INPUTS,
          sighash_type: Tapyrus::SIGHASH_TYPE[:single] | Tapyrus::SIGHASH_TYPE[:anyonecanpay]
        )
      expect(pstt.has_sighash_single?).to be true
      expect { pstt.tx_modifiable = 0 }.to raise_error(Tapyrus::PSTT::Error, /must not be relaxed/)
    end

    it "still tightens PSTT_GLOBAL_TX_MODIFIABLE after a signature has been collected" do
      pstt =
        signed_pstt(
          tx_modifiable: Tapyrus::PSTT::TxModifiable::INPUTS,
          sighash_type: Tapyrus::SIGHASH_TYPE[:all] | Tapyrus::SIGHASH_TYPE[:anyonecanpay]
        )
      expect(pstt.inputs_modifiable?).to be true
      pstt.tx_modifiable = 0
      expect(pstt.inputs_modifiable?).to be false
    end
  end

  describe "the Updater's sequence number restriction" do
    let(:prev_tx) { funding_tx([100_000, p2pkh(keys[0])]) }
    let(:other_tx) { funding_tx([100_000, p2pkh(keys[1])]) }

    def two_input_pstt
      Tapyrus::PSTT::Tx.new(
        inputs: [pstt_input(prev_tx, 0), pstt_input(other_tx, 0)],
        outputs: [pstt_output(199_000, p2pkh(keys[2]))]
      )
    end

    it "sets the sequence number while no signature commits to it" do
      pstt = two_input_pstt
      pstt.set_sequence(0, 0xfffffffe)
      expect(pstt.inputs.first.sequence).to eq(0xfffffffe)
      expect(pstt.build_tx.inputs.first.sequence).to eq(0xfffffffe)
      expect(pstt.build_tx.inputs.last.sequence).to eq(Tapyrus::TxIn::SEQUENCE_FINAL)
    end

    it "does not change the sequence number of a signed input" do
      pstt = two_input_pstt
      pstt.sign(0, keys[0], sighash_type: Tapyrus::SIGHASH_TYPE[:none])
      expect { pstt.set_sequence(0, 0xfffffffe) }.to raise_error(Tapyrus::PSTT::Error, /already signed/)
    end

    it "does not change the sequence number of another input while a SIGHASH_ALL signature exists" do
      pstt = two_input_pstt
      pstt.sign(0, keys[0])
      expect { pstt.set_sequence(1, 0xfffffffe) }.to raise_error(
        Tapyrus::PSTT::Error,
        /commits to the sequence number of every input/
      )
    end

    it "allows changing another input's sequence number when the signature does not commit to it" do
      pstt = two_input_pstt
      pstt.sign(0, keys[0], sighash_type: Tapyrus::SIGHASH_TYPE[:none])
      pstt.set_sequence(1, 0xfffffffe)
      expect(pstt.inputs.last.sequence).to eq(0xfffffffe)
    end

    it "does not change the sequence number of an unsigned input while another input is finalized" do
      pstt = two_input_pstt
      pstt.sign(0, keys[0])
      # Finalizing input 0 removes its PSTT_IN_PARTIAL_SIG records, so the sighash types of the
      # signatures it was built from can no longer be read - but its SIGHASH_ALL signature still
      # commits to the sequence number of input 1.
      pstt.inputs.first.finalize!(pstt.verified_partial_sigs(0))
      expect(pstt.inputs.first.partial_sigs).to be_empty
      expect { pstt.set_sequence(1, 0xfffffffe) }.to raise_error(
        Tapyrus::PSTT::Error,
        /A finalized input carries signatures/
      )
    end

    it "does not change the sequence number of a finalized input" do
      pstt = two_input_pstt
      pstt.sign(0, keys[0], sighash_type: Tapyrus::SIGHASH_TYPE[:none])
      pstt.inputs.first.finalize!(pstt.verified_partial_sigs(0))
      expect { pstt.set_sequence(0, 0xfffffffe) }.to raise_error(Tapyrus::PSTT::Error, /already signed/)
    end
  end

  describe "Input Finalizer" do
    let(:prev_tx) { funding_tx([100_000, p2pkh(keys[0])]) }
    let(:garbage_sig) { ("00".htb * 71) + [Tapyrus::SIGHASH_TYPE[:all]].pack("C") }

    it "does not build a scriptSig from a signature which does not verify" do
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      pstt.inputs.first.partial_sigs[keys[0].pubkey] = garbage_sig
      expect { pstt.finalize! }.to raise_error(
        Tapyrus::PSTT::Error,
        "No valid signature for the public key committed in the scriptPubKey."
      )
    end

    it "does not let an invalid signature displace a valid one in a multisig input" do
      redeem_script = Tapyrus::Script.to_multisig_script(2, [keys[0].pubkey, keys[1].pubkey, keys[2].pubkey])
      p2sh = Tapyrus::Script.to_p2sh(redeem_script.to_hash160)
      pstt =
        Tapyrus::PSTT::Tx.new(
          inputs: [pstt_input(funding_tx([100_000, p2sh]), 0)],
          outputs: [pstt_output(99_000, p2pkh(keys[3]))]
        )
      pstt.inputs.first.redeem_script = redeem_script
      # The invalid signature belongs to the first public key of the redeem script, so a
      # finalizer which took the collected signatures at face value would put it into the
      # scriptSig and leave one of the two valid ones unused.
      pstt.inputs.first.partial_sigs[keys[0].pubkey] = garbage_sig
      pstt.sign(0, keys[1])
      pstt.sign(0, keys[2])
      expect(pstt.verified_partial_sigs(0).keys).to contain_exactly(keys[1].pubkey, keys[2].pubkey)

      pstt.finalize!
      expect(pstt.extract_tx.verify_input_sig(0, p2sh)).to be true
    end

    it "counts only the valid signatures against the multisig threshold" do
      redeem_script = Tapyrus::Script.to_multisig_script(2, [keys[0].pubkey, keys[1].pubkey])
      p2sh = Tapyrus::Script.to_p2sh(redeem_script.to_hash160)
      pstt =
        Tapyrus::PSTT::Tx.new(
          inputs: [pstt_input(funding_tx([100_000, p2sh]), 0)],
          outputs: [pstt_output(99_000, p2pkh(keys[2]))]
        )
      pstt.inputs.first.redeem_script = redeem_script
      pstt.inputs.first.partial_sigs[keys[0].pubkey] = garbage_sig
      pstt.sign(0, keys[1])
      expect { pstt.finalize! }.to raise_error(
        Tapyrus::PSTT::Error,
        "2 signatures are required, but only 1 of the collected ones are valid."
      )
    end

    it "does not sign an input which is already finalized" do
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      pstt.sign(0, keys[0])
      pstt.finalize!
      expect { pstt.sign(0, keys[0]) }.to raise_error(
        Tapyrus::PSTT::Error,
        "Input 0 is finalized. It takes no further signature."
      )
      expect(pstt.inputs.first.partial_sigs).to be_empty
    end
  end

  describe "Determining the Locktime" do
    let(:prev_tx) { funding_tx([100_000, p2pkh(keys[0])]) }

    def locktime_pstt(*inputs)
      Tapyrus::PSTT::Tx.new(inputs: inputs, outputs: [pstt_output(99_000, p2pkh(keys[1]))])
    end

    it "falls back to PSTT_GLOBAL_FALLBACK_LOCKTIME when no input requires a locktime" do
      pstt = locktime_pstt(pstt_input(prev_tx, 0))
      expect(pstt.locktime).to eq(0)
      pstt.fallback_locktime = 100
      expect(pstt.locktime).to eq(100)
      expect(pstt.build_tx.lock_time).to eq(100)
    end

    it "takes the maximum height-based locktime" do
      first = pstt_input(prev_tx, 0).tap { |input| input.required_height_locktime = 100 }
      second = pstt_input(funding_tx([1, p2pkh(keys[1])]), 0).tap { |input| input.required_height_locktime = 200 }
      pstt = locktime_pstt(first, second)
      pstt.fallback_locktime = 1_000
      expect(pstt.locktime).to eq(200)
    end

    it "takes the maximum time-based locktime" do
      input = pstt_input(prev_tx, 0).tap { |i| i.required_time_locktime = 1_700_000_000 }
      expect(locktime_pstt(input).locktime).to eq(1_700_000_000)
    end

    it "prefers the height-based locktime when both kinds are acceptable" do
      input =
        pstt_input(prev_tx, 0).tap do |i|
          i.required_height_locktime = 100
          i.required_time_locktime = 1_700_000_000
        end
      expect(locktime_pstt(input).locktime).to eq(100)
    end

    it "raises when no locktime kind is acceptable to every input" do
      first = pstt_input(prev_tx, 0).tap { |input| input.required_height_locktime = 100 }
      second = pstt_input(funding_tx([1, p2pkh(keys[1])]), 0).tap { |i| i.required_time_locktime = 1_700_000_000 }
      expect { locktime_pstt(first, second).locktime }.to raise_error(
        Tapyrus::PSTT::Error,
        /No locktime kind is acceptable/
      )
    end

    it "rejects a required locktime which is out of range, both when writing and when reading" do
      input = pstt_input(prev_tx, 0).tap { |i| i.required_time_locktime = 100 }
      expect { locktime_pstt(input).to_payload }.to raise_error(Tapyrus::PSTT::Error, /PSTT_IN_REQUIRED_TIME_LOCKTIME/)
      expect { Tapyrus::PSTT::Tx.parse_from_payload(payload_with_time_locktime(100)) }.to raise_error(
        Tapyrus::PSTT::Error,
        /PSTT_IN_REQUIRED_TIME_LOCKTIME/
      )
    end

    it "rejects a required height locktime which is out of range, both when writing and when reading" do
      [0, Tapyrus::PSTT::LOCKTIME_THRESHOLD].each do |height|
        input = pstt_input(prev_tx, 0).tap { |i| i.required_height_locktime = height }
        expect { locktime_pstt(input).to_payload }.to raise_error(
          Tapyrus::PSTT::Error,
          /PSTT_IN_REQUIRED_HEIGHT_LOCKTIME/
        )
      end
    end

    # A PSTT whose PSTT_IN_REQUIRED_TIME_LOCKTIME is out of range cannot be serialized by this
    # implementation, so the parser is fed a hand-assembled payload instead.
    def payload_with_time_locktime(value)
      input = pstt_input(prev_tx, 0)
      records = input.to_records << Tapyrus::PSTT::KeyValue.new(0x11, "".b, [value].pack("V"))
      pstt = locktime_pstt(input)
      Tapyrus::PSTT::MAGIC + Tapyrus::PSTT.serialize_map(pstt.global_records) + Tapyrus::PSTT.serialize_map(records) +
        pstt.outputs.map(&:to_payload).join
    end
  end

  describe "fee provider workflow" do
    let(:color_id) { Tapyrus::Color::ColorIdentifier.reissuable(p2pkh(keys[0])) }
    let(:token_tx) { funding_tx([100, Tapyrus::Script.to_cp2pkh(color_id, keys[0].hash160)]) }
    let(:fee_tx) { funding_tx([1_000, p2pkh(keys[3])]) }

    it "lets the provider add an exact-fee input after the user has signed" do
      # The user creates and signs with SIGHASH_ALL | SIGHASH_ANYONECANPAY, leaving inputs modifiable.
      user =
        Tapyrus::PSTT::Tx.new(
          tx_modifiable: Tapyrus::PSTT::TxModifiable::INPUTS,
          inputs: [pstt_input(token_tx, 0)],
          outputs: [pstt_output(100, Tapyrus::Script.to_cp2pkh(color_id, keys[1].hash160))]
        )
      sighash_type = Tapyrus::SIGHASH_TYPE[:all] | Tapyrus::SIGHASH_TYPE[:anyonecanpay]
      user_sighash = user.sighash_for_input(0, sighash_type: sighash_type)
      user.sign(0, keys[0], sighash_type: sighash_type)
      expect(user.inputs_modifiable?).to be true

      # The provider verifies the token balance, then adds the fee input and signs with SIGHASH_ALL.
      provider = Tapyrus::PSTT::Tx.parse_from_payload(user.to_payload)
      expect(provider.input_amounts[color_id]).to eq(provider.output_amounts[color_id])
      provider.add_input(pstt_input(fee_tx, 0))
      provider.sign(1, keys[3])
      expect(provider.inputs_modifiable?).to be false

      # The user's signature hash is unchanged by the added input.
      expect(provider.sighash_for_input(0, sighash_type: sighash_type)).to eq(user_sighash)
      expect(provider.fee).to eq(1_000)

      provider.finalize!
      tx = provider.extract_tx
      expect(tx.verify_input_sig(0, token_tx.outputs.first.script_pubkey)).to be true
      expect(tx.verify_input_sig(1, fee_tx.outputs.first.script_pubkey)).to be true
    end
  end

  describe "Combiner" do
    let(:prev_tx) { funding_tx([100_000, p2pkh(keys[0])]) }
    let(:other_tx) { funding_tx([5_000, p2pkh(keys[2])]) }

    def modifiable_pstt
      Tapyrus::PSTT::Tx.new(
        tx_modifiable: Tapyrus::PSTT::TxModifiable::INPUTS | Tapyrus::PSTT::TxModifiable::OUTPUTS,
        inputs: [pstt_input(prev_tx, 0)],
        outputs: [pstt_output(99_000, p2pkh(keys[1]))]
      )
    end

    it "does not combine PSTTs with different identifiers" do
      first = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      second = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(98_000, p2pkh(keys[1]))])
      expect { first.combine(second) }.to raise_error(
        Tapyrus::PSTT::Error,
        "PSTTs with different identifiers must not be combined."
      )
    end

    it "does not resurrect a modifiable flag which the Signer cleared" do
      signed = modifiable_pstt
      # A copy taken before the signature still has both flags set, and both copies identify as
      # the same PSTT because the identifier does not depend on the signatures.
      unsigned = Tapyrus::PSTT::Tx.parse_from_payload(signed.to_payload)
      signed.sign(0, keys[0])
      expect(signed.tx_modifiable).to eq(0)
      expect(unsigned.tx_modifiable).to eq(3)

      combined = unsigned.combine(signed)
      expect(combined.tx_modifiable).to eq(0)
      expect(combined.inputs.first.signed?).to be true
      expect { combined.add_input(pstt_input(other_tx, 0)) }.to raise_error(
        Tapyrus::PSTT::Error,
        "Inputs are not modifiable."
      )
    end

    it "keeps the Has SIGHASH_SINGLE flag of either PSTT" do
      first = modifiable_pstt
      second = Tapyrus::PSTT::Tx.parse_from_payload(first.to_payload)
      second.sign(0, keys[0], sighash_type: Tapyrus::SIGHASH_TYPE[:single] | Tapyrus::SIGHASH_TYPE[:anyonecanpay])
      expect(first.combine(second).has_sighash_single?).to be true
      expect(second.combine(first).has_sighash_single?).to be true
    end

    it "does not combine PSTTs which disagree about a sequence number" do
      first = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      second = Tapyrus::PSTT::Tx.parse_from_payload(first.to_payload)
      first.set_sequence(0, 0xfffffffe)
      # The identifier is computed with every sequence number set to 0, so it does not separate
      # the two. Keeping one value would invalidate the signatures which commit to the other.
      expect(first.identification_txid).to eq(second.identification_txid)
      expect { first.combine(second) }.to raise_error(
        Tapyrus::PSTT::Error,
        "Input 0 has a different sequence number in the two PSTTs."
      )
    end
  end

  describe "BIP 32 derivation" do
    it "carries the key origin of an input and an output" do
      prev_tx = funding_tx([100_000, p2pkh(keys[0])])
      pstt = Tapyrus::PSTT::Tx.new(inputs: [pstt_input(prev_tx, 0)], outputs: [pstt_output(99_000, p2pkh(keys[1]))])
      origin = Tapyrus::PSTT::KeyOriginInfo.from_path("f05655ac", "m/44'/2377'/0'/0/0")
      pstt.inputs.first.bip32_derivations[keys[0].pubkey] = origin
      pstt.outputs.first.bip32_derivations[keys[1].pubkey] = origin

      parsed = Tapyrus::PSTT::Tx.parse_from_payload(pstt.to_payload)
      expect(parsed.inputs.first.bip32_derivations[keys[0].pubkey]).to eq(origin)
      expect(parsed.outputs.first.bip32_derivations[keys[1].pubkey].path).to eq("m/44'/2377'/0'/0/0")
      expect(parsed.outputs.first.bip32_derivations[keys[1].pubkey].fingerprint).to eq("f05655ac")
    end

    it "carries a global extended public key" do
      seed = Tapyrus.sha256("tapyrusrb pstt spec").bth
      account = Tapyrus::ExtKey.generate_master(seed).derive(44, true).derive(1, true).derive(0, true).ext_pubkey
      pstt = Tapyrus::PSTT::Tx.new
      pstt.xpubs[account.to_base58] = Tapyrus::PSTT::KeyOriginInfo.from_path(
        Tapyrus::ExtKey.generate_master(seed).fingerprint,
        "m/44'/1'/0'"
      )
      parsed = Tapyrus::PSTT::Tx.parse_from_payload(pstt.to_payload)
      expect(parsed.xpubs.keys).to eq([account.to_base58])
      expect(parsed.xpubs.values.first.path).to eq("m/44'/1'/0'")
    end
  end

  describe "Proprietary" do
    it "carries a proprietary record" do
      pstt = Tapyrus::PSTT::Tx.new
      pstt.proprietaries << Tapyrus::PSTT::Proprietary.new(
        identifier: "tapyrusrb",
        subtype: 1,
        subkeydata: "01".htb,
        value: "value"
      )
      parsed = Tapyrus::PSTT::Tx.parse_from_payload(pstt.to_payload)
      expect(parsed.proprietaries.size).to eq(1)
      expect(parsed.proprietaries.first.identifier).to eq("tapyrusrb")
      expect(parsed.proprietaries.first.subtype).to eq(1)
      expect(parsed.proprietaries.first.value).to eq("value")
    end
  end
end
