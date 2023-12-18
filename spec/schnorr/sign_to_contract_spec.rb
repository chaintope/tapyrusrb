require "spec_helper"

describe "Schnorr::SignToContract" do
  let(:contract) { Tapyrus.sha256("foo") }
  let(:message) { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".htb }
  let(:key) { Tapyrus::Key.from_wif("cW2r6zzDwqmxhKiRckCnpXmPB25csqUUkJyJ2Jab71pLa2J1HVTv") }
  let(:private_key) { key.priv_key.to_i(16) }
  let(:public_key) { key.pubkey.htb }

  describe ".sign" do
    subject do
      signature, r = Schnorr::SignToContract.sign(message, private_key, contract)
      Schnorr.valid_sig?(message, signature.encode, public_key)
    end

    it { is_expected.to be_truthy }
  end

  describe ".valid_contract?" do
    subject do
      signature, r = Schnorr::SignToContract.sign(message, private_key, contract)
      Schnorr::SignToContract.valid_contract?(r, signature, test)
    end

    context "valid contract" do
      let(:test) { Tapyrus.sha256("foo") }
      it { is_expected.to be_truthy }
    end

    context "invalid contract" do
      let(:test) { Tapyrus.sha256("bar") }
      it { is_expected.to be_falsy }
    end
  end

  describe "sign tx with sign-to-signature" do
    it do
      tx =
        Tapyrus::Tx.parse_from_payload(
          "01000000018594c5bdcaec8f06b78b596f31cd292a294fd031e24eec716f43dac91ea7494d0000000000ffffffff01a0860100000000001976a9145834479edbbe0539b31ffd3a8f8ebadc2165ed0188ac00000000".htb
        )
      script = Tapyrus::Script.parse_from_payload("76a914bb42ade3ce0fbeafa5947116e1707b053147993788ac".htb)
      sighash = tx.sighash_for_input(0, script)
      signature, r = Schnorr::SignToContract.sign(sighash, key.priv_key.to_i(16), contract)
      sig = signature.encode + [Tapyrus::SIGHASH_TYPE[:all]].pack("C")

      expect(key.verify(signature.encode, sighash, algo: :schnorr)).to be_truthy

      tx.in[0].script_sig = Tapyrus::Script.new << sig << key.pubkey.htb

      checker = Tapyrus::TxChecker.new(tx: tx, input_index: 0)
      expect(checker.verify_sig(signature.encode.bth, key.pubkey, sighash)).to be_truthy

      expect(tx.verify_input_sig(0, script)).to be_truthy
    end
  end
end
