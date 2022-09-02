require 'spec_helper'

describe Tapyrus::ScriptInterpreter do
  describe 'check script_test.json' do
    script_json = fixture_file('script_tests.json').select { |j| j.size > 3 }
    script_json.each do |r|
      it "should validate script #{r.inspect}" do
        if r[0].is_a?(Array)
          sig, pubkey, flags, error_code = r[1], r[2], r[3], r[4]
          amount = (r[0][-1] * 100_000_000).to_i
        else
          sig, pubkey, flags, error_code = r[0], r[1], r[2], r[3]
          amount = 0
        end
        script_sig = Tapyrus::TestScriptParser.parse_script(sig)
        script_pubkey = Tapyrus::TestScriptParser.parse_script(pubkey)
        credit_tx = build_credit_tx(script_pubkey, amount)
        tx = build_spending_tx(script_sig, credit_tx, amount)
        script_flags =
          flags
            .split(',')
            .map { |s| Tapyrus.const_get("SCRIPT_VERIFY_#{s}") }
            .inject(Tapyrus::SCRIPT_VERIFY_NONE) { |flags, f| flags |= f }
        expected_err_code = find_error_code(error_code)
        i = Tapyrus::ScriptInterpreter.new(flags: script_flags, checker: Tapyrus::TxChecker.new(tx: tx, input_index: 0))
        result = i.verify_script(script_sig, script_pubkey)
        expect(result).to be expected_err_code == Tapyrus::SCRIPT_ERR_OK
        expect(i.error.code).to eq(expected_err_code) unless result

        # Verify that removing flags from a passing test or adding flags to a failing test does not change the result.
        16.times do
          extra_flags = rand(32_768) # 16 bit unsigned integer
          combined_flags = result ? (script_flags & ~extra_flags) : (script_flags | extra_flags)
          next if combined_flags & Tapyrus::SCRIPT_VERIFY_CLEANSTACK && ~combined_flags & (Tapyrus::SCRIPT_VERIFY_P2SH)
          next if combined_flags && ~combined_flags & Tapyrus::SCRIPT_VERIFY_P2SH
          i =
            Tapyrus::ScriptInterpreter.new(
              flags: combined_flags,
              checker: Tapyrus::TxChecker.new(tx: tx, input_index: 0)
            )
          extra_result = i.verify_script(script_sig, script_pubkey)
          expect(extra_result).to be expected_err_code == Tapyrus::SCRIPT_ERR_OK
          expect(i.error.code).to eq(expected_err_code) unless extra_result
        end
      end
    end
  end

  describe '#eval' do
    it 'should be verified.' do
      script_pubkey = Tapyrus::Script.from_string('1 OP_ADD 7 OP_EQUAL')
      script_sig = Tapyrus::Script.from_string('6')
      expect(Tapyrus::ScriptInterpreter.eval(script_sig, script_pubkey)).to be true
    end
  end

  def build_credit_tx(script_pubkey, amount)
    tx = Tapyrus::Tx.new
    tx.features = 1
    tx.lock_time = 0
    coinbase = Tapyrus::Script.new << 0 << 0
    tx.inputs << Tapyrus::TxIn.new(out_point: Tapyrus::OutPoint.create_coinbase_outpoint, script_sig: coinbase)
    tx.outputs << Tapyrus::TxOut.new(script_pubkey: script_pubkey, value: amount)
    tx
  end

  def build_spending_tx(script_sig, locked_tx, amount)
    tx = Tapyrus::Tx.new
    tx.features = 1
    tx.lock_time = 0
    tx.inputs << Tapyrus::TxIn.new(out_point: Tapyrus::OutPoint.from_txid(locked_tx.txid, 0), script_sig: script_sig)
    tx.outputs << Tapyrus::TxOut.new(script_pubkey: Tapyrus::Script.new, value: amount)
    tx
  end

  def find_error_code(error_code)
    error_code = 'SIG_NULLFAIL' if error_code == 'NULLFAIL'
    Tapyrus::ScriptError.name_to_code('SCRIPT_ERR_' + error_code)
  end
end
