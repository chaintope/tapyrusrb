require 'spec_helper'
include Tapyrus::Opcodes
describe 'Tapyrus::Script::CheckDataSig' do
  let(:key) do
    Tapyrus::Key.new(priv_key: '0000000000000000000000000000000000000000000000000000000000000001', compressed: false)
  end
  let(:key_c) { Tapyrus::Key.new(priv_key: '0000000000000000000000000000000000000000000000000000000000000001') }

  describe 'checkdatasig test' do
    it 'should check data sig' do
      check(Tapyrus::Script.new, Tapyrus::Script.new << OP_CHECKDATASIG, Tapyrus::SCRIPT_ERR_INVALID_STACK_OPERATION)
      check(
        Tapyrus::Script.new << '00',
        Tapyrus::Script.new << OP_CHECKDATASIG,
        Tapyrus::SCRIPT_ERR_INVALID_STACK_OPERATION
      )
      check(
        Tapyrus::Script.new << '00' << '00',
        Tapyrus::Script.new << OP_CHECKDATASIG,
        Tapyrus::SCRIPT_ERR_INVALID_STACK_OPERATION
      )
      check(
        Tapyrus::Script.new,
        Tapyrus::Script.new << OP_CHECKDATASIGVERIFY,
        Tapyrus::SCRIPT_ERR_INVALID_STACK_OPERATION
      )
      check(
        Tapyrus::Script.new << '00',
        Tapyrus::Script.new << OP_CHECKDATASIGVERIFY,
        Tapyrus::SCRIPT_ERR_INVALID_STACK_OPERATION
      )
      check(
        Tapyrus::Script.new << '00' << '00',
        Tapyrus::Script.new << OP_CHECKDATASIGVERIFY,
        Tapyrus::SCRIPT_ERR_INVALID_STACK_OPERATION
      )

      message = ''
      digest = Tapyrus.sha256(message)
      pubkey = key.pubkey
      pubkey_c = key_c.pubkey
      pubkey_h = key.pubkey.htb
      pubkey_h[0] = '06'.htb
      pubkey_h[64] = (pubkey_h[64].bti & 1).itb
      pubkey_h = pubkey_h.bth

      check(
        Tapyrus::Script.new << '' << message << pubkey,
        Tapyrus::Script.new << OP_CHECKDATASIG,
        Tapyrus::SCRIPT_ERR_OK
      )
      check(
        Tapyrus::Script.new << '' << message << pubkey_c,
        Tapyrus::Script.new << OP_CHECKDATASIG,
        Tapyrus::SCRIPT_ERR_OK
      )
      check(
        Tapyrus::Script.new << '' << message << pubkey,
        Tapyrus::Script.new << OP_CHECKDATASIGVERIFY,
        Tapyrus::SCRIPT_ERR_CHECKDATASIGVERIFY
      )
      check(
        Tapyrus::Script.new << '' << message << pubkey_c,
        Tapyrus::Script.new << OP_CHECKDATASIGVERIFY,
        Tapyrus::SCRIPT_ERR_CHECKDATASIGVERIFY
      )

      sig_ecdsa = key.sign(digest)
      sig_schnorr = key.sign(digest, algo: :schnorr)
      expect(sig_ecdsa.bytesize > 64 && sig_ecdsa.bytesize <= 71).to be true
      expect(sig_schnorr.bytesize).to eq(64)

      check(Tapyrus::Script.new << sig_ecdsa << message << pubkey, Tapyrus::Script.new << OP_CHECKDATASIG, ['01'])
      check(
        Tapyrus::Script.new << sig_ecdsa << message << pubkey,
        Tapyrus::Script.new << OP_CHECKDATASIGVERIFY,
        Tapyrus::SCRIPT_ERR_OK
      )

      check(Tapyrus::Script.new << sig_schnorr << message << pubkey, Tapyrus::Script.new << OP_CHECKDATASIG, ['01'])
      check(
        Tapyrus::Script.new << sig_schnorr << message << pubkey,
        Tapyrus::Script.new << OP_CHECKDATASIGVERIFY,
        Tapyrus::SCRIPT_ERR_OK
      )

      minimal_sig = '3006020101020101'
      non_der_sig = '308006020101020101'
      high_s_sig =
        '304502203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022100ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485fcf2ce0d03b2ef0'

      script = Tapyrus::Script.new << OP_CHECKDATASIG << OP_NOT << OP_VERIFY
      script_verify = Tapyrus::Script.new << OP_CHECKDATASIGVERIFY

      # When strict encoding is enforced, hybrid key are invalid.
      check(Tapyrus::Script.new << '' << message << pubkey_h, script, Tapyrus::SCRIPT_ERR_PUBKEYTYPE)
      check(Tapyrus::Script.new << '' << message << pubkey_h, script_verify, Tapyrus::SCRIPT_ERR_PUBKEYTYPE)

      check(Tapyrus::Script.new << minimal_sig << message << pubkey, script, Tapyrus::SCRIPT_ERR_SIG_NULLFAIL)
      check(Tapyrus::Script.new << minimal_sig << message << pubkey, script_verify, Tapyrus::SCRIPT_ERR_SIG_NULLFAIL)

      check(Tapyrus::Script.new << sig_ecdsa << OP_1 << pubkey, script, Tapyrus::SCRIPT_ERR_SIG_NULLFAIL)
      check(Tapyrus::Script.new << sig_schnorr << OP_1 << pubkey, script, Tapyrus::SCRIPT_ERR_SIG_NULLFAIL)

      check(Tapyrus::Script.new << sig_ecdsa << OP_1 << pubkey, script_verify, Tapyrus::SCRIPT_ERR_SIG_NULLFAIL)
      check(Tapyrus::Script.new << sig_schnorr << OP_1 << pubkey, script_verify, Tapyrus::SCRIPT_ERR_SIG_NULLFAIL)

      # If we do enforce low S, then high S sigs are rejected.
      check(Tapyrus::Script.new << high_s_sig << message << pubkey, script, Tapyrus::SCRIPT_ERR_SIG_HIGH_S)
      check(Tapyrus::Script.new << high_s_sig << message << pubkey, script_verify, Tapyrus::SCRIPT_ERR_SIG_HIGH_S)

      check(Tapyrus::Script.new << non_der_sig << message << pubkey, script, Tapyrus::SCRIPT_ERR_SIG_DER)
      check(Tapyrus::Script.new << non_der_sig << message << pubkey, script_verify, Tapyrus::SCRIPT_ERR_SIG_DER)
    end
  end

  def check(original_stack, script, expected, flags = Tapyrus::STANDARD_SCRIPT_VERIFY_FLAGS)
    i = Tapyrus::ScriptInterpreter.new(flags: flags)
    i.eval_script(original_stack, :base, false)
    result = i.eval_script(script, :base, false)

    if result
      expect(i.stack).to eq(expected) unless expected == Tapyrus::SCRIPT_ERR_OK
    else
      expect(i.error.code).to eq(expected)
    end
  end
end
