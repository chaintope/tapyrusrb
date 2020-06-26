require 'spec_helper'
include Tapyrus::Opcodes

describe Tapyrus::Script do

  describe '#append_data' do
    context 'data < 0xff' do
      subject { Tapyrus::Script.new << 'foo' }
      it 'should be append' do
        expect(subject.to_hex).to eq('02f880')
      end
    end
    context '0xff < data < 0xffff' do
      subject { Tapyrus::Script.new << 'f' * 256 }
      it 'should be append' do
        expect(subject.to_hex).to eq('4c80ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
      end
    end
    context 'int value include' do
      it 'should be append' do
        s = Tapyrus::Script.new << OP_1NEGATE << Tapyrus::Script.encode_number(1000) << OP_ADD
        expect(s.to_hex).to eq('4f02e80393')
        expect(s.to_s).to eq('OP_1NEGATE 1000 OP_ADD')
        s = Tapyrus::Script.new << OP_1NEGATE << Tapyrus::Script.encode_number(100) << OP_ADD
        expect(s.to_hex).to eq('4f016493')
        # negative value
        s = Tapyrus::Script.new << OP_1NEGATE << Tapyrus::Script.encode_number(-1000) << OP_ADD
        expect(s.to_hex).to eq('4f02e88393')
        expect(s.to_s).to eq('OP_1NEGATE -1000 OP_ADD')
      end
    end
    context 'binary and hex mixed' do
      it 'should be append as same data' do
        hex = 'f9fc751cb7dc372406a9f8d738d5e6f8f63bab71986a39cf36ee70ee17036d07'
        expect(Tapyrus::Script.new << hex).to eq(Tapyrus::Script.new << hex.htb)
      end
    end
  end

  describe 'p2pk script' do
    subject {
      Tapyrus::Script.new << '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35' << OP_CHECKSIG
    }
    it 'should be p2pk' do
      expect(subject.get_pubkeys).to eq(['032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35'])
    end
  end

  describe 'p2pkh script' do
    subject { Tapyrus::Script.to_p2pkh('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0') }

    context 'prod', network: :prod do
      it 'should be generate P2PKH script' do
        expect(subject.to_payload.bytesize).to eq(25)
        expect(subject.to_payload).to eq('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb)
        expect(subject.to_s).to eq('OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG')
        expect(subject.p2pkh?).to be true
        expect(subject.p2sh?).to be false
        expect(subject.multisig?).to be false
        expect(subject.op_return?).to be false
        expect(subject.standard?).to be true
        expect(subject.addresses.first).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
        expect(subject.get_pubkeys).to eq([])
      end
    end

    context 'dev' do
      it 'should be generate P2PKH script' do
        expect(subject.addresses.first).to eq('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
      end
    end
  end

  describe 'p2sh script' do
    subject {
      k1 = '021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9'
      k2 = '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35'
      Tapyrus::Script.to_p2sh_multisig_script(1, [k1, k2])
    }
    context 'prod', network: :prod do
      it 'should be generate P2SH script' do
        expect(subject.length).to eq(2)
        expect(subject[0].to_hex).to eq('a9147620a79e8657d066cff10e21228bf983cf546ac687')
        expect(subject[0].to_s).to eq('OP_HASH160 7620a79e8657d066cff10e21228bf983cf546ac6 OP_EQUAL')
        expect(subject[0].p2pkh?).to be false
        expect(subject[0].p2sh?).to be true
        expect(subject[0].multisig?).to be false
        expect(subject[0].op_return?).to be false
        expect(subject[0].standard?).to be true
        expect(subject[0].addresses.first).to eq('3CTcn59uJ89wCsQbeiy8AGLydXE9mh6Yrr')
        expect(subject[1].to_hex).to eq('5121021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e921032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e3552ae')
        expect(subject[1].to_s).to eq('1 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 2 OP_CHECKMULTISIG')
        expect(subject[1].addresses).to eq(['1QDN1JzVYKRuscrPdWE6AUvTxev6TP1cF4', '1GKVcitjqJDjs7yEy19FSGZMu81xyey62J'])
        expect(subject[0].get_pubkeys).to eq([])
      end
    end

    context 'dev' do
      it 'should be generate P2SH script' do
        expect(subject[0].addresses.first).to eq('2N41pqp5vuafHQf39KraznDLEqsSKaKmrij')
        expect(subject[1].addresses).to eq(['n4jKJN5UMLsAejL1M5CTzQ8npeWoLBLCAH', 'mvqSumyieKezeESrga7dGBmgm7cfuATBvf'])
      end
    end
  end

  describe 'multisig script' do
    subject {
      k1 = '021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9'
      k2 = '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35'
      Tapyrus::Script.to_multisig_script(2, [k1, k2])
    }
    it 'should treat as multisig' do
      expect(subject.p2pkh?).to be false
      expect(subject.p2sh?).to be false
      expect(subject.multisig?).to be true
      expect(subject.op_return?).to be false
      expect(subject.standard?).to be true
      expect(subject.addresses).to eq(['n4jKJN5UMLsAejL1M5CTzQ8npeWoLBLCAH', 'mvqSumyieKezeESrga7dGBmgm7cfuATBvf'])
      expect(subject.get_pubkeys).to eq(['021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9', '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35'])
    end
  end

  describe 'op_return script' do
    context 'within MAX_OP_RETURN_RELAY' do
      subject {
        Tapyrus::Script.new << OP_RETURN << '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38'
      }
      it 'should treat as multisig' do
        expect(subject.p2pkh?).to be false
        expect(subject.p2sh?).to be false
        expect(subject.multisig?).to be false
        expect(subject.op_return?).to be true
        expect(subject.standard?).to be true
        expect(subject.op_return_data.bth).to eq('04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38')
        expect(subject.get_pubkeys).to eq([])
      end
    end

    context 'over MAX_OP_RETURN_RELAY' do
      subject {
        Tapyrus::Script.new << OP_RETURN << '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3800'
      }
      it 'should correct op_return, but not standard' do
        expect(subject.op_return?).to be true
        expect(subject.standard?).to be false
      end
    end

    context 'no op_return data' do
      subject {
        Tapyrus::Script.new << OP_RETURN
      }
      it 'should correct op_return and no data' do
        expect(subject.op_return?).to be true
        expect(subject.op_return_data).to be nil
      end
    end
  end

  describe 'cp2pkh script' do
    subject { Tapyrus::Script.to_cp2pkh(color, '46c2fbfbecc99a63148fa076de58cf29b0bcf0b0') }

    let(:color) { Tapyrus::Color::ColorIdentifier.nft(Tapyrus::OutPoint.new("01" * 32, 1))}

    it 'should be generate CP2PKH script' do
      expect(subject.to_payload.bytesize).to eq(60)
      expect(subject.to_hex).to eq('21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac')
      expect(subject.to_s).to eq('c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46 OP_COLOR OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG')
      expect(subject.p2pkh?).to be false
      expect(subject.p2sh?).to be false
      expect(subject.cp2pkh?).to be true
      expect(subject.cp2sh?).to be false
      expect(subject.multisig?).to be false
      expect(subject.op_return?).to be false
      expect(subject.standard?).to be false
      expect(subject.addresses.first).to eq('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
      expect(subject.get_pubkeys).to eq([])
    end

    context 'when color identifier is not specified' do
      let(:color) { nil }
      it { expect { subject }.to raise_error ArgumentError, 'Specified color identifier is invalid' }
    end

    context 'when color identifier is invalid' do
      let(:color) { Tapyrus::Color::ColorIdentifier.parse_from_payload("c4ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46") }
      it { expect { subject }.to raise_error ArgumentError, 'Specified color identifier is invalid' }
    end
  end

  describe 'cp2sh script' do
    subject { Tapyrus::Script.to_cp2sh(color, '7620a79e8657d066cff10e21228bf983cf546ac6') }

    let(:color) { Tapyrus::Color::ColorIdentifier.nft(Tapyrus::OutPoint.new("01" * 32, 1))}

    it 'should be generate CP2SH script' do
      expect(subject.to_payload.bytesize).to eq(58)
      expect(subject.to_hex).to eq('21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bca9147620a79e8657d066cff10e21228bf983cf546ac687')
      expect(subject.to_s).to eq('c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46 OP_COLOR OP_HASH160 7620a79e8657d066cff10e21228bf983cf546ac6 OP_EQUAL')
      expect(subject.p2pkh?).to be false
      expect(subject.p2sh?).to be false
      expect(subject.cp2pkh?).to be false
      expect(subject.cp2sh?).to be true
      expect(subject.multisig?).to be false
      expect(subject.op_return?).to be false
      expect(subject.standard?).to be false
      expect(subject.addresses.first).to eq('2N41pqp5vuafHQf39KraznDLEqsSKaKmrij')
      expect(subject.get_pubkeys).to eq([])
    end

    context 'when color identifier is not specified' do
      let(:color) { nil }
      it { expect { subject }.to raise_error ArgumentError, 'Specified color identifier is invalid' }
    end

    context 'when color identifier is invalid' do
      let(:color) { Tapyrus::Color::ColorIdentifier.parse_from_payload("c4ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46") }
      it { expect { subject }.to raise_error ArgumentError, 'Specified color identifier is invalid' }
    end
  end

  describe 'parse from payload' do
    context 'spendable' do
      subject { Tapyrus::Script.parse_from_payload('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb) }
      it 'should be parsed' do
        expect(subject.to_s).to eq('OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG')
        expect(subject.p2pkh?).to be true
      end
    end

    context 'unspendable' do
      subject { Tapyrus::Script.parse_from_payload('76a914c486de584a735ec2f22da7cd9681614681f92173d83d0aa68688ac'.htb) }
      it 'should be parsed' do
        expect(subject.to_hex).to eq('76a914c486de584a735ec2f22da7cd9681614681f92173d83d0aa68688ac')
        expect(subject.p2pkh?).to be false
        expect(subject.to_s).to eq('OP_DUP OP_HASH160 c486de584a735ec2f22da7cd9681614681f92173 OP_UNKNOWN [error]')
      end
    end
  end

  describe '#add_color' do
    subject { script.add_color(color) }

    let(:color) { Tapyrus::Color::ColorIdentifier.nft(Tapyrus::OutPoint.new("01" * 32, 1))}

    context 'for p2pkh' do
      let(:script) { Tapyrus::Script.to_p2pkh('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0') }

      it { expect(subject.to_hex).to eq '21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac' }
      it { expect(subject.cp2pkh?).to be_truthy }
      it { expect(subject.cp2sh?).to be_falsy }
    end
    context 'for p2sh' do
      let(:script) do
        k1 = '021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9'
        k2 = '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35'
        Tapyrus::Script.to_p2sh_multisig_script(1, [k1, k2])[0]
      end

      it { expect(subject.to_hex).to eq('21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bca9147620a79e8657d066cff10e21228bf983cf546ac687') }
      it { expect(subject.cp2pkh?).to be_falsy }
      it { expect(subject.cp2sh?).to be_truthy }
    end

    context 'for op_return' do
      let(:script) { Tapyrus::Script.new << OP_RETURN }

      it { expect { subject }.to raise_error }
    end

    context 'when color identifier is not specified' do
      let(:color) { nil }
      let(:script) { Tapyrus::Script.to_p2pkh('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0') }

      it { expect { subject }.to raise_error ArgumentError, 'Specified color identifier is invalid' }
    end

    context 'when color identifier is invalid' do
      let(:color) { Tapyrus::Color::ColorIdentifier.parse_from_payload("c4ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46") }
      let(:script) { Tapyrus::Script.to_p2pkh('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0') }

      it { expect { subject }.to raise_error ArgumentError, 'Specified color identifier is invalid' }
    end
  end

  describe '#from_string' do
    it 'should be generate' do
      p2pkh = Tapyrus::Script.from_string('OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG')
      expect(p2pkh.to_payload).to eq('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb)
      expect(p2pkh.to_s).to eq('OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG')

      p2sh = Tapyrus::Script.from_string('1 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 2 OP_CHECKMULTISIG')
      expect(p2sh.to_s).to eq('1 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 2 OP_CHECKMULTISIG')
      expect(p2sh.to_payload).to eq('5121021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e921032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e3552ae'.htb)

      pushdata = Tapyrus::Script.from_string('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0')
      expect(pushdata.to_s).to eq('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0')
      expect(pushdata.to_payload).to eq('1446c2fbfbecc99a63148fa076de58cf29b0bcf0b0'.htb)

      contract = Tapyrus::Script.from_string('OP_HASH160 b6ca66aa538d28518852b2104d01b8b499fc9b23 OP_EQUAL OP_IF 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 OP_ELSE 1000 OP_CHECKSEQUENCEVERIFY OP_DROP 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 OP_ENDIF OP_CHECKSIG')
      expect(contract.to_hex).to eq('a914b6ca66aa538d28518852b2104d01b8b499fc9b23876321021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e96702e803b27521032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e3568ac')
      expect(contract.to_s).to eq('OP_HASH160 b6ca66aa538d28518852b2104d01b8b499fc9b23 OP_EQUAL OP_IF 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 OP_ELSE 1000 OP_CSV OP_DROP 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 OP_ENDIF OP_CHECKSIG')
    end
  end

  describe '#push_only?' do
    it 'should be judged' do
      expect(Tapyrus::Script.new.push_only?).to be true
      expect(Tapyrus::Script.from_string('0 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0').push_only?).to be true
      expect(Tapyrus::Script.from_string('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUAL').push_only?).to be false
      expect(Tapyrus::Script.from_string('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0').push_only?).to be true
      expect(Tapyrus::Script.from_string('3044022009ea34cf915708efa8d0fb8a784d4d9e3108ca8da4b017261dd029246c857ebc02201ae570e2d8a262bd9a2a157f473f4089f7eae5a8f54ff9f114f624557eda742001 02effb2edfcf826d43027feae226143bdac058ad2e87b7cec26f97af2d357ddefa').push_only?).to be true
    end
  end

  describe '#encode_number' do
    it 'should be encoded' do
      expect(Tapyrus::Script.encode_number(1000)).to eq('e803')
      expect(Tapyrus::Script.encode_number(100)).to eq('64')
      expect(Tapyrus::Script.encode_number(-1000)).to eq('e883')
      expect(Tapyrus::Script.encode_number(127)).to eq('7f')
      expect(Tapyrus::Script.encode_number(128)).to eq('8000')
      expect(Tapyrus::Script.encode_number(129)).to eq('8100')
      expect(Tapyrus::Script.encode_number(-127)).to eq('ff')
      expect(Tapyrus::Script.encode_number(-128)).to eq('8080')
      expect(Tapyrus::Script.encode_number(-129)).to eq('8180')
      expect(Tapyrus::Script.encode_number(0)).to eq('')
    end
  end

  describe '#decode_number' do
    it 'should be decoded' do
      expect(Tapyrus::Script.decode_number('e803')).to eq(1000)
      expect(Tapyrus::Script.decode_number('64')).to eq(100)
      expect(Tapyrus::Script.decode_number('e883')).to eq(-1000)
      expect(Tapyrus::Script.decode_number('7f')).to eq(127)
      expect(Tapyrus::Script.decode_number('8000')).to eq(128)
      expect(Tapyrus::Script.decode_number('8100')).to eq(129)
      expect(Tapyrus::Script.decode_number('ff')).to eq(-127)
      expect(Tapyrus::Script.decode_number('8080')).to eq(-128)
      expect(Tapyrus::Script.decode_number('8180')).to eq(-129)
      expect(Tapyrus::Script.decode_number('')).to eq(0)
    end
  end

  describe '#subscript' do
    subject {
      Tapyrus::Script.new << OP_DUP << OP_HASH160 << 'pubkeyhash' << OP_EQUALVERIFY << OP_CHECKSIG
    }
    it 'should be split' do
      expect(subject.subscript(0..-1)).to eq(subject)
      expect(subject.subscript(3..-1)).to eq(Tapyrus::Script.new << OP_EQUALVERIFY << OP_CHECKSIG)
    end
  end

  describe '#find_and_delete' do
    it 'should be delete' do
      s = Tapyrus::Script.new << OP_1 << OP_2
      d = Tapyrus::Script.new
      expect(s.find_and_delete(d)).to eq(s)

      s = Tapyrus::Script.new << OP_1 << OP_2 << OP_3
      d = Tapyrus::Script.new << OP_2
      expect(s.find_and_delete(d)).to eq(Tapyrus::Script.new << OP_1 << OP_3)

      s = Tapyrus::Script.new << OP_3 << OP_1 << OP_3 << OP_3 << OP_4 << OP_3
      d = Tapyrus::Script.new << OP_3
      expect(s.find_and_delete(d)).to eq(Tapyrus::Script.new << OP_1 << OP_4)

      s = Tapyrus::Script.parse_from_payload('0302ff03'.htb) # PUSH 0x02ff03 onto stack
      d = Tapyrus::Script.parse_from_payload('0302ff03'.htb)
      expect(s.find_and_delete(d)).to eq(Tapyrus::Script.new)

      s = Tapyrus::Script.parse_from_payload('0302ff030302ff03'.htb) # PUSH 0x2ff03 PUSH 0x2ff03
      d = Tapyrus::Script.parse_from_payload('0302ff03'.htb)
      expect(s.find_and_delete(d)).to eq(Tapyrus::Script.new)

      s = Tapyrus::Script.parse_from_payload('0302ff030302ff03'.htb)
      d = Tapyrus::Script.parse_from_payload('02'.htb)
      expect(s.find_and_delete(d)).to eq(s) # find_and_delete matches entire opcodes

      s = Tapyrus::Script.parse_from_payload('0302ff030302ff03'.htb)
      d = Tapyrus::Script.parse_from_payload('ff'.htb)
      expect(s.find_and_delete(d)).to eq(s)

      # This is an odd edge case: strip of the push-three-bytes prefix, leaving 02ff03 which is push-two-bytes:
      s = Tapyrus::Script.parse_from_payload('0302ff030302ff03'.htb)
      d = Tapyrus::Script.parse_from_payload('03'.htb)
      expect(s.find_and_delete(d)).to eq(Tapyrus::Script.new << 'ff03' << 'ff03')

      # Byte sequence that spans multiple opcodes:
      s = Tapyrus::Script.parse_from_payload('02feed5169'.htb) # PUSH(0xfeed) OP_1 OP_VERIFY
      d = Tapyrus::Script.parse_from_payload('feed51'.htb)
      expect(s.find_and_delete(d)).to eq(s) # doesn't match 'inside' opcodes

      s = Tapyrus::Script.parse_from_payload('02feed5169'.htb) # PUSH(0xfeed) OP_1 OP_VERIFY
      d = Tapyrus::Script.parse_from_payload('02feed51'.htb)
      expect(s.find_and_delete(d)).to eq(Tapyrus::Script.parse_from_payload('69'.htb))

      s = Tapyrus::Script.parse_from_payload('516902feed5169'.htb)
      d = Tapyrus::Script.parse_from_payload('feed51'.htb)
      expect(s.find_and_delete(d)).to eq(s)

      s = Tapyrus::Script.parse_from_payload('516902feed5169'.htb) # PUSH(0xfeed) OP_1 OP_VERIFY
      d = Tapyrus::Script.parse_from_payload('02feed51'.htb)
      expect(s.find_and_delete(d)).to eq(Tapyrus::Script.parse_from_payload('516969'.htb))

      s = Tapyrus::Script.new << OP_0 << OP_0 << OP_1 << OP_1
      d = Tapyrus::Script.new << OP_0 << OP_1
      expect(s.find_and_delete(d)).to eq(Tapyrus::Script.new << OP_0 << OP_1)

      s = Tapyrus::Script.new << OP_0 << OP_0 << OP_1 << OP_0 << OP_1 << OP_1
      d = Tapyrus::Script.new << OP_0 << OP_1
      expect(s.find_and_delete(d)).to eq(Tapyrus::Script.new << OP_0 << OP_1)

      s = Tapyrus::Script.parse_from_payload('0003feed'.htb)
      d = Tapyrus::Script.parse_from_payload('03feed'.htb)
      expect(s.find_and_delete(d)).to eq(Tapyrus::Script.parse_from_payload('00'.htb))

      s = Tapyrus::Script.parse_from_payload('0003feed'.htb)
      d = Tapyrus::Script.parse_from_payload('00'.htb)
      expect(s.find_and_delete(d)).to eq(Tapyrus::Script.parse_from_payload('03feed'.htb))
    end
  end

  describe '#delete_opcode' do
    it 'should be delete target opcode' do
      script = Tapyrus::Script.from_string('038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 OP_CHECKSIGVERIFY OP_CODESEPARATOR 038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 OP_CHECKSIGVERIFY OP_CODESEPARATOR 1')
      expect(script.delete_opcode(Tapyrus::Opcodes::OP_CODESEPARATOR).to_s).to eq('038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 OP_CHECKSIGVERIFY 038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 OP_CHECKSIGVERIFY 1')
    end
  end

  describe '#parse_from_addr' do
    context 'prod', network: :prod do
      it 'should generate script' do
        # P2PKH
        expect(Tapyrus::Script.parse_from_addr('191arn68nSLRiNJXD8srnmw4bRykBkVv6o')).to eq(Tapyrus::Script.parse_from_payload('76a91457dd450aed53d4e35d3555a24ae7dbf3e08a78ec88ac'.htb))
        # P2SH
        expect(Tapyrus::Script.parse_from_addr('3HG15Tn6hEd1WVR1ySQtWRstTbvyy6B5V8')).to eq(Tapyrus::Script.parse_from_payload('a914aac6e837af9eba6951552e83862740b069cf59f587'.htb))
      end
    end

    context 'dev' do
      it 'should generate script' do
        # P2PKH
        expect(Tapyrus::Script.parse_from_addr('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')).to eq(Tapyrus::Script.parse_from_payload('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb))
        # P2SH
        expect(Tapyrus::Script.parse_from_addr('2N3wh1eYqMeqoLxuKFv8PBsYR4f8gYn8dHm')).to eq(Tapyrus::Script.parse_from_payload('a914755874542a017c665184c356f67c20cf4a0621ca87'.htb))
      end
    end

    context 'invalid address' do
      it 'should raise error' do
        expect{Tapyrus::Script.parse_from_addr('191arn68nSLRiNJXD8srnmw4bRykBkVv6o')}.to raise_error
        expect{Tapyrus::Script.parse_from_addr('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F2')}.to raise_error
        expect{Tapyrus::Script.parse_from_addr('bc1q2lw52zhd202wxhf42k3y4e7m70sg578ver73dn')}.to raise_error
        expect{Tapyrus::Script.parse_from_addr('tb1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607sajrpy0')}.to raise_error
      end
    end
  end

  describe '#include?' do
    it 'should be judge' do
      # P2PKH
      p2pkh = Tapyrus::Script.parse_from_payload('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb)
      pubkey_hash = '46c2fbfbecc99a63148fa076de58cf29b0bcf0b0'
      expect(p2pkh.include?(pubkey_hash)).to be true
      expect(p2pkh.include?(pubkey_hash.htb)).to be true
      expect(p2pkh.include?('46c2fbfbecc99a63148fa076de58cf29b0bcf0b1')).to be false
      expect(p2pkh.include?(OP_EQUALVERIFY)).to be true
      expect(p2pkh.include?(OP_EQUAL)).to be false
      # multisig
      multisig = Tapyrus::Script.parse_from_payload('5121021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e921032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e3552ae'.htb)
      expect(multisig.include?(OP_1)).to be true
      expect(multisig.include?(OP_3)).to be false
      expect(multisig.include?('032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35')).to be true
    end
  end

  describe '#run' do
    context 'valid script' do
      subject {Tapyrus::Script.from_string('6 1 OP_ADD 7 OP_EQUAL')}
      it 'should return true.' do
        expect(subject.run).to be true
      end
    end

    context 'invalid script' do
      subject {Tapyrus::Script.from_string('3 1 OP_ADD 7 OP_EQUAL')}
      it 'should return false.' do
        expect(subject.run).to be false
      end
    end
  end

end
