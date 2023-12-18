require 'spec_helper'

describe Tapyrus::TIP0137 do
  class Stub
    include Tapyrus::TIP0137
  end

  before { Tapyrus.chain_params = :prod }

  after { Tapyrus.chain_params = :dev }

  let(:txid) { '6632d4a28c6f33bd29d32857ffcba6e3021c2fdeb9c792edb742955006a99dbd' }
  let(:index) { 1 }
  let(:value) { 1 }
  let(:color_id) do
    Tapyrus::Color::ColorIdentifier.parse_from_payload(
      'c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46'.htb
    )
  end
  let(:script_pubkey) do
    Tapyrus::Script.parse_from_payload(
      '21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac'
        .htb
    )
  end
  let(:address) { 'w26x2EaheVBsceNf9RufpmmZ1i1qLBux1UMKMs16dkcZxjwnb69aA3oVApMjjUqSp3SEgmqkNuu4mS' }
  let(:message) { '0102030405060708090a0b0c0d0e0f' }

  describe '#sign_message!' do
    subject do
      Stub.new.sign_message!(
        key,
        txid: txid,
        index: index,
        value: value,
        color_id: color_id,
        script_pubkey: script_pubkey,
        address: address,
        message: message
      )
    end

    let(:key) { Tapyrus::Key.new(priv_key: '1111111111111111111111111111111111111111111111111111111111111111') }

    it do
      expect(subject).to match(
        "eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ\.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ\..*"
      )
    end

    it 'can be decoded to original payload' do
      json = Tapyrus::JWS.decode(subject)
      expect(json[0]).to eq(
        {
          'txid' => txid,
          'index' => index,
          'color_id' => color_id.to_hex,
          'value' => value,
          'script_pubkey' => script_pubkey.to_hex,
          'address' => address,
          'message' => message
        }
      )
      expect(json[1]['typ']).to eq 'JWT'
      expect(json[1]['alg']).to eq 'ES256K'
      expect(json[1]['jwk']['keys'][0]['kty']).to eq 'EC'
      expect(json[1]['jwk']['keys'][0]['crv']).to eq 'P-256K'
      expect(json[1]['jwk']['keys'][0]['alg']).to eq 'ES256K'
    end

    context 'txid is invalid' do
      let(:txid) { '00' * 31 }

      it { expect { subject }.to raise_error(ArgumentError, 'txid is invalid') }
    end

    context 'index is invalid(is not integer)' do
      let(:index) { '0x0a' }

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'index is invalid(negative integer)' do
      let(:index) { -1 }

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'index is invalid(too large)' do
      let(:index) { 2**32 }

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'value is invalid(is not integer)' do
      let(:value) { '0x0a' }

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'value is invalid(negative integer)' do
      let(:value) { -1 }

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'value is invalid(too large)' do
      let(:value) { 2**64 }

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'color_id is nil' do
      let(:color_id) { nil }

      it { expect { subject }.not_to raise_error }
    end
    context 'color_id is invalid(too long)' do
      let(:color_id) do
        Tapyrus::Color::ColorIdentifier.parse_from_payload(
          'c1000000000000000000000000000000000000000000000000000000000000000000'.htb
        )
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id is invalid') }
    end

    context 'color_id is invalid(too short)' do
      let(:color_id) do
        Tapyrus::Color::ColorIdentifier.parse_from_payload(
          'c100000000000000000000000000000000000000000000000000000000000000'.htb
        )
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id is invalid') }
    end

    context 'script_pubkey is invalid' do
      let(:script_pubkey) { 'invalid script_pubkey' }

      it do
        expect { subject }.to raise_error(
          ArgumentError,
          'script_pubkey is invalid. scirpt_pubkey must be a hex string and its type must be p2pkh or cp2pkh'
        )
      end
    end

    context 'script_pubkey is p2sh' do
      let(:script_pubkey) { Tapyrus::Script.to_p2sh('7620a79e8657d066cff10e21228bf983cf546ac6') }

      it do
        expect { subject }.to raise_error(
          ArgumentError,
          'script_pubkey is invalid. scirpt_pubkey must be a hex string and its type must be p2pkh or cp2pkh'
        )
      end
    end

    context 'script_pubkey is cp2sh' do
      let(:script_pubkey) { Tapyrus::Script.to_p2sh('7620a79e8657d066cff10e21228bf983cf546ac6').add_color(color_id) }

      it do
        expect { subject }.to raise_error(
          ArgumentError,
          'script_pubkey is invalid. scirpt_pubkey must be a hex string and its type must be p2pkh or cp2pkh'
        )
      end
    end

    context 'script_pubkey is op_return' do
      let(:script_pubkey) { Tapyrus::Script.new << Tapyrus::Script::OP_RETURN }

      it do
        expect { subject }.to raise_error(
          ArgumentError,
          'script_pubkey is invalid. scirpt_pubkey must be a hex string and its type must be p2pkh or cp2pkh'
        )
      end
    end

    context 'address is invalid' do
      let(:address) { 'invalid address' }

      it { expect { subject }.to raise_error(ArgumentError, 'address is invalid') }
    end

    context 'message is invalid' do
      let(:message) { 'invalid message' }

      it { expect { subject }.to raise_error(ArgumentError, 'message is invalid. message must be a hex string') }
    end

    context 'address is not derived from scriptPubkey' do
      let(:address) { 'mo6CPsdW8EsnWdmSSCrQ6225VVDtpMBTug' }

      it do
        expect { subject }.to raise_error(
          ArgumentError,
          'address is invalid. An address should be derived from scriptPubkey'
        )
      end
    end

    context 'key is invalid' do
      let(:key) { Tapyrus::Key.new(priv_key: '22' * 32) }

      it { expect { subject }.to raise_error(ArgumentError, 'key is invalid') }
    end
  end

  describe '#verify_message!' do
    subject { Stub.new.verify_message!(jws, client: client) }

    let(:jws) do
      'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.XTUVWDYqVOkdClgLgwlIxiHEqjA7ELhiHKHhc6G8VAofcggKdkqL2kia-aUDiy1_LxheF2K0lhJta2phG_UyVA'
    end

    let(:client) { nil }

    it do
      expect(subject[0]).to eq(
        {
          'txid' => txid,
          'index' => index,
          'color_id' => color_id.to_hex,
          'value' => value,
          'script_pubkey' => script_pubkey.to_hex,
          'address' => address,
          'message' => message
        }
      )
      expect(subject[1]['typ']).to eq 'JWT'
      expect(subject[1]['alg']).to eq 'ES256K'
      expect(subject[1]['jwk']['keys'][0]['kty']).to eq 'EC'
      expect(subject[1]['jwk']['keys'][0]['crv']).to eq 'P-256K'
      expect(subject[1]['jwk']['keys'][0]['alg']).to eq 'ES256K'
    end

    context 'p2pkh key' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMzU1MWNkN2VkODRjOWRiZTc3YmMxNGY5OTQyODI5ZDI5MmU5NzkxMDM5ZGM2ZmM3YTY0YmFhN2I4MTkwZmMwYyIsImluZGV4IjowLCJjb2xvcl9pZCI6bnVsbCwidmFsdWUiOjYwMCwic2NyaXB0X3B1YmtleSI6Ijc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjFRMXBFNXZQR0VFTXFSY1ZSTWJ0Qks4NDJZNlB6bzZuSzkiLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.6UlEknf_oVWE6eGQnRLW0gV-NYIYWc-VssL22aVXwWlqIlHW6uTxiNOzTR-_8fKbFMQ8-j5wECidI8kAUC4oSQ'
      end
      let(:txid) { '3551cd7ed84c9dbe77bc14f9942829d292e9791039dc6fc7a64baa7b8190fc0c' }
      let(:index) { 0 }
      let(:value) { 600 }
      let(:script_pubkey) do
        Tapyrus::Script.parse_from_payload('76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac'.htb)
      end
      let(:address) { '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9' }

      it do
        expect(subject[0]).to eq(
          {
            'txid' => txid,
            'index' => index,
            'value' => value,
            'color_id' => nil,
            'script_pubkey' => script_pubkey.to_hex,
            'address' => address,
            'message' => message
          }
        )
        expect(subject[1]['typ']).to eq 'JWT'
        expect(subject[1]['alg']).to eq 'ES256K'
        expect(subject[1]['jwk']['keys'][0]['kty']).to eq 'EC'
        expect(subject[1]['jwk']['keys'][0]['crv']).to eq 'P-256K'
        expect(subject[1]['jwk']['keys'][0]['alg']).to eq 'ES256K'
      end
    end

    context 'invalid signature' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      end

      it { expect { subject }.to raise_error(JWT::VerificationError) }
    end

    context 'no jwk header' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOltdfSwiYWxnIjoiSFMyNTYifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.O72HoJLXPCzAh5tAtWM3DNczKDLihiucEW29YwA1mDA'
      end

      it { expect { subject }.to raise_error(Tapyrus::JWS::DecodeError, 'No jwk key found in header') }
    end

    context 'jwk kty is not EC' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsImNydiI6IlAtMjU2SyIsIngiOiJUelZiM0xmTUN2Y283enpPdVdGZGtHaEx0YkxLWDRXYXNQQzNCQWRZY2FvIiwieSI6Ik9GdHJHNDZ0Z0p5bWRGVFphRF9QSzZBMFZ0Yi1MRXEtS3dmdy05dXk4Y0UiLCJ1c2UiOiJzaWciLCJhbGciOiJFUzI1NksiLCJraWQiOiJlNzVkNGNhMjc3ODczN2MxNDA0ZjUzNGQxNDY1ZTJjZDQ2YmIxZjcxZGY4NmM2MWQ3Yzk0MTNlNWNhMWFhNjkwIn1dfSwiYWxnIjoiRVMyNTZLIn0.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.A9gj1VgmmtbvOdn3kb-5HvEytYoyR2ZwgyWcBNzlVF_DNtLAdj3Cka8-oK_PFPQMPzMtS-S4x4JWiNiw2yeKqQ'
      end

      it { expect { subject }.to raise_error(Tapyrus::JWS::DecodeError, 'kty must be "EC"') }
    end

    context 'jwk crv is not P-256K' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVHpWYjNMZk1DdmNvN3p6T3VXRmRrR2hMdGJMS1g0V2FzUEMzQkFkWWNhbyIsInkiOiJPRnRyRzQ2dGdKeW1kRlRaYURfUEs2QTBWdGItTEVxLUt3ZnctOXV5OGNFIiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTZLIiwia2lkIjoiZTc1ZDRjYTI3Nzg3MzdjMTQwNGY1MzRkMTQ2NWUyY2Q0NmJiMWY3MWRmODZjNjFkN2M5NDEzZTVjYTFhYTY5MCJ9XX0sImFsZyI6IkVTMjU2SyJ9.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.ZYSwqhs7OXgZ48FQeE0_J1eJ9nCVK8GbSDxfFMeq1WZDbssTdS4LEPuArPKT4ZmhDHoHc8rK6E1b_ty4lwgW0g'
      end

      it { expect { subject }.to raise_error(Tapyrus::JWS::DecodeError, 'crv must be "P-256K"') }
    end

    context 'jwk use is not sig' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6ImVuYyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.NgpLxxM0WMF0V9D6v5gR_vtTQQq49qqlNoIZAurGWF3xGIz7ET00MP0JgPVn_H5oQrHU_JQHecCV2uSBdIi9PQ'
      end

      it { expect { subject }.to raise_error(Tapyrus::JWS::DecodeError, 'use must be "sig"') }
    end

    context 'jwk alg is not ES256K' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTNTEyIiwia2lkIjoiZTc1ZDRjYTI3Nzg3MzdjMTQwNGY1MzRkMTQ2NWUyY2Q0NmJiMWY3MWRmODZjNjFkN2M5NDEzZTVjYTFhYTY5MCJ9XX0sImFsZyI6IkVTMjU2SyJ9.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.sgeC-P-ZuVH16NMyQWV2cglnaG3HCE13OCp9Oga6TPP7ej93hTq9i0NXAu1UoYMf_CNy1cCz0Y1hvrZc84qyUQ'
      end

      it { expect { subject }.to raise_error(Tapyrus::JWS::DecodeError, 'alg must be "ES256K"') }
    end

    context 'txid is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJpbmRleCI6MSwiY29sb3JfaWQiOiJjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDYiLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiJ3MjZ4MkVhaGVWQnNjZU5mOVJ1ZnBtbVoxaTFxTEJ1eDFVTUtNczE2ZGtjWnhqd25iNjlhQTNvVkFwTWpqVXFTcDNTRWdtcWtOdXU0bVMiLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.p0q40TnUiopfOHw_1bdkZxSwsbBdvXr2n1cTcraQbR3xe2dBFZyH24IJO9C9Vc1do52pvB1-8oA_RuEjaJAvDQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'txid is invalid') }
    end

    context 'index is invalid(is not integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoiMHgwYSIsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoidzI2eDJFYWhlVkJzY2VOZjlSdWZwbW1aMWkxcUxCdXgxVU1LTXMxNmRrY1p4anduYjY5YUEzb1ZBcE1qalVxU3AzU0VnbXFrTnV1NG1TIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.llQTHFfaqJbNWkylcmYZoZQ0ynRzOZLrWsr1T119jgg6J3f4A31q8NrUUoYqavdL0EnnsnFYgmxX9jCNZ52fUQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'index is invalid(negative integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjotMSwiY29sb3JfaWQiOiJjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDYiLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiJ3MjZ4MkVhaGVWQnNjZU5mOVJ1ZnBtbVoxaTFxTEJ1eDFVTUtNczE2ZGtjWnhqd25iNjlhQTNvVkFwTWpqVXFTcDNTRWdtcWtOdXU0bVMiLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.thibsuExXUH_b2iLXnJXYJfKR4byjMP85IrD-zHWNgHezMN4IqIv3kyGy2iAo3V1o0DbD_O3I6qDe16JpeqfkQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'index is invalid(too large)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4Ijo0Mjk0OTY3Mjk2LCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.p6kPC55M-lnl5fNzbCoMGu-MKu75druqNl-HfenN2aUQYLh8ZI4ucZ9Si7Yiwav7vrPyaNv0mEhNtx8opU2Hvg'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'value is invalid(is not integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoiMHgwYSIsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoidzI2eDJFYWhlVkJzY2VOZjlSdWZwbW1aMWkxcUxCdXgxVU1LTXMxNmRrY1p4anduYjY5YUEzb1ZBcE1qalVxU3AzU0VnbXFrTnV1NG1TIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.4mnvC7v9cYoE7zDeMlw59jHd4EhAqfjFf9d7HfBDtIfRH9oVX0C5EsqaSCk2yVsbTNf26Qw1nAML-HDueCcumw'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'value is invalid(negative integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjotMSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiJ3MjZ4MkVhaGVWQnNjZU5mOVJ1ZnBtbVoxaTFxTEJ1eDFVTUtNczE2ZGtjWnhqd25iNjlhQTNvVkFwTWpqVXFTcDNTRWdtcWtOdXU0bVMiLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.NaweC1HmRHEBpm6taAEc7BOCuh5ZNE8RFxauZzkWctru5P0Cn7SuDRn-J02QVmh_qr7Zo8QnPEH-Vz0Ni-2hQQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'value is invalid(too large)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxODQ0Njc0NDA3MzcwOTU1MTYxNiwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiJ3MjZ4MkVhaGVWQnNjZU5mOVJ1ZnBtbVoxaTFxTEJ1eDFVTUtNczE2ZGtjWnhqd25iNjlhQTNvVkFwTWpqVXFTcDNTRWdtcWtOdXU0bVMiLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.x4zYD0dlrJ-OcCsTXtEKCEKP9llSCGjmHSKB-Z8BnQmPoakf6dkNPa4Q9eWQCdpNXQ6Z32GOrno51gNaSp6anw'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'color_id is nil' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6bnVsbCwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoidzI2eDJFYWhlVkJzY2VOZjlSdWZwbW1aMWkxcUxCdXgxVU1LTXMxNmRrY1p4anduYjY5YUEzb1ZBcE1qalVxU3AzU0VnbXFrTnV1NG1TIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.TcH2HrKoQ-IW5VrYtjdjK3cR3lnv8g6GzkvMc8hE94V_SB__1Wa-kSyF7gX6TfjRbfc715GtL6dIcrzrwBrjSA'
      end

      it { expect(subject[0]['color_id']).to be_nil }
    end

    context 'color_id is invalid(too long)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoidzI2eDJFYWhlVkJzY2VOZjlSdWZwbW1aMWkxcUxCdXgxVU1LTXMxNmRrY1p4anduYjY5YUEzb1ZBcE1qalVxU3AzU0VnbXFrTnV1NG1TIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.wi6hH2A9mw5QLleYyuWHHZ_-0jtqS81GFat2nc3o3FVB35kY_5o1TbqJ4knqEmwi-5j4Al_Tz1CIxfaf39Dw-w'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id is invalid') }
    end

    context 'color_id is invalid(too short)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiJ3MjZ4MkVhaGVWQnNjZU5mOVJ1ZnBtbVoxaTFxTEJ1eDFVTUtNczE2ZGtjWnhqd25iNjlhQTNvVkFwTWpqVXFTcDNTRWdtcWtOdXU0bVMiLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.EQkOr12eGkFKcpd2wpdaJEsB7ek8SOw54rgrbhOH-7V-62vfAjlgTz8l4FGZstiqhu3YcR_jfGvo7_gDsaptdg'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id is invalid') }
    end

    context 'color_id does not equal to colorId in scriptPubkey' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMxZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.MQtACOMgsiAI14IayWdwrWlgrGdzNRIcYY0C7Z0AICWI_OvdaDfULmD4ZEZrO4e_vP1epv2zkumiSKd0QdZxaQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id should be equal to colorId in scriptPubkey') }
    end

    context 'script_pubkey is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiaW52YWxpZCBzY3JpcHQiLCJhZGRyZXNzIjoidzI2eDJFYWhlVkJzY2VOZjlSdWZwbW1aMWkxcUxCdXgxVU1LTXMxNmRrY1p4anduYjY5YUEzb1ZBcE1qalVxU3AzU0VnbXFrTnV1NG1TIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.GvEsrg9aR4vPFPY0R9meb95zWEIbyMYsIxjwcHfcCe-lTalpylc4GrHLZ8Dnz7q-1LOabo0oyvLHghEkuJYcsA'
      end

      it do
        expect { subject }.to raise_error(
          ArgumentError,
          'script_pubkey is invalid. scirpt_pubkey must be a hex string and its type must be p2pkh or cp2pkh'
        )
      end
    end

    context 'script_pubkey is p2sh' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6bnVsbCwidmFsdWUiOjYwMCwic2NyaXB0X3B1YmtleSI6ImE5MTQ3NjIwYTc5ZTg2NTdkMDY2Y2ZmMTBlMjEyMjhiZjk4M2NmNTQ2YWM2ODciLCJhZGRyZXNzIjoiM0NUY241OXVKODl3Q3NRYmVpeThBR0x5ZFhFOW1oNllyciIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.uxcDHG43kriYHhE24_JJh4uoCfd-tThQ7yvAjtaDkNboA7K7NHybb9GL8q_AFYsSUKeJLN5NN57WtcrfMjWYkw'
      end

      it do
        expect { subject }.to raise_error(
          ArgumentError,
          'script_pubkey is invalid. scirpt_pubkey must be a hex string and its type must be p2pkh or cp2pkh'
        )
      end
    end

    context 'script_pubkey is cp2sh' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiY2E5MTQ3NjIwYTc5ZTg2NTdkMDY2Y2ZmMTBlMjEyMjhiZjk4M2NmNTQ2YWM2ODciLCJhZGRyZXNzIjoiNGEyOEY1WmVoUU5hTXNTQ0V6QkdRU0tqVngyV3oyYzRzMzJqb2ltUGNpRlRMemM3QVVxc2ZnMnhob0JxOE5BakVwUk5GTlVyQVpycEVIQiIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.WRaoHKGSgjuNqpEbGaoXWJs3DAus5XTtbyVd-AP00dSrS8WJjQ8l4xvtrZL_LNFY2B3pImdPX1mwC2HnC2dAEg'
      end

      it do
        expect { subject }.to raise_error(
          ArgumentError,
          'script_pubkey is invalid. scirpt_pubkey must be a hex string and its type must be p2pkh or cp2pkh'
        )
      end
    end

    context 'address is nil' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.QBC8kpSWfSYpfyYjpkzCfHt0y4mT-p3Z23Dmw30fEiO6cxg-nHHwWL0gyJ7kutkw27U_vSWi2F8pI6uGq8h4Ww'
      end

      it { expect(subject[0]['address']).to be_nil }
    end

    context 'address is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6ImludmFsaWQgYWRkcmVzcyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.B6A4b_6TZNm2oT5uhDORvvyz8YhHFfh1_Lvjg2tUzt3pq3RHgMCGtLCPuqczGxzz3OSgNWJCPrmu5ddnyOqVUQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'address is invalid') }
    end

    context 'address is not derived from scriptPubkey' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6Im1vNkNQc2RXOEVzbldkbVNTQ3JRNjIyNVZWRHRwTUJUdWciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.Ok3q7uxHC4I2VHuB5F6RGbq5CoVftP868tdbhfB1XU3DULEBidC2LsRLD1QdmTZ00kVSW8XvtVEKz7365kK_HA'
      end

      it do
        expect { subject }.to raise_error(
          ArgumentError,
          'address is invalid. An address should be derived from scriptPubkey'
        )
      end
    end

    context 'key is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlJtMV95dVZqNWNzSm9OR0hDN1dBTkVnRVlYaDVvVWxKenlJb1h4dXVQeWMiLCJ5IjoiWnlnWGJEeGtNZmp1MmtVNDNEZklaZUo0VHpxZWQ5QkU4ejVBZDVmaEo0byIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6IjYxNmIwM2FjM2U0ODllZGQzN2RlZGEzYzFkOTgxNTYwYzllZmVlYWE1ZTA2ZTlkOTJiOWUwOGExNmJiYTQ0NDYifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.iXkT5afc-QniCNpKArKfcYFAxiaLvJhK5IXV2P2_OHFx_sEY0KWMCv_nI1HLs7JD5wwos7QyfN1Wc209t_rUFg'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'key is invalid') }
    end

    context 'message is nil' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyJ9.2DnNz1XkGdLQ6uF_j5fkIU4UkjS2wcFGh5TEy1GTojglfGwBYMH9a3U1IwEwdvaN_eBgglHRU2hZ1l4ImFEidw'
      end

      it { expect(subject[0]['message']).to be_nil }
    end

    context 'message is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiJpbnZhbGlkIG1lc3NhZ2UifQ.tEfEmZXrpu6ViGaxGn4WsoH_o-xNl-MxJP2mcMgrthDRRDExX92BJMMikco_7l76lUadyObKSPtPdTvzPkURzg'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'message is invalid. message must be a hex string') }
    end

    context 'client specified' do
      let(:client) { Tapyrus::RPC::TapyrusCoreClient.new }
      let(:rpc) { instance_double('rpc') }

      before do
        allow(Tapyrus::RPC::TapyrusCoreClient).to receive(:new).and_return(rpc)
        allow(rpc).to receive(:getrawtransaction) do |txid|
          '01000000000201000000000000003c21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac01000000000000003c21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000'
        end
      end

      context 'valid' do
        it { expect { subject }.not_to raise_error }
      end

      context 'txid is not in blockchain' do
        it do
          allow(rpc).to receive(:getrawtransaction).and_raise(Tapyrus::RPC::Error.new('500', nil, nil))
          expect { subject }.to raise_error(Tapyrus::RPC::Error)
        end
      end

      context 'tx output is not in blockchain' do
        it do
          allow(rpc).to receive(:getrawtransaction) do |txid|
            Tapyrus::Tx.new.to_hex
          end
          expect { subject }.to raise_error(ArgumentError, 'output not found in blockchain')
        end
      end

      context 'color_id does not match in blockchain' do
        it do
          allow(rpc).to receive(:getrawtransaction) do |txid|
            '01000000000201000000000000003c21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac01000000000000003c21c3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbc76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000'
          end
          expect { subject }.to raise_error(
            ArgumentError,
            'color_id of transaction in blockchain is not match to one in the signed message'
          )
        end
      end

      context 'script_pubkey does not match in blockchain' do
        it do
          allow(rpc).to receive(:getrawtransaction) do |txid|
            '01000000000201000000000000003c21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac01000000000000003c21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a914ffffffffffffffffffffffffffffffffffffffff88ac00000000'
          end
          expect { subject }.to raise_error(
            ArgumentError,
            'script_pubkey of transaction in blockchain is not match to one in the signed message'
          )
        end
      end

      context 'value does not match in blockchain' do
        it do
          allow(rpc).to receive(:getrawtransaction) do |txid|
            '01000000000201000000000000003c21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac02000000000000003c21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000'
          end
          expect { subject }.to raise_error(
            ArgumentError,
            'value of transaction in blockchain is not match to one in the signed message'
          )
        end
      end
    end
  end

  describe '#verify_message' do
    subject { Stub.new.verify_message(jws, client: client) }

    let(:jws) do
      'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.XTUVWDYqVOkdClgLgwlIxiHEqjA7ELhiHKHhc6G8VAofcggKdkqL2kia-aUDiy1_LxheF2K0lhJta2phG_UyVA'
    end

    let(:client) { nil }

    it { expect(subject).to eq true }

    context 'invalid signature' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiNjYzMmQ0YTI4YzZmMzNiZDI5ZDMyODU3ZmZjYmE2ZTMwMjFjMmZkZWI5Yzc5MmVkYjc0Mjk1NTAwNmE5OWRiZCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IncyNngyRWFoZVZCc2NlTmY5UnVmcG1tWjFpMXFMQnV4MVVNS01zMTZka2NaeGp3bmI2OWFBM29WQXBNampVcVNwM1NFZ21xa051dTRtUyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      end

      it { expect(subject).to eq false }
    end
  end
end
