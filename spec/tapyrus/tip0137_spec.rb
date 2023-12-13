require 'spec_helper'

describe Tapyrus::TIP0137 do
  class Stub
    include Tapyrus::TIP0137
  end

  let(:txid) { '01' * 32 }
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
  let(:address) { '22VdQ5VjWcF9zgsnPQodFBS1PBQPaAQEXSofkyMv2D9zV1MdNheaAy7sroTg52mwW5apNhxPqB6X4YRG' }
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
        "eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ\.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9\..*"
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
      'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.AwYx36tlBYnKfr77n3sv7aonrgQztNqPc1q_le049BLNeyBPWP3DS_sd84IgFVcn0YaVXJGEDnvBaPc1mUlsRg'
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

    context 'invalid signature' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      end

      it { expect { subject }.to raise_error(JWT::VerificationError) }
    end

    context 'no jwk header' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOltdfSwiYWxnIjoiSFMyNTYifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6ImludmFsaWQgYWRkcmVzcyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.O72HoJLXPCzAh5tAtWM3DNczKDLihiucEW29YwA1mDA'
      end

      it { expect { subject }.to raise_error(JWT::DecodeError, 'No jwk key found in header') }
    end

    context 'jwk kty is not EC' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsImNydiI6IlAtMjU2SyIsIngiOiJUelZiM0xmTUN2Y283enpPdVdGZGtHaEx0YkxLWDRXYXNQQzNCQWRZY2FvIiwieSI6Ik9GdHJHNDZ0Z0p5bWRGVFphRF9QSzZBMFZ0Yi1MRXEtS3dmdy05dXk4Y0UiLCJ1c2UiOiJzaWciLCJhbGciOiJFUzI1NksiLCJraWQiOiJlNzVkNGNhMjc3ODczN2MxNDA0ZjUzNGQxNDY1ZTJjZDQ2YmIxZjcxZGY4NmM2MWQ3Yzk0MTNlNWNhMWFhNjkwIn1dfSwiYWxnIjoiRVMyNTZLIn0.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.A9gj1VgmmtbvOdn3kb-5HvEytYoyR2ZwgyWcBNzlVF_DNtLAdj3Cka8-oK_PFPQMPzMtS-S4x4JWiNiw2yeKqQ'
      end

      it { expect { subject }.to raise_error(JWT::DecodeError, 'kty must be "EC"') }
    end

    context 'jwk crv is not P-256K' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVHpWYjNMZk1DdmNvN3p6T3VXRmRrR2hMdGJMS1g0V2FzUEMzQkFkWWNhbyIsInkiOiJPRnRyRzQ2dGdKeW1kRlRaYURfUEs2QTBWdGItTEVxLUt3ZnctOXV5OGNFIiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTZLIiwia2lkIjoiZTc1ZDRjYTI3Nzg3MzdjMTQwNGY1MzRkMTQ2NWUyY2Q0NmJiMWY3MWRmODZjNjFkN2M5NDEzZTVjYTFhYTY5MCJ9XX0sImFsZyI6IkVTMjU2SyJ9.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.ZYSwqhs7OXgZ48FQeE0_J1eJ9nCVK8GbSDxfFMeq1WZDbssTdS4LEPuArPKT4ZmhDHoHc8rK6E1b_ty4lwgW0g'
      end

      it { expect { subject }.to raise_error(JWT::DecodeError, 'crv must be "P-256K"') }
    end

    context 'jwk use is not sig' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6ImVuYyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.NgpLxxM0WMF0V9D6v5gR_vtTQQq49qqlNoIZAurGWF3xGIz7ET00MP0JgPVn_H5oQrHU_JQHecCV2uSBdIi9PQ'
      end

      it { expect { subject }.to raise_error(JWT::DecodeError, 'use must be "sig"') }
    end

    context 'jwk alg is not ES256K' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTNTEyIiwia2lkIjoiZTc1ZDRjYTI3Nzg3MzdjMTQwNGY1MzRkMTQ2NWUyY2Q0NmJiMWY3MWRmODZjNjFkN2M5NDEzZTVjYTFhYTY5MCJ9XX0sImFsZyI6IkVTMjU2SyJ9.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.sgeC-P-ZuVH16NMyQWV2cglnaG3HCE13OCp9Oga6TPP7ej93hTq9i0NXAu1UoYMf_CNy1cCz0Y1hvrZc84qyUQ'
      end

      it { expect { subject }.to raise_error(JWT::DecodeError, 'alg must be "ES256K"') }
    end

    context 'txid is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJpbmRleCI6MSwiY29sb3JfaWQiOiJjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDYiLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ._zOOMdu5q6X9kVn0z3ByGbBCvesxMVFEWzJstCNEab0WhYZK4WyWgQweIIPuLIKrMwg2w2hWYjEI_29vW1oQgw'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'txid is invalid') }
    end

    context 'index is invalid(is not integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoiMHgwYSIsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.f2It-n5frz6mj-Abm9SVkqG5IR-MtJYPtIhCNftSRu9hmfG8qxUntBXMVMsNKItww25ksAHxh244Gk1Daglvbg'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'index is invalid(negative integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjotMSwiY29sb3JfaWQiOiJjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDYiLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.dHkYfC2sl3JULNB837BT5kyDF6U5dZcdllez5_knBkUQoIn84mBceoPx7CxsJoP-l2KX1uXWZCxtPL06LJwmUg'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'index is invalid(too large)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4Ijo0Mjk0OTY3Mjk2LCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.6NZOkHqQeFoZD_QctWlXwEV7GH4XMbtVg8zRFPDyRbSpevnULJ1h8e-luls5-eAuZ4HBYlfMEft5sGlcXW7S8A'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'value is invalid(is not integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoiMHgwYSIsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.s3idamS92itXPuuMgyUv-A27rprzrGIDACCuQ_VxehzWtPyCt4XgCAvEEDj3vLRNyvYxdyw7TBYN33MzhL5efA'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'value is invalid(negative integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjotMSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.EjgLGuDB3aGChFIM0K76VB2gTI-FDdNzo9wSG02lb6Hq5dYE3Dn-4TWF_AKBM24pergX7hew0jMBGGNqCB2iPQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'value is invalid(too large)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxODQ0Njc0NDA3MzcwOTU1MTYxNiwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.x43P5v38EZ7r9iRsWYdYFmcf9bo_fGF5MMFTwMGli8-Ey6RB6p-tGYvdcBM3E7-NMZJ0esjh2IznbDlSsO-_Pw'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'color_id is nil' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6bnVsbCwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.Jg2s2u1_GHoQBNuCKWLVtYtOiSqgwQ3A9EnFXPfYe20FNMVTCEC72Xl9M-eNdKMkSoIFy_oJS0DjZ6muXzu9yw'
      end

      it { expect(subject[0]['color_id']).to be_nil }
    end

    context 'color_id is invalid(too long)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.RvOi_c2E76djvS0y4nwqZlX8QKMrvVIQ7bcvNNZW5vh5eZuozkyjeWOl_srSHu0NzVCSph5YE41gn5WQpz3D1g'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id is invalid') }
    end

    context 'color_id is invalid(too short)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.z1v8GQW86Of5-7ko2pbjgNwjhY2wHcf9PIzcNuC1lWv1JlRFOXxpDz5pGzhnISZs6U_Jwu7-jdGdTw7LukJ7_Q'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id is invalid') }
    end

    context 'color_id does not equal to colorId in scriptPubkey' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.LBDLgt-xvEfUARasdEsvHX061th0l2e6Z9hwYOrSunTfY9aA7HSenHMRDfWAC_FYhqnZjAO134l2k5Kt_qEYNA'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id should be equal to colorId in scriptPubkey') }
    end

    context 'script_pubkey is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiaW52YWxpZCBzY3JpcHQiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.driR253pbdYrEhBeqd4NogkHmd7gQEpLX_tXVC6rMpmt_oieef16OFoch-z_3GNZt3qsojLKj_e2gxrboufQeA'
      end

      it do
        expect { subject }.to raise_error(
          ArgumentError,
          'script_pubkey is invalid. scirpt_pubkey must be a hex string and its type must be p2pkh or cp2pkh'
        )
      end
    end

    context 'script_pubkey is not p2pkh either cp2pkh' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiYTkxNDc2MjBhNzllODY1N2QwNjZjZmYxMGUyMTIyOGJmOTgzY2Y1NDZhYzY4NyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.ONIE3_R2snr0s1y-iccXkPVxmfqo7HQQiKw_kslzChTHN8r5kZkxNpnee7kHeQxYKe2WJDkKeDnOgiwiFoZ2jg'
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
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.J1yjuQ3-B2T8prsTfss5scItvCW14gkeZT3QG1_o-iptX15hP2vYPF8-ZuaFl2M7MyFlQFKk1o3E6GqZ-cRriA'
      end

      it { expect(subject[0]['address']).to be_nil }
    end

    context 'address is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6ImludmFsaWQgYWRkcmVzcyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.SyHBxaDZdB5GCjoRhAHZC9JN_hQsOXGOT6apmgFGVo4FhRGzIgQy4Sww0wYRAbwPYne09CPeZYyz1JzObXE7Yg'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'address is invalid') }
    end

    context 'address is not derived from scriptPubkey' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMzU1MWNkN2VkODRjOWRiZTc3YmMxNGY5OTQyODI5ZDI5MmU5NzkxMDM5ZGM2ZmM3YTY0YmFhN2I4MTkwZmMwYyIsImluZGV4IjowLCJjb2xvcl9pZCI6bnVsbCwidmFsdWUiOjYwMCwic2NyaXB0X3B1YmtleSI6Ijc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6Im1vNkNQc2RXOEVzbldkbVNTQ3JRNjIyNVZWRHRwTUJUdWciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.LwaSb013UUFykd81t2vUx1dfA2si_yZCIw8KSkR5Os8n0Q9uw_iCFGUHo28louXjpv0ZgeCw_xIXdW4MwOpDjw'
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
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlJtMV95dVZqNWNzSm9OR0hDN1dBTkVnRVlYaDVvVWxKenlJb1h4dXVQeWMiLCJ5IjoiWnlnWGJEeGtNZmp1MmtVNDNEZklaZUo0VHpxZWQ5QkU4ejVBZDVmaEo0byIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6IjYxNmIwM2FjM2U0ODllZGQzN2RlZGEzYzFkOTgxNTYwYzllZmVlYWE1ZTA2ZTlkOTJiOWUwOGExNmJiYTQ0NDYifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMzU1MWNkN2VkODRjOWRiZTc3YmMxNGY5OTQyODI5ZDI5MmU5NzkxMDM5ZGM2ZmM3YTY0YmFhN2I4MTkwZmMwYyIsImluZGV4IjowLCJjb2xvcl9pZCI6bnVsbCwidmFsdWUiOjYwMCwic2NyaXB0X3B1YmtleSI6Ijc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6Im40WG1YOTFONUZmY2NZNjc4dmFHMUVMTnRYaDZza1ZFUzciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.9p9DikAcQ1ZWRGWrqRnhiyFtjETfSdJvB1fLf97GdaRDre1AvjXspf4sWV2sLLEXuuafxW_uev-rr7vCauMW0g'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'key is invalid') }
    end

    context 'message is nil' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIn0.YlM7LI1GTGRyR2Nc2gBtJoR-FD_3S3GUp-VTMah5XUoxg6usUrkmQaWUl54U4z6_4OMnGLkl_JsmAzLDDfQ9Kw'
      end

      it { expect(subject[0]['message']).to be_nil }
    end

    context 'message is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6ImludmFsaWQgbWVzc2FnZSJ9.REsTweTO1tGPqgy-IOwO5Plt5xi7wUDsdboJoar7eTGSQ4oHZonRWuKeBBFHW7ZInPCNkHXAalFMotVLUboM5Q'
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
      'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.AwYx36tlBYnKfr77n3sv7aonrgQztNqPc1q_le049BLNeyBPWP3DS_sd84IgFVcn0YaVXJGEDnvBaPc1mUlsRg'
    end

    let(:client) { nil }

    it { expect(subject).to eq true }

    context 'invalid signature' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGdvIjoiRVMyNTZLIiwiandrIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTZLIiwieCI6IlR6VmIzTGZNQ3Zjbzd6ek91V0Zka0doTHRiTEtYNFdhc1BDM0JBZFljYW8iLCJ5IjoiT0Z0ckc0NnRnSnltZEZUWmFEX1BLNkEwVnRiLUxFcS1Ld2Z3LTl1eThjRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImU3NWQ0Y2EyNzc4NzM3YzE0MDRmNTM0ZDE0NjVlMmNkNDZiYjFmNzFkZjg2YzYxZDdjOTQxM2U1Y2ExYWE2OTAifV19LCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      end

      it { expect(subject).to eq false }
    end
  end
end
