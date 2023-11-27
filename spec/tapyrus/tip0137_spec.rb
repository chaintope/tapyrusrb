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
  let(:data) { '0102030405060708090a0b0c0d0e0f' }

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
        data: data
      )
    end

    let(:key) { Tapyrus::Key.new(priv_key: '1111111111111111111111111111111111111111111111111111111111111111') }

    it do
      payload = {
        txid: txid,
        index: index,
        color_id: color_id.to_hex,
        value: value,
        script_pubkey: script_pubkey.to_hex,
        address: address,
        data: data
      }
      expect(subject).to match(
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ\.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9\..*"
      )
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

      it { expect { subject }.to raise_error(ArgumentError, 'script_pubkey is invalid') }
    end

    context 'script_pubkey is p2sh' do
      let(:script_pubkey) {  Tapyrus::Script.to_p2sh('7620a79e8657d066cff10e21228bf983cf546ac6') }

      it { expect { subject }.to raise_error(ArgumentError, 'script_pubkey is invalid') }
    end

    context 'script_pubkey is cp2sh' do
      let(:script_pubkey) {  Tapyrus::Script.to_p2sh('7620a79e8657d066cff10e21228bf983cf546ac6').add_color(color_id) }

      it { expect { subject }.to raise_error(ArgumentError, 'script_pubkey is invalid') }
    end

    context 'script_pubkey is op_return' do
      let(:script_pubkey) {  Tapyrus::Script.new << Tapyrus::Script::OP_RETURN }

      it { expect { subject }.to raise_error(ArgumentError, 'script_pubkey is invalid') }
    end

    context 'address is invalid' do
      let(:address) { 'invalid address' }

      it { expect { subject }.to raise_error(ArgumentError, 'address is invalid') }
    end

    context 'data is invalid' do
      let(:data) { 'invalid data' }

      it { expect { subject }.to raise_error(ArgumentError, 'data is invalid') }
    end
  end

  describe '#verify_message!' do
    subject { Stub.new.verify_message!(jws, key, client: client) }

    let(:key) { Tapyrus::Key.new(pubkey: '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa') }

    let(:jws) do
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.s08khWD9aixrUHWcqNVXRH5lRDAnvTYbQDHBx1qr1kyTIru9HE2hxZo0q-ANcXj4O4WMZGS6xZe5BPLc1Uat5g'
    end

    let(:client) { nil }

    it do
      expect(subject).to eq(
        [
          {
            'txid' => txid,
            'index' => index,
            'color_id' => color_id.to_hex,
            'value' => value,
            'script_pubkey' => script_pubkey.to_hex,
            'address' => address,
            'data' => data
          },
          { 'alg' => 'ES256K', 'typ' => 'JWT' }
        ]
      )
    end

    context 'invalid signature' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.' + 'eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIw' +
          'MTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEw' + 'MTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEw' +
          'MTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNl' + 'YzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhk' +
          'YWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYw' + 'YjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXki' +
          'OiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMz' + 'OTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUz' +
          'NjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRl' + 'ZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4' +
          'YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdz' + 'blBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpW' +
          'MU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2' + 'WDRZUkciLCJkYXRhIjoiMDEwMjAzMDQwNTA2MDcw' +
          'ODA5MGEwYjBjMGQwZTBmIn0.AAAAAAAAAAAAAAAA' + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + 'AAAAAAAAA'
      end

      it { expect { subject }.to raise_error(JWT::VerificationError) }
    end

    context 'txid is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.' + 'eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiI' +
          'wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD' +
          'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.nSwKx7CVbjd3KFEE-7BFmmVRE_o5BUxL04ZSpoWjfgx-ED0OEDiHu4llM8KQTpPyr9q9PNTM96Pe9aKNBRontw'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'txid is invalid') }
    end

    context 'index is invalid(is not integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOiIweDBhIiwiY29sb3JfaWQiOiJjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDYiLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsImRhdGEiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.lC6n-QmF5f5H8AXuv0YW1nu4bzkuh0l35S29B6gt3weWKsWA06jOrhF8P2jPdNYsiT3kALt1YhhI33Llw_tBkg'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'index is invalid(negative integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOi0xLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.7tJkLcWiVqr0Zp6GJTVgbizPgsd3ep9_P6nOu_LqVMCZtgegZ9y0naTol-JWaVnCEsS7ZJ10gh3a6hc5G6SAvA'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'index is invalid(too large)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjQyOTQ5NjcyOTYsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJkYXRhIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.nzuXviCNRkgzDiTYbw5qh-2l-jZTZwupFIqFLUdIghK58m_BQhR_IICOJ23GOweZQmaSiSvdvTLGvDKfpDlhAQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'value is invalid(is not integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOiIweDBhIiwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsImRhdGEiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.ocxHYJ37bl7aX5sXzdFAuo1Le3PlQgaAfp5Jo5kpTtDt3I75jR6khBK7oUDYfihibTC2PIisut-ktp6xXfpQhQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'value is invalid(negative integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOi0xLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.GRX-P9JerF3NG71EtNTJ_NWi2ILKf174FX_0da14EvL0vjv1tGsvmAEpj5Lifv7XB39BYCZLiOVEprHKoeCTSQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'value is invalid(too large)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjE4NDQ2NzQ0MDczNzA5NTUxNjE2LCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.SmqXfAttjME9L_mpXPzRpKyIQbzD1MQ4RKUhAVUPtl7UawaaLmcUtAURrsKOkm5v5javz-GxM5xKfnjhosksXw'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'color_id is nil' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6bnVsbCwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJkYXRhIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.fIC8n6hNIOccSnyQYLk-zO00M9qv8JNLtSglY8JS9xWAh-nL0y5KyAlpHjEMVD0YDJ9dPa3lSlYGN1OPw3xm8A'
      end

      it { expect(subject[0]["color_id"]).to be_nil }
    end

    context 'color_id is invalid(too long)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiIzxUYXB5cnVzOjpDb2xvcjo6Q29sb3JJZGVudGlmaWVyOjB4MDAwMDAwMDEwNTE0YzZiMD4iLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsImRhdGEiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.6He2KBiekfl_auaG8wSkM2TgHBMQXxAGvKR0TNclYN99yF4Y5xZW5pSfHGA4CZJmvzs7fELr2l7hPYvdBxUIDA'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id is invalid') }
    end

    context 'color_id is invalid(too short)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiIzxUYXB5cnVzOjpDb2xvcjo6Q29sb3JJZGVudGlmaWVyOjB4MDAwMDAwMDEwNTFiNTJhMD4iLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsImRhdGEiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.oRGFSAuIcJb_9uOfW81Yg1Rw6l1kkp0YIrlMO8Z6wGjF0FmzdJn37kwW9AjxUQkA5RZsy0qc-tLnGoLCadCTTg'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id is invalid') }
    end

    context 'script_pubkey is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOm51bGwsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsImRhdGEiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.7dpSE4n10SXIJAAnv1m0uARajzSCqNKf-f9icl_247zqCl7IZX9oSNWiY0m9KlxHi3hXFMs2VKNwTjoRjz08lw'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'script_pubkey is invalid') }
    end

    context 'script_pubkey is not p2pkh either cp2pkh' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiYTkxNDc2MjBhNzllODY1N2QwNjZjZmYxMGUyMTIyOGJmOTgzY2Y1NDZhYzY4NyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.BJA-TPrt-eDPEBY1ydjZjtmDgic-SnoOPnNB5_j7Ci-gE2uQVMocjCdVynV9gR57BqDqS0bWiduZQBE0uxODig'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'script_pubkey is invalid') }
    end


    context 'address is nil' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6bnVsbCwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.fClXQ8gsmHlFfOHmmkGINwUAZ--ZlCi66lao0V0efoC3FH8ExVlLVOcgX-Fmhn4Ch3-5eUPTIv0opK2S2PZnuQ'
      end

      it { expect(subject[0]["address"]).to be_nil }
    end

    context 'address is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiaW52YWxpZCBhZGRyZXNzIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.6tudFQaX7EaZkoo916T1olmoHkpn4tamQqtAJQvj2xoRvf-vxHaMYzoZJ8ylaKTvvSWd9vyoDXwhMz1v3WuL1Q'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'address is invalid') }
    end

    context 'data is nil' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6bnVsbH0.34dj7jiRatGR_jrPDGQoQcJG3kdPvcfO0LAMee8zL_HOHyxPfS0M7cFrCEsVQZJzG0b-gjt8eyWY6E3DQO802Q'
      end

      it { expect(subject[0]["data"]).to be_nil }
    end

    context 'data is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJkYXRhIjoiaW52YWxpZCBkYXRhIn0.osdRksPRPn1Pe5iQwFz09gzw5-IpeJzYfkKwHwu1x3bF5FthVfTIU5ivKfH0wrdy5BVyc92zkHJRYWPNfeOohQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'data is invalid') }
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
    subject { Stub.new.verify_message(jws, key, client: client) }

    let(:key) { Tapyrus::Key.new(pubkey: '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa') }

    let(:jws) do
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.jyDfXwow8xqflxqrIb0t8dpI9iO1QaXHF2Ca_olal8yOu61ON3KDG-k-Nz0AVUzFXTQQ89yOz3FBMC0su9V0Eg'
    end

    let(:client) { nil }

    it { expect(subject).to eq true }

    context 'invalid signature' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.' + 'eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIw' +
          'MTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEw' + 'MTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEw' +
          'MTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNl' + 'YzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhk' +
          'YWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYw' + 'YjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXki' +
          'OiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMz' + 'OTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUz' +
          'NjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRl' + 'ZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4' +
          'YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdz' + 'blBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpW' +
          'MU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2' + 'WDRZUkciLCJkYXRhIjoiMDEwMjAzMDQwNTA2MDcw' +
          'ODA5MGEwYjBjMGQwZTBmIn0.AAAAAAAAAAAAAAAA' + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + 'AAAAAAAAA'
      end

      it { expect(subject).to eq false }
    end
  end
end
