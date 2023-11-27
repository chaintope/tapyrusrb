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
      payload = {
        txid: txid,
        index: index,
        color_id: color_id.to_hex,
        value: value,
        script_pubkey: script_pubkey.to_hex,
        address: address,
        message: message
      }
      expect(subject).to match(
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ\.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9\..*"
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
      let(:script_pubkey) { Tapyrus::Script.to_p2sh('7620a79e8657d066cff10e21228bf983cf546ac6') }

      it { expect { subject }.to raise_error(ArgumentError, 'script_pubkey is invalid') }
    end

    context 'script_pubkey is cp2sh' do
      let(:script_pubkey) { Tapyrus::Script.to_p2sh('7620a79e8657d066cff10e21228bf983cf546ac6').add_color(color_id) }

      it { expect { subject }.to raise_error(ArgumentError, 'script_pubkey is invalid') }
    end

    context 'script_pubkey is op_return' do
      let(:script_pubkey) { Tapyrus::Script.new << Tapyrus::Script::OP_RETURN }

      it { expect { subject }.to raise_error(ArgumentError, 'script_pubkey is invalid') }
    end

    context 'address is invalid' do
      let(:address) { 'invalid address' }

      it { expect { subject }.to raise_error(ArgumentError, 'address is invalid') }
    end

    context 'message is invalid' do
      let(:message) { 'invalid message' }

      it { expect { subject }.to raise_error(ArgumentError, 'message is invalid') }
    end
  end

  describe '#verify_message!' do
    subject { Stub.new.verify_message!(jws, key, client: client) }

    let(:key) { Tapyrus::Key.new(pubkey: '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa') }

    let(:jws) do
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.jyDfXwow8xqflxqrIb0t8dpI9iO1QaXHF2Ca_olal8yOu61ON3KDG-k-Nz0AVUzFXTQQ89yOz3FBMC0su9V0Eg'
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
            'message' => message
          },
          { 'alg' => 'ES256K', 'typ' => 'JWT' }
        ]
      )
    end

    context 'invalid signature' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJkYXRhIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      end

      it { expect { subject }.to raise_error(JWT::VerificationError) }
    end

    context 'txid is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJpbmRleCI6MSwiY29sb3JfaWQiOiJjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDYiLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.9Q-HQsPZJ4XjGwl-KLFPDixg5A6_oFbEWJYARJadKiEr4NWqDeUbgXGoYBO6dghU0_294Pab_V9FiWK4cykZ4Q'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'txid is invalid') }
    end

    context 'index is invalid(is not integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoiMHgwYSIsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.6A1MLJ5bO5SnwMzZpE-dNd8ngfwxFKDj5GQ7NR5FR60vt-Etq8SF9IyFMrPIv5F7y6rwE7Rf30mLQg3NdJT4YQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'index is invalid(negative integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjotMSwiY29sb3JfaWQiOiJjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDYiLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.YafWtSGrih0d0GxbB-liJR0-FcuFiMVT4iguuQblWXO8YYGmZvp-p4KTxmS4QR5cctB8lBgyBxmJXs_kac2xSA'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'index is invalid(too large)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4Ijo0Mjk0OTY3Mjk2LCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.WilsjrBUGldFuwJltag9Kd9Z54BVztPAkWDW_Uiy31anlmWqwwXBO5Qt5TTjUZ4t3ToENVQOqT5DSVx8DSTVuQ'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'index is invalid') }
    end

    context 'value is invalid(is not integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoiMHgwYSIsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.f_5qPQ3cGukjaFJEjaZIIc7WNlTIhdk8llUGfw12TmZKNDY0bUYvbveROlgKdaiS8amwzoyvK84TQ3GTcNSI5A'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'value is invalid(negative integer)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjotMSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.jjv0FxBxfS_GwqgLFCWXQWBrBKsZOZOTHhPeXyRFh35I4Xp-nBdn0LWt550BwmJ3CvyglktRnNbo4kadVmy3HA'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'value is invalid(too large)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxODQ0Njc0NDA3MzcwOTU1MTYxNiwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.ykghYL3EaqJxUxEJv38DvlzdDuqCcZI2QMjI_qlUyxiPaWyWuR2fnft2E16rQ9hnE5wnNCMrwiCVdHBJfm-rcA'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'value is invalid') }
    end

    context 'color_id is nil' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6bnVsbCwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.aWLtOGxFjHB_V2z0VrU034PWHXheCl8OTXDnuEmShtRq2RHRNqPTKZnRt2SIrDuhLjz9TlaiPMr3JkCPXKPvMA'
      end

      it { expect(subject[0]['color_id']).to be_nil }
    end

    context 'color_id is invalid(too long)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.mI90_BgXgwydaxV_XyV00rz36x7_e25wdKkxiYeIyu9DN0VSItWYWXz37phx7Jj1HOz9YpADXpARwYBXL4nirg'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id is invalid') }
    end

    context 'color_id is invalid(too short)' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.oPTUwzJpg3KWYVpd33Ua9AJ4U4WsXfHfukb7AhKbSrfWCxHlk6q6PN6nkOf6CzxyHTAPw1is2--ULnlhbStqvw'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'color_id is invalid') }
    end

    context 'script_pubkey is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiaW52YWxpZCBzY3JpcHQiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJtZXNzYWdlIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.5Q_MgE0t9DV3Zpp1QO9A8tgSc140mKONbMK569UsLrITxj5262LSBFsQ6FOw7l0veQUsvZPJZ2vG6nZv7alA0w'
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
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6bnVsbCwibWVzc2FnZSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.ZFKG3aoIAydKHFmf3ddMFSQJoYWeCwgw_OgucszQzPOwlHtskeHsR2bXAWiWS3uh9C0wJm24CaaEwJGTCm4F3Q'
      end

      it { expect(subject[0]['address']).to be_nil }
    end

    context 'address is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6ImludmFsaWQgYWRkcmVzcyIsIm1lc3NhZ2UiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.6RK9Nmo5FLfoC8oL1aaTbCa-W8KvlIg2jFp7Ql6PkwXkz2X8kX163BRpHcqlm9kpMRtoc-8RaRa4guBmyfmY7Q'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'address is invalid') }
    end

    context 'message is nil' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6bnVsbH0.4PdrfgMfAX-wZIHe_C721kw7AG_nYG0jdV7mWH4xAKQdo1-i39lK9Lb04DHtzf19CIRv1nC9CHy1-xs2P6cjrA'
      end

      it { expect(subject[0]['message']).to be_nil }
    end

    context 'message is invalid' do
      let(:jws) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwibWVzc2FnZSI6ImludmFsaWQgbWVzc2FnZSJ9.wjkRggCMdmCfwzu6DRUm8snNXUHw6oWjf4fxklpcvWWXJaDi1Ku9NROLLcdBreKpc4jW8u9NavAMbO9zkIklEA'
      end

      it { expect { subject }.to raise_error(ArgumentError, 'message is invalid') }
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
