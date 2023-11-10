require 'spec_helper'

describe Tapyrus::TIP0002 do
  class Stub
    include Tapyrus::TIP0002
  end

  let(:txid) { '01' * 32 }
  let(:index) { 1 }
  let(:value) { 1 }
  let(:color_id) { Tapyrus::Color::ColorIdentifier.parse_from_payload("c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46".htb) }
  let(:script_pubkey) { Tapyrus::Script.parse_from_payload("21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac".htb) }
  let(:address) { "22VdQ5VjWcF9zgsnPQodFBS1PBQPaAQEXSofkyMv2D9zV1MdNheaAy7sroTg52mwW5apNhxPqB6X4YRG" }
  let(:data) { "0102030405060708090a0b0c0d0e0f" }

  describe "#sign_message" do
    subject { Stub.new.sign_message(key, txid:, index:, color_id:, value:, script_pubkey:, address:, data:) }

    let(:key) { Tapyrus::Key.new(priv_key: "1111111111111111111111111111111111111111111111111111111111111111") }

    it do
      expect(subject).to match(
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ\.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9\..*"
      )
    end

    context 'txid is invalid' do
      let(:txid) { '00' * 31 }

      it { expect { subject }.to raise_error(RuntimeError, "txid is invalid") }
    end

    context 'index is invalid(is not integer)' do
      let(:index) { "0x0a" }

      it { expect { subject }.to raise_error(RuntimeError, "index is invalid") }
    end

    context 'index is invalid(negative integer)' do
      let(:index) { -1 }

      it { expect { subject }.to raise_error(RuntimeError, "index is invalid") }
    end

    context 'index is invalid(too large)' do
      let(:index) { 2 ** 32 }

      it { expect { subject }.to raise_error(RuntimeError, "index is invalid") }
    end

    context 'value is invalid(is not integer)' do
      let(:value) { "0x0a" }

      it { expect { subject }.to raise_error(RuntimeError, "value is invalid") }
    end

    context 'value is invalid(negative integer)' do
      let(:value) { -1 }

      it { expect { subject }.to raise_error(RuntimeError, "value is invalid") }
    end

    context 'value is invalid(too large)' do
      let(:value) { 2 ** 64 }

      it { expect { subject }.to raise_error(RuntimeError, "value is invalid") }
    end

    context 'color_id is invalid(too long)' do
      let(:color_id) { Tapyrus::Color::ColorIdentifier.parse_from_payload("c1000000000000000000000000000000000000000000000000000000000000000000".htb) }

      it { expect { subject }.to raise_error(RuntimeError, "color_id is invalid") }
    end

    context 'color_id is invalid(too short)' do
      let(:color_id) { Tapyrus::Color::ColorIdentifier.parse_from_payload("c100000000000000000000000000000000000000000000000000000000000000".htb) }

      it { expect { subject }.to raise_error(RuntimeError, "color_id is invalid") }
    end

    context 'script_pubkey is invalid' do
      let(:script_pubkey) { "invalid script_pubkey" }

      it { expect { subject }.to raise_error(RuntimeError, "script_pubkey is invalid") }
    end

    context 'address is invalid' do
      let(:address) { "invalid address" }

      it { expect { subject }.to raise_error(RuntimeError, "address is invalid") }
    end

    context 'data is invalid' do
      let(:data) { "invalid data" }

      it { expect { subject }.to raise_error(RuntimeError, "data is invalid") }
    end
  end

  describe "#verify_message" do
    subject { Stub.new.verify_message(jws, key) }

    let(:key) { Tapyrus::Key.new(pubkey: "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa") }

    let(:jws) do
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ0eGlkIjoiMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMSIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.s08khWD9aixrUHWcqNVXRH5lRDAnvTYbQDHBx1qr1kyTIru9HE2hxZo0q-ANcXj4O4WMZGS6xZe5BPLc1Uat5g"
    end

    it do
      expect(subject).to eq([{
        "txid" => txid, 
        "index" => index, 
        "color_id" => color_id.to_hex,
        "value" => value, 
        "script_pubkey" => script_pubkey.to_hex, 
        "address" => address, 
        "data" => data
      },{
        "alg" => "ES256K", "typ" =>"JWT"
      }])
    end

    context 'invalid signature' do
      let(:jws) do
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ." + 
        "eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIw" + 
        "MTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEw" + 
        "MTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEw" + 
        "MTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNl" + 
        "YzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhk" + 
        "YWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYw" + 
        "YjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXki" + 
        "OiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMz" + 
        "OTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUz" + 
        "NjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRl" + 
        "ZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4" + 
        "YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdz" + 
        "blBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpW" + 
        "MU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2" +
        "WDRZUkciLCJkYXRhIjoiMDEwMjAzMDQwNTA2MDcw" + 
        "ODA5MGEwYjBjMGQwZTBmIn0.AAAAAAAAAAAAAAAA" + 
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + 
        "AAAAAAAAA"
      end

      it do
        expect { subject }.to raise_error(JWT::VerificationError)
      end

      context 'txid is invalid' do
        let(:jws) do
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ." + 
        "eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiI" + 
        "wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD" + "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsImluZGV4IjoxLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.nSwKx7CVbjd3KFEE-7BFmmVRE_o5BUxL04ZSpoWjfgx-ED0OEDiHu4llM8KQTpPyr9q9PNTM96Pe9aKNBRontw"
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "txid is invalid") }
      end
  
      context 'index is invalid(is not integer)' do
        let(:jws) do
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOiIweDBhIiwiY29sb3JfaWQiOiJjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDYiLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsImRhdGEiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.lC6n-QmF5f5H8AXuv0YW1nu4bzkuh0l35S29B6gt3weWKsWA06jOrhF8P2jPdNYsiT3kALt1YhhI33Llw_tBkg"
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "index is invalid") }
      end
  
      context 'index is invalid(negative integer)' do
        let(:jws) do
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOi0xLCJjb2xvcl9pZCI6ImMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NiIsInZhbHVlIjoxLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.7tJkLcWiVqr0Zp6GJTVgbizPgsd3ep9_P6nOu_LqVMCZtgegZ9y0naTol-JWaVnCEsS7ZJ10gh3a6hc5G6SAvA"
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "index is invalid") }
      end
  
      context 'index is invalid(too large)' do
        let(:jws) do
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjQyOTQ5NjcyOTYsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJkYXRhIjoiMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIn0.nzuXviCNRkgzDiTYbw5qh-2l-jZTZwupFIqFLUdIghK58m_BQhR_IICOJ23GOweZQmaSiSvdvTLGvDKfpDlhAQ"
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "index is invalid") }
      end
  
      context 'value is invalid(is not integer)' do
        let(:jws) do
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOiIweDBhIiwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsImRhdGEiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.ocxHYJ37bl7aX5sXzdFAuo1Le3PlQgaAfp5Jo5kpTtDt3I75jR6khBK7oUDYfihibTC2PIisut-ktp6xXfpQhQ"
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "value is invalid") }
      end
  
      context 'value is invalid(negative integer)' do
        let(:jws) do
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOi0xLCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.GRX-P9JerF3NG71EtNTJ_NWi2ILKf174FX_0da14EvL0vjv1tGsvmAEpj5Lifv7XB39BYCZLiOVEprHKoeCTSQ"
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "value is invalid") }
      end
  
      context 'value is invalid(too large)' do
        let(:jws) do
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjE4NDQ2NzQ0MDczNzA5NTUxNjE2LCJzY3JpcHRfcHVia2V5IjoiMjFjM2VjMmZkODA2NzAxYTNmNTU4MDhjYmVjMzkyMmMzOGRhZmFhMzA3MGM0OGM4MDNlOTA0M2VlMzY0MmM2NjBiNDZiYzc2YTkxNGZjNzI1MGEyMTFkZWRkYzcwZWU1YTI3MzhkZTVmMDc4MTczNTFjZWY4OGFjIiwiYWRkcmVzcyI6IjIyVmRRNVZqV2NGOXpnc25QUW9kRkJTMVBCUVBhQVFFWFNvZmt5TXYyRDl6VjFNZE5oZWFBeTdzcm9UZzUybXdXNWFwTmh4UHFCNlg0WVJHIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.SmqXfAttjME9L_mpXPzRpKyIQbzD1MQ4RKUhAVUPtl7UawaaLmcUtAURrsKOkm5v5javz-GxM5xKfnjhosksXw"
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "value is invalid") }
      end
  
      context 'color_id is invalid(too long)' do
        let(:jws) do
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiIzxUYXB5cnVzOjpDb2xvcjo6Q29sb3JJZGVudGlmaWVyOjB4MDAwMDAwMDEwNTE0YzZiMD4iLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsImRhdGEiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.6He2KBiekfl_auaG8wSkM2TgHBMQXxAGvKR0TNclYN99yF4Y5xZW5pSfHGA4CZJmvzs7fELr2l7hPYvdBxUIDA"
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "color_id is invalid") }
      end
  
      context 'color_id is invalid(too short)' do
        let(:jws) do
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiIzxUYXB5cnVzOjpDb2xvcjo6Q29sb3JJZGVudGlmaWVyOjB4MDAwMDAwMDEwNTFiNTJhMD4iLCJ2YWx1ZSI6MSwic2NyaXB0X3B1YmtleSI6IjIxYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2YmM3NmE5MTRmYzcyNTBhMjExZGVkZGM3MGVlNWEyNzM4ZGU1ZjA3ODE3MzUxY2VmODhhYyIsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsImRhdGEiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.oRGFSAuIcJb_9uOfW81Yg1Rw6l1kkp0YIrlMO8Z6wGjF0FmzdJn37kwW9AjxUQkA5RZsy0qc-tLnGoLCadCTTg"  
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "color_id is invalid") }
      end
  
      context 'script_pubkey is invalid' do
        let(:jws) do
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOm51bGwsImFkZHJlc3MiOiIyMlZkUTVWaldjRjl6Z3NuUFFvZEZCUzFQQlFQYUFRRVhTb2ZreU12MkQ5elYxTWROaGVhQXk3c3JvVGc1Mm13VzVhcE5oeFBxQjZYNFlSRyIsImRhdGEiOiIwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYifQ.7dpSE4n10SXIJAAnv1m0uARajzSCqNKf-f9icl_247zqCl7IZX9oSNWiY0m9KlxHi3hXFMs2VKNwTjoRjz08lw"
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "script_pubkey is invalid") }
      end
  
      context 'address is invalid' do
        let(:jws) do
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiaW52YWxpZCBhZGRyZXNzIiwiZGF0YSI6IjAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZiJ9.6tudFQaX7EaZkoo916T1olmoHkpn4tamQqtAJQvj2xoRvf-vxHaMYzoZJ8ylaKTvvSWd9vyoDXwhMz1v3WuL1Q"
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "address is invalid") }
      end
  
      context 'data is invalid' do
        let(:jws) do
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJleGFtcGxlLmNvbSIsInR4aWQiOiIwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxIiwiaW5kZXgiOjEsImNvbG9yX2lkIjoiYzNlYzJmZDgwNjcwMWEzZjU1ODA4Y2JlYzM5MjJjMzhkYWZhYTMwNzBjNDhjODAzZTkwNDNlZTM2NDJjNjYwYjQ2IiwidmFsdWUiOjEsInNjcmlwdF9wdWJrZXkiOiIyMWMzZWMyZmQ4MDY3MDFhM2Y1NTgwOGNiZWMzOTIyYzM4ZGFmYWEzMDcwYzQ4YzgwM2U5MDQzZWUzNjQyYzY2MGI0NmJjNzZhOTE0ZmM3MjUwYTIxMWRlZGRjNzBlZTVhMjczOGRlNWYwNzgxNzM1MWNlZjg4YWMiLCJhZGRyZXNzIjoiMjJWZFE1VmpXY0Y5emdzblBRb2RGQlMxUEJRUGFBUUVYU29ma3lNdjJEOXpWMU1kTmhlYUF5N3Nyb1RnNTJtd1c1YXBOaHhQcUI2WDRZUkciLCJkYXRhIjoiaW52YWxpZCBkYXRhIn0.osdRksPRPn1Pe5iQwFz09gzw5-IpeJzYfkKwHwu1x3bF5FthVfTIU5ivKfH0wrdy5BVyc92zkHJRYWPNfeOohQ"
        end
  
        it { expect { subject }.to raise_error(RuntimeError, "data is invalid") }
      end
    end
  end
end
