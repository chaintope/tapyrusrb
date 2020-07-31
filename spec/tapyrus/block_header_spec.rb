require 'spec_helper'

describe Tapyrus::BlockHeader do

  describe 'parse from payload' do
    subject {Tapyrus::BlockHeader.parse_from_payload('010000008dd071313dd2674dc098996805b917f79111359026adde510ac7f5447d0cb3ce8a081b8fbd5159e96d4744a4e1d883d6b9474bb204d14c09bf00b67f3ffdfdf86f5b597044f70e892887af9ee1d7a1288267c684e8afc6670949fefe946510eca314215f0040742dd09cab068bd26fd83d1c1a066405026ccc86bfc5c562350832f78fcd837f6b2ba890c7af950aa1adb40f75834da3c3c4075697c9c938dae1e745114e559c'.htb)}
    it 'should be parsed' do
      expect(subject.features).to eq(1)
      expect(subject.prev_hash).to eq('8dd071313dd2674dc098996805b917f79111359026adde510ac7f5447d0cb3ce')
      expect(subject.merkle_root).to eq('8a081b8fbd5159e96d4744a4e1d883d6b9474bb204d14c09bf00b67f3ffdfdf8')
      expect(subject.im_merkle_root).to eq('6f5b597044f70e892887af9ee1d7a1288267c684e8afc6670949fefe946510ec')
      expect(subject.x_field_type).to eq(0)
      expect(subject.x_field).to be nil
      expect(subject.block_hash).to eq('2adef8049d73da832a6e667d33a1777e2e47f81212917e040c3755e0be746589')
      expect(subject.hash_for_sign).to eq('12dae4b61b7429f084752ebe6dbd0d51c8ea206b9df8d45f5f9c07223f1463c4')
      expect(subject.proof).to eq('742dd09cab068bd26fd83d1c1a066405026ccc86bfc5c562350832f78fcd837f6b2ba890c7af950aa1adb40f75834da3c3c4075697c9c938dae1e745114e559c')
      expect(subject.to_hex).to eq('010000008dd071313dd2674dc098996805b917f79111359026adde510ac7f5447d0cb3ce8a081b8fbd5159e96d4744a4e1d883d6b9474bb204d14c09bf00b67f3ffdfdf86f5b597044f70e892887af9ee1d7a1288267c684e8afc6670949fefe946510eca314215f0040742dd09cab068bd26fd83d1c1a066405026ccc86bfc5c562350832f78fcd837f6b2ba890c7af950aa1adb40f75834da3c3c4075697c9c938dae1e745114e559c')
    end
  end

  describe '#valid_timestamp?' do
    subject {
      Tapyrus::BlockHeader.parse_from_payload('010000008dd071313dd2674dc098996805b917f79111359026adde510ac7f5447d0cb3ce8a081b8fbd5159e96d4744a4e1d883d6b9474bb204d14c09bf00b67f3ffdfdf86f5b597044f70e892887af9ee1d7a1288267c684e8afc6670949fefe946510eca314215f0040742dd09cab068bd26fd83d1c1a066405026ccc86bfc5c562350832f78fcd837f6b2ba890c7af950aa1adb40f75834da3c3c4075697c9c938dae1e745114e559c'.htb)
    }

    before {
      Timecop.freeze(Time.utc(2017, 9, 22, 15, 13, 25))
    }

    context 'too future' do
      it 'should be false' do
        subject.time = Time.utc(2017, 9, 22, 17, 13, 26).to_i
        expect(subject.valid_timestamp?).to be false
      end
    end

    context 'recent time' do
      it 'should be true' do
        subject.time = Time.utc(2017, 9, 22, 17, 13, 25).to_i
        expect(subject.valid_timestamp?).to be true
      end
    end

    after {
      Timecop.return
    }
  end

end
