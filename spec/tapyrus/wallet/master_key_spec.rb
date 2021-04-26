require 'spec_helper'

describe Tapyrus::Wallet::MasterKey do
  describe '#parse_from_payload, #to_payload' do
    subject do
      Tapyrus::Wallet::MasterKey.parse_from_payload(
        '0110f9d75d45f59a9e07a7b6331a58ceedd740a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55'
          .htb
      )
    end
    it 'should load data' do
      expect(subject.encrypted).to be true
      expect(subject.salt).to eq('f9d75d45f59a9e07a7b6331a58ceedd7')
      expect(subject.seed).to eq(
        'a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55'
      )
      expect(subject.mnemonic).to be nil
      expect(subject.to_hex).to eq(
        '0110f9d75d45f59a9e07a7b6331a58ceedd740a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55'
      )
    end
  end

  describe '#encrypt, #decrypt' do
    it 'should be process' do
      passphrase = 'hogehoge'
      key =
        Tapyrus::Wallet::MasterKey.new(
          'a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55'
        )
      expect { key.key }.not_to raise_error
      key.encrypt(passphrase)
      expect(key.seed).not_to eq(
        'a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55'
      )
      expect { key.key }.to raise_error('seed is encrypted. please decrypt the seed.')
      expect(key.encrypted).to be true
      expect { key.encrypt(passphrase) }.to raise_error('The wallet is already encrypted.') # already encrypted.
      key.decrypt(passphrase)
      expect { key.key }.not_to raise_error
      expect(key.seed).to eq(
        'a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55'
      )
      expect(key.encrypted).to be false
      expect(key.salt).to eq('')
      expect { key.decrypt(passphrase) }.to raise_error('The wallet is not encrypted.') # not encrypted.
    end
  end

  describe '#derive' do
    subject { test_master_key }
    it 'should derive child key using path.' do
      expect(subject.derive("m/84'/0'/0'/0/0").to_base58).to eq(
        'vprv9PWf8opM7jMHZicbJtr7E7cVTCGRf7Q5JXpeD7t7oxMVdMDT1XXxJdacknPVLhM17iCnyCGsun8s9hqrCb5FBdyXTa15xasKRh5rrVZysDJ'
      )
      expect(subject.derive("m/84'/0'/0'/0/1").to_base58).to eq(
        'vprv9PWf8opM7jMHbu7Sybs4CafvwY2iv2QHzqgBVRqPn78ZtQTFDs6TkuUdwrAwWewFENPmAqR1MNi3rz993NLx9wBbhMw15EMimanNmMs7zut'
      )
      expect(subject.derive("m/84'/0'/0'/1/0").to_base58).to eq(
        'vprv9Q3pihpk5z42ccjrpVemVD5J1uRzGBNF6RJd3CZ7qpjwnQ5vrjQ1kcSbWpkznPQ2KwMiTs6pRGBNJCKMRaf6ZyCg6s25smxwnGB7NMARf8S'
      )
      expect(subject.derive("m/44'/0'/0/0'/1").to_base58).to eq(
        'tprv8kKYBSrNjXJo4EeTudQL5eFSQebFcWi4YtLX4mpqYYBaFYuXoDPFWJTbjWJX9rK4D9ceYm4ZoKFc9AiTfHKWsob9z3GBjDdVZkfThwEuLDD'
      )
      expect(subject.derive("m/44'/1/0'/0/1'").to_base58).to eq(
        'tprv8kEZgVRKpjG75bCKWBxhaYcpqfd4BZN4THGjwr9MQo3rRKXzMoBpV7mPAAQb6rTFddvVc1fdx9j3KCGnJRMEASziMVrxj4hV58YrnVzWa1J'
      )

      expect { subject.derive("n/44'/1/0'/0/1'") }.to raise_error(ArgumentError)
      expect { subject.derive("m/m'/1/0'/0/1'") }.to raise_error(ArgumentError)
      expect { subject.derive("m/44'/m/0'/0/1'") }.to raise_error(ArgumentError)
      expect { subject.derive("m/44'/1/0'/0/1m'") }.to raise_error(ArgumentError)
    end
  end
end
