require 'spec_helper'

# BIP-32 test
# https://github.com/Tapyrus/bips/blob/master/bip-0032.mediawiki#Test_Vectors
describe Tapyrus::ExtKey, network: :prod do

  describe 'Test Vector 1' do

    before do
      @master_key = Tapyrus::ExtKey.generate_master('000102030405060708090a0b0c0d0e0f')
    end

    it 'Chain m' do
      expect(@master_key.depth).to eq(0)
      expect(@master_key.number).to eq(0)
      expect(@master_key.fingerprint).to eq('2f636ca9')
      expect(@master_key.chain_code.bth).to eq('5ab2b1ccdbe95ebe7a4e3eb82c61e32a8deabdb2121772dbf68164f5c5ab9fac')
      expect(@master_key.priv).to eq('dbce05e935c31b0970396d75891fd4e8b8abe5aea72819436446399862967b15')
      expect(@master_key.addr).to eq('15KZs9dFye8LCr423QvLpnCeCrypgWwFXc')
      expect(@master_key.pub).to eq('03fbdd72e050ea8dac6abfd5bb8e03cfd035ff8a0cc3f06fcc96a39d5854e5bc24')
      expect(@master_key.hash160).to eq('2f636ca97f1ad03e871f03094c1f3cc7d50d3ad9')
      expect(@master_key.to_base58).to eq('xprv9s21ZrQH143K2xjLUb6KPjDjExyBLXq6K9u1gGQVMLyvewCLXdivoY7w3iRxAk1eX7k51Dxy71QdfRSQMmiMUGUi5iKfsKh2wfZVEGcqXEe')
      expect(@master_key.ext_pubkey.to_base58).to eq('xpub661MyMwAqRbcFSooacdKksATnzofjzYwgNpcUep6ugWuXjXV5B3BMLSQu1eaiuxJ5zdoKt6ZcnpMi8mz2XHDHg8qSNWZpNnKABKxGetVSeG')
      expect(@master_key.ext_pubkey.pub).to eq('03fbdd72e050ea8dac6abfd5bb8e03cfd035ff8a0cc3f06fcc96a39d5854e5bc24')
      expect(@master_key.ext_pubkey.hash160).to eq('2f636ca97f1ad03e871f03094c1f3cc7d50d3ad9')
      expect(@master_key.ext_pubkey.addr).to eq('15KZs9dFye8LCr423QvLpnCeCrypgWwFXc')
      expect(@master_key.key_type).to eq(Tapyrus::Key::TYPES[:compressed])
    end

    it 'Chain m/0H' do
      key = @master_key.derive(0, true)
      expect(key.depth).to eq(1)
      expect(key.hardened?).to be true
      expect(key.fingerprint).to eq('f7e86dfb')
      expect(key.chain_code.bth).to eq('2a696f5ae70fc4d8b3596cdec599748cfc48481df056b726def2f366ebfd3d7d')
      expect(key.priv).to eq('a9c2b671ddd8b34d87200bf0d5a7cb9f1ae9ac1b7055e6602fd9937cd5b2e8ec')
      expect(key.pub).to eq('038b8a025e0483de5205737959d75fa8a928068c58c3dfcf1b690429a5698f1e07')
      expect(key.addr).to eq('1PbpLsnivrrr3Kh9JrTQ8GR7y7rR5t9xhh')
      expect(key.to_base58).to eq('xprv9uFM9iJccmW8MWthq313xGRzCStfizbMbuoFc7e3bherrNG4n7pxxeZnbt5xL3C4apsWhDp5xHqJVYTXaEZym1QxYutBNzsbA3KNN3brxYg')
      expect(key.ext_pubkey.to_base58).to eq('xpub68EhZDqWT94RZzyAw4Y4KQNikUjA8TKCy8irQW3fA3BqjAbDKf9DWStGTAq9yngbomLc1kWLcTsif1Q3K81CAtajweZiJgzYoBf3ok5siog')
      expect(key.ext_pubkey.hardened?).to be true
    end

    it 'Chain m/0H/1' do
      key = @master_key.derive(0, true).derive(1)
      expect(key.depth).to eq(2)
      expect(key.hardened?).to be false
      expect(key.fingerprint).to eq('54f9b99e')
      expect(key.chain_code.bth).to eq('c9aadda01691a1aa890ba1a409c9dfc9d6003eadbac2b0f5cf96843f00fbba59')
      expect(key.priv).to eq('b49e4eb97bc273fb31a2c39676704b43cfe94fecdfe7eb878520397f659efc6a')
      expect(key.to_base58).to eq('xprv9xby4JDYU1wVTmtDez13fFZYwujZNjCnuog6uMJDok16SnZnKaCxZNcqC4yGX7y7EzkCCtp8zdowyapkCAmZ48Qcw5SdPcAmYC4GyAaq17w')
      expect(key.ext_pubkey.to_base58).to eq('xpub6BbKTokSJPVngFxgm1Y42PWHVwa3nBveH2bhhjhqN5Y5Katvs7XD7AwK3LAx9RQfdHjLNXYgMx9pav9de2VDZ3ovqZfhYsqhXdN1D8ZknGV')
      expect(key.key_type).to eq(Tapyrus::Key::TYPES[:compressed])
      # pubkey derivation
      ext_pubkey = @master_key.derive(0, true).ext_pubkey.derive(1)
      expect(ext_pubkey.to_base58).to eq('xpub6BbKTokSJPVngFxgm1Y42PWHVwa3nBveH2bhhjhqN5Y5Katvs7XD7AwK3LAx9RQfdHjLNXYgMx9pav9de2VDZ3ovqZfhYsqhXdN1D8ZknGV')
      expect(key.ext_pubkey.hardened?).to be false
      expect(ext_pubkey.key_type).to eq(Tapyrus::Key::TYPES[:compressed])
    end

    it 'Chain m/0H/1/2H' do
      key = @master_key.derive(0, true).derive(1).derive(2, true)
      expect(key.depth).to eq(3)
      expect(key.hardened?).to be true
      expect(key.fingerprint).to eq('b4df6bd2')
      expect(key.chain_code.bth).to eq('ae69c3aa13a285ba03753e9a05123e8603a59ef31c909da99698ad194ba753bf')
      expect(key.priv).to eq('b798b73cc7bc74fb7fdc18e73771fe57cef37ce374b3342a87198ccd501a4e97')
      expect(key.to_base58).to eq('xprv9yHeFHDADn4TthzzG64pa8fN4oJ1hXaErdbTwenLijZZepW8KRvFrXHUyXxV9YZefWYLnwLcRDBufF2ZcdNBeKagGtEYmC3deGVrKJfUN7h')
      expect(key.ext_pubkey.to_base58).to eq('xpub6CGzenk449cm7C5TN7bpwGc6cq8W6zJ6DrX4k3BxH56YXcqGryEWQKbxpoGaV5SiD6JpEvE7vCrkQxHmyWka33JpLJuCjbR1XGBQrK7kCJR')
      expect(key.ext_pubkey.hardened?).to be true
      expect(key.key_type).to eq(Tapyrus::Key::TYPES[:compressed])
    end

    it 'Chain m/0H/1/2H/2' do
      key = @master_key.derive(0, true).derive(1).derive(2, true).derive(2)
      expect(key.depth).to eq(4)
      expect(key.hardened?).to be false
      expect(key.fingerprint).to eq('623d7a80')
      expect(key.chain_code.bth).to eq('d7bb2b3ab12244ca5a23d0ef250cfc2c862c6f211962406f54a96ee9070ca79b')
      expect(key.priv).to eq('aae0790f9f1ff173dfea1730f45f22deab9dd0c1c07941438e5623f11b60a00f')
      expect(key.to_base58).to eq('xprvA1sfG8WVX65Z2fnP4nbcKqhU4u8X2ZhDnafhLapjgar7kVFNJkHB9m46iRjyMRniTSU6Ftop4oQBarK2VaptXCHwBxN2JyeE3HZCdWj3naS')
      expect(key.ext_pubkey.to_base58).to eq('xpub6Es1fe3PMTdrF9rrAp8cgyeCcvy1S2R59obJ8yEMEvP6dHaWrHbRhZNaZhD1U3BK91axZiTZFTV9Tizr1X5D4yemBn59HqpGjqc4ijMrN2Y')
      expect(key.ext_pubkey.hardened?).to be false
    end

    it 'Chain m/0H/1/2H/2/1000000000' do
      key = @master_key.derive(0, true).derive(1).derive(2, true).derive(2).derive(1000000000)
      expect(key.depth).to eq(5)
      expect(key.hardened?).to be false
      expect(key.fingerprint).to eq('6a2523ff')
      expect(key.chain_code.bth).to eq('29a1188feaf0dcc7dd4ced00950ce5da5c4d790a5e3178c298031dbbbdb2f928')
      expect(key.priv).to eq('e05e1869ebffbb06f4fa567bc8390840ff6c6d11571f59dfe84a286e39ef30f8')
      expect(key.to_base58).to eq('xprvA39ZwpCsVGrRgnS4n7Ub6s4RPYMqsD64zPpdmm6pD6SNjEc2LTHha47jbqYxBSKNL4cuyMCxk1b44oiApcAd8uH89UYb4Hj7RmUQBJH3bmu')
      expect(key.ext_pubkey.to_base58).to eq('xpub6G8vMKjmKeQiuGWXt91bU119waCLGfovMckEa9WRmRyMc2wAszbx7rSDT6tmshb7WRQsuEbYPCdGsUrCKDxAdoPv59neBYeAaEMGQPeAgNy')
      expect(key.ext_pubkey.hardened?).to be false
    end
  end

  describe 'Test Vector 2' do
    before do
      @master_key = Tapyrus::ExtKey.generate_master('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')
    end

    it 'Chain m' do
      expect(@master_key.depth).to eq(0)
      expect(@master_key.number).to eq(0)
      expect(@master_key.to_base58).to eq('xprv9s21ZrQH143K3EAWtaFfWyKZ4wZYY8EritwZ7t8Q1CjU2sAF2A6STEAcvE18D4NErHh4zdGYysW7GYbykLp5cnFeFUzgNQaevEX56YV4MfL')
      expect(@master_key.ext_pubkey.to_base58).to eq('xpub661MyMwAqRbcFiEyzbnft7GHcyQ2waxi67s9vGY1ZYGSufVPZhQh12V6mTVtGMVZVNZ6pUA1sJjkPQzcSp3Yy1KrbKbYB2j2prTCLQ5q5xU')
    end

    it 'Chain m/0' do
      key = @master_key.derive(0)
      expect(key.depth).to eq(1)
      expect(key.hardened?).to be false
      expect(key.number).to eq(0)
      expect(key.to_base58).to eq('xprv9uNreJ4cFzMXpxuys3mL2oWZvBdDqLzRJcjKEaryur7g89ZJPidyoA2FHN65ugspw18VBNYhEcqwQKez6RPPvfvVp4jnZpv8zpEDEPmUas8')
      expect(key.ext_pubkey.to_base58).to eq('xpub68ND3obW6Muq3SzSy5JLPwTJUDTiEoiGfqev2yGbUBeezwtSwFxELxLj8e9T4N92dNmfcdheGw29NPGe4i3rYeAecJxMmMgKoV6JfDCwDYu')
      expect(key.ext_pubkey.hardened?).to be false
    end

    it 'Chain m/0/2147483647H' do
      key = @master_key.derive(0).derive(2147483647, true)
      expect(key.depth).to eq(2)
      expect(key.hardened?).to be true
      expect(key.number).to eq(2**31 + 2147483647)
      expect(key.to_base58).to eq('xprv9xAAhXL9iBW14jQBobrkXTJAuKgbtrbjKukd8miYZL6npywgwi8MqzENDt2zMfQhcduM5zLq1Efs3oNTQZJ2RTsbKrnyusrdxyewDk5cQtt')
      expect(key.ext_pubkey.to_base58).to eq('xpub6B9X72s3YZ4JHDUeudPktbEuTMX6JKKah8gDwA8A7fdmhnGqVFScPnYr5CXoV7gbJyQSKU9pZhqjnA4gUHpGba1T2gBphsQi76NJBtePzrE')
      expect(key.ext_pubkey.hardened?).to be true
    end

    it 'Chain m/0/2147483647H/1' do
      key = @master_key.derive(0).derive(2147483647, true).derive(1)
      expect(key.depth).to eq(3)
      expect(key.hardened?).to be false
      expect(key.number).to eq(1)
      expect(key.to_base58).to eq('xprv9xsheafKD5fYcGJWkNFdsX8St5XF13E9j8h5CVeKEgkpYrRvL6zQdm5Ex7gVC32CLFoVU3zKeGrrvLqJF1ZouBirmMWvK24eFTy9xN3vAch')
      expect(key.ext_pubkey.to_base58).to eq('xpub6Bs446CD3TDqpkNyrPneEf5BS7MjQVx16Mcfzt3vo2HoRem4seJfBZPioQ2JE3KjLYBxxu3ezCbCg5nv1JJeBNKPXgPBZQLBQxcHC9bdg8a')
      expect(key.ext_pubkey.hardened?).to be false
    end

    it 'Chain m/0/2147483647H/1/2147483646H' do
      key = @master_key.derive(0).derive(2147483647, true).derive(1).derive(2147483646, true)
      expect(key.depth).to eq(4)
      expect(key.hardened?).to be true
      expect(key.number).to eq(2**31 + 2147483646)
      expect(key.to_base58).to eq('xprvA16mAad8fZ2LQvPiCyMbaonMQGfQCbEQXUkpUqJ34D6hjUsHa4tEFiubS9n9QKtMEwHS2zupnC6ENGyNWDcTQAGDhDYb9fqkE7KedNoN8jq')
      expect(key.ext_pubkey.to_base58).to eq('xpub6E67a6A2VvaddQUBJztbwwj5xJVtc3xFthgRHDhecYdgcHCS7cCUoXE5HRhPgSDx4H1Y6qLbT5PtTjxomcvadXe2seaj4uzQG5kRs1o2Unb')
      expect(key.ext_pubkey.hardened?).to be true
    end

    it 'Chain m/0/2147483647H/1/2147483646H/2' do
      key = @master_key.derive(0).derive(2147483647, true).derive(1).derive(2147483646, true).derive(2)
      expect(key.depth).to eq(5)
      expect(key.hardened?).to be false
      expect(key.number).to eq(2)
      expect(key.to_base58).to eq('xprvA3miAHhnL1mo7oKJ9SgmQdUHfEmsbiPUyUorxoiuJXnQTp4kKiYAF6aDxLKpFTQ6mzsACWa7oC7p44S9h8dkCiHWcQjQL1vNyJWGn4BrCpP')
      expect(key.ext_pubkey.to_base58).to eq('xpub6Gm4ZoEgAPL6LHPmFUDmmmR2DGcN1B7LLhjTmC8WrsKPLcPtsFrQntthobzSvu7t8uiBD1GkK6jek6Life3QvWygRYkAegjuFNTK1v1F858')
      ext_pubkey = @master_key.derive(0).derive(2147483647, true).derive(1).derive(2147483646, true).ext_pubkey.derive(2)
      expect(ext_pubkey.to_base58).to eq('xpub6Gm4ZoEgAPL6LHPmFUDmmmR2DGcN1B7LLhjTmC8WrsKPLcPtsFrQntthobzSvu7t8uiBD1GkK6jek6Life3QvWygRYkAegjuFNTK1v1F858')
      expect(key.ext_pubkey.hardened?).to be false
    end

  end

  describe 'import from base58 address' do

    it 'import private key' do
      # normal key
      key = Tapyrus::ExtKey.from_base58('xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs')
      expect(key.depth).to eq(2)
      expect(key.number).to eq(1)
      expect(key.chain_code.bth).to eq('2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19')
      expect(key.priv).to eq('3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368')
      expect(key.ext_pubkey.to_base58).to eq('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')
      expect(key.key_type).to eq(Tapyrus::Key::TYPES[:compressed])

      # hardended key
      key = Tapyrus::ExtKey.from_base58('xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM')
      expect(key.depth).to eq(3)
      expect(key.number).to eq(2**31 + 2)
      expect(key.fingerprint).to eq('ee7ab90c')
      expect(key.chain_code.bth).to eq('04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f')
      expect(key.priv).to eq('cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca')
      expect(key.to_base58).to eq('xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM')
      expect(key.ext_pubkey.to_base58).to eq('xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5')
      expect(key.key_type).to eq(Tapyrus::Key::TYPES[:compressed])

      # pubkey format
      expect{Tapyrus::ExtKey.from_base58('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')}.to raise_error('An unsupported version byte was specified.')
    end

    it 'import public key' do
      # normal key
      key = Tapyrus::ExtPubkey.from_base58('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')
      expect(key.depth).to eq(2)
      expect(key.number).to eq(1)
      expect(key.chain_code.bth).to eq('2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19')
      expect(key.to_base58).to eq('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')
      expect(key.pubkey).to eq('03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c')
      expect(key.key_type).to eq(Tapyrus::Key::TYPES[:compressed])

      # hardended key
      key = Tapyrus::ExtPubkey.from_base58('xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5')
      expect(key.depth).to eq(3)
      expect(key.number).to eq(2**31 + 2)
      expect(key.fingerprint).to eq('ee7ab90c')
      expect(key.chain_code.bth).to eq('04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f')
      expect(key.pubkey).to eq('0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2')
      expect(key.key_type).to eq(Tapyrus::Key::TYPES[:compressed])

      # priv key format
      expect{Tapyrus::ExtPubkey.from_base58('xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM')}.to raise_error('An unsupported version byte was specified.')
    end
  end

  describe 'pubkey hardended derive' do
    it 'should raise error' do
      key = Tapyrus::ExtPubkey.from_base58('xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5')
      expect{key.derive(2**31)}.to raise_error('hardened key is not support')
    end
  end

  describe '#parse_from_payload' do
    it 'should deserialize key object.' do
      ext_pubkey = Tapyrus::ExtPubkey.parse_from_payload('0488b21e0354f9b99e8000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2'.htb)
      expect(ext_pubkey.to_base58).to eq('xpub6CGzenk449cm5VqBBH4iCJtAJysSRDt47eJGKuhdn1t1wWjv4bz1ZEUGjPqaa3wVPRcBm1nMZ956Tkc64mzAhAjZbXw1dAGfqLWm994LYxG')

      key = Tapyrus::ExtKey.parse_from_payload('0488ade4025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368'.htb)
      expect(key.to_base58).to eq('xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs')
    end
  end

  describe 'Test Vector 3' do
    subject {
      Tapyrus::ExtKey.generate_master('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be')
    }
    it 'should retain leading zeros' do
      expect(subject.ext_pubkey.to_base58).to eq('xpub661MyMwAqRbcGSgFKbmauzByRXbUwzcTereYkAKHdmCCsstP1Gr4jSpy38Gw3DRGTi47zaaZCux4tEU334RNcp32NL6Y6KwDAsjW7EWAvK8')
      expect(subject.to_base58).to eq('xprv9s21ZrQH143K3xbnDaEaYrFEsVkzYXtcHdiwwmug5RfE15ZETjXpBeWVBrJA6HFJWMLNK4U7U9MiWVyA1Q3uRoKdKhhKdozE6YALH8r5dEr')
      child = subject.derive(0, true)
      expect(child.ext_pubkey.to_base58).to eq('xpub68XfkYoDiPEjkgM5X7nAYdR23PPW9HyF8WPmHV1ET9rs6XUHmZxp4BJaRBQALEUkmwWJmBF6L1ZzyPjWDRtNVidyqH9cJDyVgdWKeJoHDzE')
      expect(child.to_base58).to eq('xprv9uYKM3GKt1gSYCGcR6FABVUHVMZ1jqFPmHUAV6bctpKtDj99E2eZWNz6ZvJsvxeur9pBRpLdLpjaguLLXJ9gg6dMm41qb13jB3onoHdTD34')
    end
  end

  describe 'Test Vector 4' do
    it 'should raise error.' do
      # pubkey version / prvkey mismatch
      expect{Tapyrus::ExtPubkey.from_base58('xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_PUBLIC_KEY)
      # prvkey version / pubkey mismatch
      expect{Tapyrus::ExtKey.from_base58('xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_BIP32_PRIV_PREFIX)

      # invalid pubkey prefix 04
      expect{Tapyrus::ExtPubkey.from_base58('xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_PUBLIC_KEY)
      expect{Tapyrus::ExtKey.from_base58('xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_BIP32_PRIV_PREFIX)

      # invalid pubkey prefix 01
      expect{Tapyrus::ExtPubkey.from_base58('xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_PUBLIC_KEY)
      expect{Tapyrus::ExtKey.from_base58('xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_BIP32_PRIV_PREFIX)

      # zero depth with non-zero parent fingerprint
      expect{Tapyrus::ExtPubkey.from_base58('xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_BIP32_FINGERPRINT)
      expect{Tapyrus::ExtKey.from_base58('xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_BIP32_FINGERPRINT)

      # zero depth with non-zero index
      expect{Tapyrus::ExtPubkey.from_base58('xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_BIP32_ZERO_INDEX)
      expect{Tapyrus::ExtKey.from_base58('xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_BIP32_ZERO_INDEX)

      # zero parent fingerprint with non-zero depth
      expect{Tapyrus::ExtPubkey.from_base58('xpub67tVq9TC3jGc6K4by6z6kdQafQSuot6u4B8hWn5Jd6vh9hdKNusPnNU4r2sXEKbgYVAAkbLpeut3DMSgLDAvSEQFHEp3f2MJaNQRiCpcWj3')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_BIP32_ZERO_DEPTH)
      expect{Tapyrus::ExtKey.from_base58('xprv9tu9RdvJDMiJspz8s5T6PVTr7NcRQRP3gxD6iPfh4mPiGuJAqNZ9Ea9aziKNptLTaB28LkiTWqvg636gvKqKxoVtLSVj2tUDqBzHxUKKS2m')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_BIP32_ZERO_DEPTH)

      # unknown extended key version
      expect{Tapyrus::ExtPubkey.from_base58('DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_BIP32_VERSION)
      expect{Tapyrus::ExtKey.from_base58('DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_BIP32_VERSION)

      # private key 0 not in 1..n-1
      expect{Tapyrus::ExtKey.from_base58('xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_PRIV_KEY)
      # private key n not in 1..n-1
      expect{Tapyrus::ExtKey.from_base58('xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_PRIV_KEY)

      # invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007
      expect{Tapyrus::ExtPubkey.from_base58('xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_PUBLIC_KEY)

      # invalid checksum
      expect{Tapyrus::ExtKey.from_base58('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL')}.to raise_error(ArgumentError, Tapyrus::Errors::Messages::INVALID_CHECKSUM)
    end
  end

end
