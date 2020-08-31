require 'spec_helper'

describe Tapyrus::RPC::RequestHandler do

  class HandlerMock
    include Tapyrus::RPC::RequestHandler
    attr_reader :node
    def initialize(node)
      @node = node
    end
  end

  let(:chain) { load_chain_mock }
  let(:wallet) { create_test_wallet }
  subject {
    allow(Tapyrus::Wallet::MasterKey).to receive(:generate).and_return(test_master_key)
    node_mock = double('node mock')
    allow(node_mock).to receive(:chain).and_return(chain)
    allow(node_mock).to receive(:pool).and_return(load_pool_mock(node_mock.chain))
    allow(node_mock).to receive(:broadcast).and_return(nil)
    allow(node_mock).to receive(:wallet).and_return(wallet)
    HandlerMock.new(node_mock)
  }
  after {
    chain.db.close
    wallet.close
  }

  describe '#getblockchaininfo' do
    it 'should return chain info' do
      result = subject.getblockchaininfo
      expect(result[:chain]).to eq('dev')
      expect(result[:headers]).to eq(15071)
      expect(result[:bestblockhash]).to eq('75be7b3b19e07f2c3644523016132db7e7e67063b3f5abbaa420cafc8a44557f')
      expect(result[:mediantime]).to eq(1594879787,)
    end
  end

  describe '#getblockheader' do
    context 'has block header' do
      it 'should return header info' do
        result = subject.getblockheader('a296873d850b332564e25061e8b8c9c57abb6d4fad56626780f70d5b53082df6', true)
        expect(result[:hash]).to eq('a296873d850b332564e25061e8b8c9c57abb6d4fad56626780f70d5b53082df6')
        expect(result[:height]).to eq(15070)
        expect(result[:features]).to eq(1)
        expect(result[:featuresHex]).to eq('01000000')
        expect(result[:merkleroot]).to eq('94b5dae46c6d0e7d3c6043b374ab64ddbfee371463fbbc4ee080a463a2a45b7f')
        expect(result[:time]).to eq(1594880968)
        expect(result[:mediantime]).to eq(1594879492)
        expect(result[:xfield_type]).to eq(0)
        expect(result[:xfield]).to be nil
        expect(result[:proof]).to eq('5b9f92404e15f411d07df45b15c1db8e2235d9f4357081014bda7b6820a2ec411a55421ceb7e228bc80bf89dde50dcda3c26c9770ab52d43b6aebea3b127f20a')
        expect(result[:previousblockhash]).to eq('2c5eeffc7d82ab1df248bd95b76c6a3c4a3692219c4135cbcb0c752a3bdd35ff')
        expect(result[:nextblockhash]).to eq('75be7b3b19e07f2c3644523016132db7e7e67063b3f5abbaa420cafc8a44557f')
        header = subject.getblockheader('a296873d850b332564e25061e8b8c9c57abb6d4fad56626780f70d5b53082df6', false)
        expect(header).to eq('01000000ff35dd3b2a750ccbcb35419c2192364a3c6a6cb795bd48f21dab827dfcef5e2c7f5ba4a263a480e04ebcfb631437eebfdd64ab74b343603c7d0e6d6ce4dab5945ec6e4adaa36156849708d7cc1c41b69afd0ed608c8bdc2221f8e5d0e609d537c8f30f5f00405b9f92404e15f411d07df45b15c1db8e2235d9f4357081014bda7b6820a2ec411a55421ceb7e228bc80bf89dde50dcda3c26c9770ab52d43b6aebea3b127f20a')
      end
    end

    context 'has not block header' do
      it 'should return error' do
        expect{subject.getblockheader('00', true)}.to raise_error(ArgumentError, 'Block not found')
      end
    end
  end

  describe '#getpeerinfo' do
    it 'should return connected peer info' do
      result = subject.getpeerinfo
      expect(result.length).to eq(2)
      expect(result[0][:id]). to eq(1)
      expect(result[0][:addr]). to eq('192.168.0.1:18333')
      expect(result[0][:addrlocal]). to eq('192.168.0.3:18333')
      expect(result[0][:services]). to eq('000000000000000c')
      expect(result[0][:relaytxes]). to be false
      expect(result[0][:lastsend]). to eq(1508305982)
      expect(result[0][:lastrecv]). to eq(1508305843)
      expect(result[0][:bytessent]). to eq(31298)
      expect(result[0][:bytesrecv]). to eq(1804)
      expect(result[0][:conntime]). to eq(1508305774)
      expect(result[0][:pingtime]). to eq(0.593433)
      expect(result[0][:minping]). to eq(0.593433)
      expect(result[0][:version]). to eq(70015)
      expect(result[0][:subver]). to eq('/Satoshi:0.14.1/')
      expect(result[0][:inbound]). to be false
      expect(result[0][:startingheight]). to eq(1210488)
      expect(result[0][:best_hash]). to eq(-1)
      expect(result[0][:best_height]). to eq(-1)
    end
  end

  describe '#sendrawtransaction' do
    it 'should return txid' do
      raw_tx = '0100000001b827a4b3edeb56a5598e22c1a54205de3b9c6b749fbfdb6a494bd1cb550cc93f000000006b483045022100aedbe7fa2f0dff58222d15665471266ff539bf1285b0ce69b22ae030d13535f602206d1272f2437e2e8c5185d59dc51a8169b0fb61b8a7aaa9576a878e8a4baafbe8012103fd8474629e95865deff1b8d72004055b03a87714d8288e33330f2b0a966f46b8ffffffff01adfcdf07000000001976a914f38f47c0b9de955bb9aca788525a8281ed50973b88ac00000000'
      expect(subject.sendrawtransaction(raw_tx)).to eq('3bf1b76036214dbd940603c1499b817e86cc6dc2b1f796642b1833320b00a310')
    end
  end

  describe '#decoderawtransaction' do
    it 'should return tx hash.' do
      # for legacy tx
      tx = subject.decoderawtransaction('01000000017179acc39e281989c62f1ed77940977a8562d2a03c902c20e1888ecca10e75eb00000000715347304402206945124b3126753fa83e7d4b03c419b6ceb90109cb68386ce81052fafe421fbf022023b0a4fabfea8286cb2102fb44623093abb170c127eeb51049f60a2e45d7abea012721022d4549c2f5aca5697dc232390770a99d6ee6ee139fda0fa0412e77a7bcd4b3eead55935887ffffffff010865f2040000000017a91454080827c0212bce22f827d1728d8480975de9338700000000')
      expect(tx).to include(
                        txid: '417bb3c8c2c54d6f833308bd2c31800bff543cb5d67f772f566915b1d2e3beb9',
                        hash: '32fc29c43ee6ff13e12f7419a5ef29e07fdc84e24808d06a397fb24854fbf56a',
                        features: 1, size: 196, locktime: 0,
                        vin:[{
                            txid: 'eb750ea1cc8e88e1202c903ca0d262857a974079d71e2fc68919289ec3ac7971', vout: 0,
                            script_sig: {
                                asm: '3 304402206945124b3126753fa83e7d4b03c419b6ceb90109cb68386ce81052fafe421fbf022023b0a4fabfea8286cb2102fb44623093abb170c127eeb51049f60a2e45d7abea01 21022d4549c2f5aca5697dc232390770a99d6ee6ee139fda0fa0412e77a7bcd4b3eead55935887',
                                hex: '5347304402206945124b3126753fa83e7d4b03c419b6ceb90109cb68386ce81052fafe421fbf022023b0a4fabfea8286cb2102fb44623093abb170c127eeb51049f60a2e45d7abea012721022d4549c2f5aca5697dc232390770a99d6ee6ee139fda0fa0412e77a7bcd4b3eead55935887'
                            },
                            sequence: 4294967295}],
                        vout: [{
                            value: 0.8299444,
                            n: 0,
                            script_pubkey: {
                                asm: 'OP_HASH160 54080827c0212bce22f827d1728d8480975de933 OP_EQUAL',
                                hex: 'a91454080827c0212bce22f827d1728d8480975de93387',
                                req_sigs: 1, type: 'scripthash',
                                addresses: ['2MzuYNTgfcezpymFsHLGjsNPchnKXwNP7SK']
                            }}]
                    )
      # for invalid tx
      expect{subject.decoderawtransaction('hoge')}.to raise_error(ArgumentError)
    end
  end

  describe '#decodescript' do
    context 'p2pkh' do
      it 'should return p2pkh script and addr.' do
        h = subject.decodescript('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac')
        expect(h).to include(asm: 'OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG',
                             type: 'pubkeyhash', req_sigs: 1,
                             p2sh: '2MztYDkQ6pdm8o26Eur1QcYRX8D8VP7v3yX',
                             addresses: ['mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1'])
      end
    end
    context 'p2sh' do
      it 'should return p2sh script and addr.' do
        h = subject.decodescript('a9147620a79e8657d066cff10e21228bf983cf546ac687')
        expect(h).to include(asm: 'OP_HASH160 7620a79e8657d066cff10e21228bf983cf546ac6 OP_EQUAL',
                             type: 'scripthash', req_sigs: 1,
                             addresses: ['2N41pqp5vuafHQf39KraznDLEqsSKaKmrij'])
      end
    end
    context 'multisig' do
      it 'should return multisig script and addrs.' do
        h = subject.decodescript('522102b3c35b692667fe940033aa50ea2f000ef0a67afb4f09f189695f627e55efa4972102d79e3fb71193b0269fe3822ea0fdaec210bd42f7a73679401787aa6932202f642103b0f671f3dda9b42442a82dcdd8d03ad8690c9b55dae6d46e30af3dbf2dd7283553ae')
        expect(h).to include(asm: '2 02b3c35b692667fe940033aa50ea2f000ef0a67afb4f09f189695f627e55efa497 02d79e3fb71193b0269fe3822ea0fdaec210bd42f7a73679401787aa6932202f64 03b0f671f3dda9b42442a82dcdd8d03ad8690c9b55dae6d46e30af3dbf2dd72835 3 OP_CHECKMULTISIG',
                             type: 'multisig', req_sigs: 2, p2sh: '2NBqJTuQRr8848Y9JdrEr7eudmWMTux5uR8',
                             addresses: ['myYTwRGG7s4zHHwn2UAKjY1oNLv9e3ucX9', 'mz4LtFxEHaQE5psvdq5dBJLv6UjqsFTUMr','mwRBqUC2HqeoRUVxoqaAR1eC3fC8Wig1T4'])
      end
    end
    context 'contract' do
      it 'should return contract script.' do
        h = subject.decodescript('a914b6ca66aa538d28518852b2104d01b8b499fc9b23876321021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e96702e803b27521032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e3568ac')
        expect(h).to include(asm: 'OP_HASH160 b6ca66aa538d28518852b2104d01b8b499fc9b23 OP_EQUAL OP_IF 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 OP_ELSE 1000 OP_CSV OP_DROP 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 OP_ENDIF OP_CHECKSIG',
                             type: 'nonstandard', p2sh: '2MxzAqJzM8xmcerj3oLtTRnXfnaqj7WD6wc')
      end
    end
  end

  describe '#createwallet' do
    before {
      path = test_wallet_path(3)
      FileUtils.rm_r(path) if Dir.exist?(path)
    }
    after {
      path = test_wallet_path(3)
      FileUtils.rm_r(path) if Dir.exist?(path)
    }
    it 'should be create new wallet' do
      result = subject.createwallet(3, TEST_WALLET_PATH)
      expect(result[:wallet_id]).to eq(3)
      expect(result[:mnemonic].size).to eq(12)
    end
  end

  describe '#listwallets' do
    it 'should return wallet list.' do
      result = subject.listwallets(TEST_WALLET_PATH)
      expect(result[0]).to eq(test_wallet_path(1))
    end
  end

  describe '#getwalletinfo' do

    context 'node has no wallet.' do
      subject {
        node_mock = double('node mock')
        allow(node_mock).to receive(:wallet).and_return(nil)
        HandlerMock.new(node_mock)
      }
      it 'should return empty hash' do
        expect(subject.getwalletinfo).to eq({})
      end
    end

    context 'node has wallet.' do
      it 'should return current wallet data' do
        result = subject.getwalletinfo

        expect(result[:wallet_id]).to eq(1)
        expect(result[:version]).to eq(Tapyrus::Wallet::Base::VERSION)
        expect(result[:account_depth]).to eq(1)

        accounts = result[:accounts]
        expect(accounts.size).to eq(1)
        expect(accounts[0][:name]).to eq('Default')
        expect(accounts[0][:path]).to eq("m/84'/1'/0'")
        expect(accounts[0][:type]).to eq('p2wpkh')
        expect(accounts[0][:index]).to eq(0)
        expect(accounts[0][:receive_depth]).to eq(0)
        expect(accounts[0][:change_depth]).to eq(0)
        expect(accounts[0][:look_ahead]).to eq(10)
        expect(accounts[0][:account_key]).to eq('vpub5YgmGYD5gaRBg3FssXTWkB8X7DfjvYhksZDQFBGPSVoB3GBN63jJkZucj9aeNQG6RJ8ymsENTB8XiPeK8fZQrsTF95VEoEngg7AMNd7798w')
        expect(accounts[0][:watch_only]).to be false
        expect(accounts[0][:receive_address]).to eq('mz7MBd4ew7KPY4GV3dU8GXRuutfCqSeLPW')
        expect(accounts[0][:change_address]).to eq('muvKLFKSsWwhnBSUri7Y3pDmYjfHKvGFzi')

        master = result[:master]
        expect(master[:encrypted]).to be false
      end
    end
  end

  describe '#listaccounts' do
    context 'node has no wallet.' do
      subject {
        node_mock = double('node mock')
        allow(node_mock).to receive(:wallet).and_return(nil)
        HandlerMock.new(node_mock)
      }
      it 'should return empty array' do
        expect(subject.listaccounts).to eq({})
      end
    end

    context 'node has wallet.' do
      it 'should return the list of account.' do
        result = subject.listaccounts
        expect(result['Default']).to eq(0.0)
      end
    end
  end

  describe '#encryptwallet' do
    it 'should encrypt wallet.' do
      expect(subject.encryptwallet('passphrase')).to eq('The wallet \'wallet_id: 1\' has been encrypted.')
      expect{subject.encryptwallet('passphrase2')}.to raise_error('The wallet is already encrypted.')
    end
  end

  private

  def load_entry(payload, height)
    header = Tapyrus::BlockHeader.parse_from_payload(payload.htb)
    Tapyrus::Store::ChainEntry.new(header, height)
  end

  def load_chain_mock
    chain_mock = create_test_chain
    latest_entry = load_entry('01000000f62d08535b0df780676256ad4f6dbb7ac5c9b8e86150e26425330b853d8796a2abd52ce318e5c5d6c3aeb3aea278ebf7fc8b8fe8cb5535543a76d4fd903589742ecee1ba9a3d25123dada6041c6bafff1423b3dd4f561816adcf245736004698f1f40f5f00403b9b731cb77c87078c0bdc8f1f2dc91406b42f082f9d8f095be16b5b0dd68f549b5ad1dda9e01ff87d022404b1f80dd40d40e0d3accc69fb9180fd8db30b5064', 15071)
    allow(chain_mock).to receive(:latest_block).and_return(latest_entry)
    # recent 11 block
    allow(chain_mock).to receive(:find_entry_by_hash).with('7f55448afcca20a4baabf5b36370e6e7b72d1316305244362c7fe0193b7bbe75').and_return(latest_entry)
    allow(chain_mock).to receive(:find_entry_by_hash).with('f62d08535b0df780676256ad4f6dbb7ac5c9b8e86150e26425330b853d8796a2').and_return(load_entry('01000000ff35dd3b2a750ccbcb35419c2192364a3c6a6cb795bd48f21dab827dfcef5e2c7f5ba4a263a480e04ebcfb631437eebfdd64ab74b343603c7d0e6d6ce4dab5945ec6e4adaa36156849708d7cc1c41b69afd0ed608c8bdc2221f8e5d0e609d537c8f30f5f00405b9f92404e15f411d07df45b15c1db8e2235d9f4357081014bda7b6820a2ec411a55421ceb7e228bc80bf89dde50dcda3c26c9770ab52d43b6aebea3b127f20a', 15070))
    allow(chain_mock).to receive(:find_entry_by_hash).with('ff35dd3b2a750ccbcb35419c2192364a3c6a6cb795bd48f21dab827dfcef5e2c').and_return(load_entry('0100000056e536e635464af4c5f29c70053aca5c6bf85cd74be4b13767585b8fb584e0d65c1ff2dc325153b244d698b26a2c6da39ad44f0ea1b2da15ec627abf3f8e07719b0db5e2556a79f5e82c00fa26bf67c07ac34706a2230e8733b8bf4c16f224f0a1f20f5f0040237714442c7e200f4541a04d376d8f8c5ec33b0e6612ee8dac6b170238de91ea43d23f3bc693bfbe1b14796abbf4f88506d115674ae41629a257ec521dc06a6c', 15069))
    allow(chain_mock).to receive(:find_entry_by_hash).with('56e536e635464af4c5f29c70053aca5c6bf85cd74be4b13767585b8fb584e0d6').and_return(load_entry('010000003eade24ce628c75aed820f0b0f8b9769470d3647a9ddf127eebb6ddbd4c8dc5822e42334cf5ea6b72706fb1d689be6b513ef0ffca00eadcd7201c21e5c33578e4037456245438089b06eb1282eded40209e5d0431a29ecc5fe66eb4305946b0e7af10f5f0040f01861a03b1c318e20e96de612b73bc01b00f2add5e134ed504181fd858d7448229b70b59b97cecd2aba5134e4aee5850d401298ff8ae7c51b4e0a5995dd70f4', 15068))
    allow(chain_mock).to receive(:find_entry_by_hash).with('3eade24ce628c75aed820f0b0f8b9769470d3647a9ddf127eebb6ddbd4c8dc58').and_return(load_entry('0100000050a70429e51f769bc10c3854d70687a96bb9d862d32be90a21fb649614187d4c3f59451a84e0d1c78a8bcc9ce47fcb5a8b77180f1ae0f55ae0346154e75a3ad24ddaf3935cd775aea9bbe3fda1ba96901d56b5d7ab95281ee62fb3d50023415852f00f5f0040eafd2fa6943f047f47553ab1e9b142d57373539e0dd7c100efc4ae536b9b253a7946103abd7f1b6afcedd3152a772ce8216b7812dcb69a0cacf232d90513c604', 15067))
    allow(chain_mock).to receive(:find_entry_by_hash).with('50a70429e51f769bc10c3854d70687a96bb9d862d32be90a21fb649614187d4c').and_return(load_entry('01000000025a0c77434286176b86beb58c93c6592331f1da951c68efa40a3a7cbcd7810119452ec46124a8b95535fcaa7aef293e0f3883096cddab4cae9bebfbb1161bcf82c0b5b492ea36e497c839cf3ee086d2341e69f9e5ebe07155c8171129254ebc2bef0f5f00403829ee0a5b37c611543845cc3a74ce6afdedf2e1a8f5f349e17ece7aa2893920dde038b7bc1863070517d5fc858b8ebcc7bbbe9a1491b9f160b63e1134ebe212', 15066))
    allow(chain_mock).to receive(:find_entry_by_hash).with('025a0c77434286176b86beb58c93c6592331f1da951c68efa40a3a7cbcd78101').and_return(load_entry('01000000d2e3ed7b79adee43a9595036183ae538b0a821f307c620062a902c1f405ea6090c7033dd06b6fcec471f8b3c0613bcd05c159f7a2c0ac856b494c9ac0da072f42c7aa291680a9b74e36a448c4ac2f6ae2d14f94c4a46e1fa66edac19a959133604ee0f5f0040e4e14d63a7fe4ed0dbc1007d54f0de4d1f120068e2c1a8f44df4a2d0c22703d995f072424f1d8083f67ff199d59342824bfb625b4885c8a47dce9df31188d2ae', 15065))
    allow(chain_mock).to receive(:find_entry_by_hash).with('d2e3ed7b79adee43a9595036183ae538b0a821f307c620062a902c1f405ea609').and_return(load_entry('010000007aa97a4c214285cd26826adc3d9a3b99e3c96cffa26d8eb55ff7c0ee577d7f92d80458cc460014907151c69253569247580a22f58114a6016d92333add7e7fd3d358517ba15fe191ca24fb9991212e0c8bd46c6501cdec7759040849e456b5c9dbec0f5f004052ffabaae041db7edc1de0ad586cecafb53d175f8c6bbc1521ce61d3e3f99dcff43284d37647371f971591955796e3080e4e9e11837ba37f93a32493b5b05474', 15064))
    allow(chain_mock).to receive(:find_entry_by_hash).with('7aa97a4c214285cd26826adc3d9a3b99e3c96cffa26d8eb55ff7c0ee577d7f92').and_return(load_entry('01000000b72da02b82357a9e84a092504ccfb86413dfd9fc53dcf61de0d142faa016b0558c725cb245799bacfa4508dcec97f4a1cbcc17c40d1c4f05ea038b52d247b5a88fd20ad2da8866d8876d1a9b859488c1262910b5b531d5aa2aa0910ea608068fb5eb0f5f0040b454083156453df857490d26823451b3f94058cf7a657499fa78e9b20fb6c34734f9a46788f9fd4d160043de9641f41dc32753065c220b80b69e68727be5bc5e', 15063))
    allow(chain_mock).to receive(:find_entry_by_hash).with('b72da02b82357a9e84a092504ccfb86413dfd9fc53dcf61de0d142faa016b055').and_return(load_entry('01000000de6c62b258491f8661990ce5dc455e8ee6fd432ee4bf910bf9e80763f4b7fab5eb47ed1177b845aafb114f1d07c268d62d22d6a5e474f74da221d6f3628d66013f1d2f691416e6ce210bf35f066980c967de88b77df9ea006814bda2bac4dfb88eea0f5f00406e5b011d40d7ec21621980459b5c194ce47a161c6581675861483531e978272b92061e561a201053cc4377a64152d28d47ce89f8353e03a86d7907b494f166f3', 15062))
    allow(chain_mock).to receive(:find_entry_by_hash).with('de6c62b258491f8661990ce5dc455e8ee6fd432ee4bf910bf9e80763f4b7fab5').and_return(load_entry('010000003bd37ec180d002b4a64281c99b5c9e1df4d1a0c87f2d21ffe6fdb885621bf3a18889f838ace351dd40a770f0542002b8fc7c93872b89de1c390b2476a4399f378fd46f3a5d94d58083d64e61d279ced7b9837c6a0fae3161043f0c2441e8af2d65e90f5f00404fc9913444c2b66996bd1e40d4dac89e0051973fa30e3c199a8d74d180dbca2ba40903a62ad03b281a781d9cef36605cfd781146a4ebb1f96bba591b43dca34c', 15061))
    allow(chain_mock).to receive(:find_entry_by_hash).with('3bd37ec180d002b4a64281c99b5c9e1df4d1a0c87f2d21ffe6fdb885621bf3a1').and_return(load_entry('01000000dfcbcca983e4d98e6851eae1c99ec0d20e22f6c8bc8b74313ef467d24965eaec1d7cc530f03348c1c95341ed3e66401eebcfe5328b8e01fdcdc5ecc939d23ff09ebfa3ef5a2d80bd1d12471a9b5cb52d7d31d6d33c8a8be3df828b0bacdb45323fe80f5f00405b8a6df5176bdfad01e7f52632c7c6d5d3b8fc9a483026788a314cc114813a4b04754e1a1d78adee64d76099c5701fe8d0c55843b0cd9ff9c6ce27181ecda1e7', 15060))
    allow(chain_mock).to receive(:find_entry_by_hash).with('dfcbcca983e4d98e6851eae1c99ec0d20e22f6c8bc8b74313ef467d24965eaec').and_return(load_entry('010000002ff154348994d2a5df33048c2867e5a0ee39f474cfa141ae424adf090a94736829183926c8f031aaa6b2dd15fe69c59bf1f4f9178aa711443c40c2375afdd865e3422b0d83a8233c54c53afbb5ad0df2d7f7db3c7842ad1f5ab483b9a98d744818e70f5f004050b721ee95b08c15f3ecb079e608cfa5a4817d7ac25aed7278f5526c98dc7a48f7d1f81c372c5b6dc38ac74336e9a31e6a811ba0194a03f7aeae12fe9ad5c8e2', 15059))
    allow(chain_mock).to receive(:find_entry_by_hash).with('2ff154348994d2a5df33048c2867e5a0ee39f474cfa141ae424adf090a947368').and_return(load_entry('01000000066329ae3211d65c398dffc0e315e0fe4cd1af4bca9edd1310888b8dfc3d93465a14b7331905abb1faa54b8074095874673aabce735a8476d0345ebdfe188b0f8e532f29914c366034ff015debb35a5e7881e021437a5b96994831b5b17c8f0befe50f5f00403abc769ee9b2656d35044ec777809c5da76517736308b626408a1b47b1e89f4978944132730667a7d4f0bb609027bfc85cab276af6af62d9f2337c47bf6c809f', 15058))
    allow(chain_mock).to receive(:find_entry_by_hash).with('00').and_return(nil)

    # previous block
    allow(chain_mock).to receive(:next_hash).with('f62d08535b0df780676256ad4f6dbb7ac5c9b8e86150e26425330b853d8796a2').and_return('7f55448afcca20a4baabf5b36370e6e7b72d1316305244362c7fe0193b7bbe75')
    chain_mock
  end

  def load_pool_mock(chain)
    node_mock = double('node mock')
    conn1 = double('connection_mock1')
    conn2 = double('connection_mock1')
    allow(conn1).to receive(:version).and_return(Tapyrus::Message::Version.new(
        version: 70015, user_agent: '/Satoshi:0.14.1/', start_height: 1210488,
        remote_addr: Tapyrus::Message::NetworkAddr.new(ip: '192.168.0.3', port: 60519, time: nil), services: 12
    ))
    allow(conn2).to receive(:version).and_return(Tapyrus::Message::Version.new)

    configuration = Tapyrus::Node::Configuration.new(network: :dev)
    pool = Tapyrus::Network::Pool.new(node_mock, chain, configuration)

    peer1 =Tapyrus::Network::Peer.new('192.168.0.1', 18333, pool, configuration)
    peer1.id = 1
    peer1.last_send = 1508305982
    peer1.last_recv = 1508305843
    peer1.bytes_sent = 31298
    peer1.bytes_recv = 1804
    peer1.conn_time = 1508305774
    peer1.last_ping = 1508386048
    peer1.last_pong = 1508979481

    allow(peer1).to receive(:conn).and_return(conn1)
    pool.peers << peer1

    peer2 =Tapyrus::Network::Peer.new('192.168.0.2', 18333, pool, configuration)
    peer2.id = 2
    allow(peer2).to receive(:conn).and_return(conn2)
    pool.peers << peer2

    pool
  end

end