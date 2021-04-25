require 'spec_helper'

describe Tapyrus::Network::MessageHandler do
  class Handler
    include Tapyrus::Network::MessageHandler
    attr_reader :logger, :peer, :sendheaders, :chain
    def initialize
      @message = ''
      @logger = Logger.new(STDOUT)
      configuration = Tapyrus::Node::Configuration.new(network: :dev)
      @chain = create_test_chain
      @peer =
        Tapyrus::Network::Peer.new(
          '127.0.0.1',
          18_332,
          Tapyrus::Network::Pool.new(nil, @chain, configuration),
          configuration
        )
      @sendheaders = false
    end

    def addr
      peer.addr
    end
  end

  subject do
    node_mock = double('node mock')
    handler = Handler.new
    allow(handler).to receive(:node).and_return(node_mock)
    handler
  end
  after { subject.chain.db.close }

  describe 'handle message' do
    context 'invalid header magic' do
      it 'raise message error' do
        # prod magic
        expect(subject).not_to receive(:defer_handle_command)
        expect(subject).to receive(:close).once
        subject.handle('f9beb4d976657261636b000000000000000000005df6e0e2'.htb)
      end
    end

    context 'invalid header checksum' do
      it 'raise message error' do
        expect(subject).not_to receive(:defer_handle_command)
        expect(subject).to receive(:close).once
        subject.handle('0b11090776657261636b000000000000000000005df6e0e3'.htb)
      end
    end

    context 'correct header' do
      it 'parse message' do
        expect(subject).to receive(:defer_handle_command).once
        subject.handle('0b11090776657261636b000000000000000000005df6e0e2'.htb)
      end
    end

    context 'segmented packet' do
      it 'merge message' do
        expect(subject).not_to receive(:close)
        expect(subject).to receive(:defer_handle_command).once
        subject.handle('0b11090770696e67000000000000000008000000'.htb)
        subject.handle('ed0382b90ffb510779cfe2'.htb)
        subject.handle('61'.htb)
      end
    end

    context 'sendheaders received' do
      it 'sendheaders flag on' do
        subject.handle_command('sendheaders', '')
        expect(subject.sendheaders).to be true
      end
    end

    context 'contains multiple command' do
      it 'handle multiple command' do
        expect(subject).to receive(:defer_handle_command).exactly(4).times
        subject.handle(
          '0b11090770696e67000000000000000008000000ed0382b90ffb510779cfe2610b11090767657468656164657273000025040000ade306747d11010020e7420d310f136d9c47986d6b0f085ea92bd6478264aa4d67f3aa0000000000009c24fcff7d9f0d3ca92c57df522dec636e81b3460a3f5cb8e22e0000000000007ac1484940ed24c9897b0f4ce82368fa46c43c2f8c6f3c3b993f000000000000193f804ac381baa65755df6c9fad23fdc0c18b07131f5dec0f88000000000000fc12b04651b0b1baf66e196dd7d0d234f35dfd7340fd5b9f5b87000000000000e71e66ba0c89e1271a14e48b257d4a8831cb95a00417142df8720000000000001df1ced8582ca556592c2133d6ccd6e409c50078d932205ac2a7000000000000f29ae31fe472fea5a9812cd8bd9d73c7e4491ee62fbaf9b1be2000000000000068f0b43a778b8203c4d6ea7be03a0b009505c075461bf04cfd08000000000000ed2bf1e887b73f71587b8d99d0877c704b358653ff1c33a4ce76000000000000f2a5b5dbd6f237ad984f130c4005c81282571405017b431b3d020000000000001e7f00ecfe5dcd4ecf636679af6d36e1504c6efae87d3a3cf38f000000000000f5cdf9532cc4f54d02f084547b36736bd5299abae8e5404c40470000000000008e0c6ee749e9ea8825f4ef947efd6c46d8f3fcfd53d1803069650000000000000008763d8a26752130799d5a531f63726ab52cde41efe054d75d000000000000353b073954a4253fd8f207f86e721eb9e09cfa2bbbe80f891fa9000000000000a8e1c5ca29a6c226edddcc227fea563f664ea07f66c220779b7e0000000000005b9111f950d237afe75056e7519022cb0fca1241a58766051ebc00000000000013e8d26541ec5f4120b57f0009226ee2be8b00fad73a16b2877b000000000000352d76b458910bb7aa112eb3451bde0e3a89ffa7ac67e942d55a0000000000001e1f6b07dc6fb2aea2a49932ed0c9aeced4171d339e279cd6c7800000000000012f4b9b6e8dba237487cff98e23781f10ec80bc1f0517b25fbed0100000000002116cc5c2eefd608f7f19817438e21310bbc6fba9353633940920c0000000000634f208d99326a6662646775bf88d6a1cebcbb4e1916c110dc2d3500000000005311d534ffe39473bd1ba445aec2600f3ec6035c9c03497983f27e5b00000000bca7c8349b8cfab22bde2dfa0dd65e7fb4ddd2f70e60c8cfd444000000000000175ba8659885ee5bec8a72c4160de6658c8f634f6e3ec4eb266100000000000045936b468e2f0250da7f477ebe0a6c635a921552d5b49e62cb8e85b900000000ea3d0f06df1dba91b8013d76aa6c48606f56e54c7771134a52a5580000000000b0f292183bda340c2de360e7de2112b9a852b391ba94871c31c20a00000000007b9550a04a1077ae035b307d77dccdd787910f65ff573737663c92000000000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000000000000000000000000000000000000000000000000000000000000000000000b11090766656566696c74657200000008000000e80fd19fe8030000000000000b11090768656164657273000000000038020000f5f34ae707000000201df1ced8582ca556592c2133d6ccd6e409c50078d932205ac2a70000000000005fa05fbd578adc2d9cda1afc6d95df5bb5315b56523153727cfe21ceaff910ec16bd48590bd6001b3f2bc9d00000000020e71e66ba0c89e1271a14e48b257d4a8831cb95a00417142df87200000000000041e10883c886d26bc0b14916dba6a25e71016959fa551cf7991047da2cbb022b29bd48590bd6001b2136d9b10000000020fc12b04651b0b1baf66e196dd7d0d234f35dfd7340fd5b9f5b87000000000000bec2e08ad2b13745379f57831c1b541783bfcd6cd114ee56ae93275f613ecd535bbd48590bd6001bce07b3e90000000020193f804ac381baa65755df6c9fad23fdc0c18b07131f5dec0f88000000000000f531f68e88f34d64f3c4a26eab493b231630a6df1dbe8ae15c3fc796c715d5827fbd48590bd6001b3e172d4a00000000207ac1484940ed24c9897b0f4ce82368fa46c43c2f8c6f3c3b993f0000000000003050a0d49567934c5dc8975c9b0b2d861a5d600792f7190f53c3591ad890dae8a7bd48590bd6001b5047a94f00000000209c24fcff7d9f0d3ca92c57df522dec636e81b3460a3f5cb8e22e000000000000dd3bca34e4a525ca98dca03efb1c2cd33d6aa93796a49b399c81057bdf31116bb7bd48590bd6001bb6f989160000000020e7420d310f136d9c47986d6b0f085ea92bd6478264aa4d67f3aa0000000000003afbb1f170fbb870aae481e73e78e45da715f0f85aa6349f6f8749d3820f78b52fbe48590bd6001b644df9e500'
            .htb
        )
      end
    end
  end

  describe 'corresponds to get_addr' do
    it 'should send addr message' do
      expect(subject.peer).to receive(:send_addrs)
      subject.handle_command('getaddr', '')
    end
  end
end
