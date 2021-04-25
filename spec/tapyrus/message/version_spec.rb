# encoding: ascii-8bit
require 'spec_helper'

describe Tapyrus::Message::Version do
  describe 'to_payload and parse_from_payload' do
    subject do
      Tapyrus::Message::Version.parse_from_payload(
        '721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001'
          .htb
      )
    end
    it 'should parse payload' do
      expect(subject.version).to eq(70_002)
      expect(subject.services).to eq(Tapyrus::Message::SERVICE_FLAGS[:network])
      expect(subject.timestamp).to eq(1_415_483_324)
      expect(subject.user_agent).to eq('/Satoshi:0.9.3/')
      expect(subject.local_addr.port).to eq(8333)
      expect(subject.local_addr.ip.to_s).to eq('198.27.100.9')
      expect(subject.local_addr.services).to eq(Tapyrus::Message::SERVICE_FLAGS[:network])
      expect(subject.local_addr.time).to be nil
      expect(subject.remote_addr.port).to eq(8333)
      expect(subject.remote_addr.ip.to_s).to eq('203.0.113.192')
      expect(subject.remote_addr.services).to eq(Tapyrus::Message::SERVICE_FLAGS[:network])
      expect(subject.remote_addr.time).to be nil
      expect(subject.relay).to be true
      expect(subject.nonce).to eq(['128035cbc97953f8'].pack('H*').reverse.bti)
      expect(subject.start_height).to eq(329_167)
      expect(subject.to_hex).to eq(
        '721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001'
      )
    end
  end

  describe 'specify opts' do
    subject { Tapyrus::Message::Version.new(start_height: 500, remote_addr: '83.243.59.57:8333') }
    it 'should be applied.' do
      expect(subject.start_height).to eq(500)
      expect(subject.remote_addr).to eq('83.243.59.57:8333')
    end
  end

  describe 'to_pkt' do
    subject do
      Tapyrus::Message::Version.new(
        local_addr: Tapyrus::Message::NetworkAddr.new(port: 18_333),
        remote_addr: Tapyrus::Message::NetworkAddr.new(port: 18_333),
        timestamp: 1_497_706_959,
        services: 0,
        version: 70_015,
        user_agent: '/tapyrusrb:0.1.0/',
        nonce: 13_469_974_270_669_794_112,
        relay: false
      ).to_pkt
    end
    it 'should generate pkt' do
      expect(subject.bth).to eq(
        '0b11090776657273696f6e0000000000670000004a6a37257f1101000000000000000000cf31455900000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d40abec703bf6eeba112f7461707972757372623a302e312e302f0000000000'
      )
    end
  end
end
