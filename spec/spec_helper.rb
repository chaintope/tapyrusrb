$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'tapyrus'
require 'logger'
require 'timecop'
require 'webmock/rspec'

RSpec.configure do |config|
  config.before(:each) do |example|
    if example.metadata[:network]
      Tapyrus.chain_params = example.metadata[:network]
    else
      Tapyrus.chain_params = :dev
    end
    example.metadata[:use_secp256k1] ? use_secp256k1 : use_ecdsa_gem
  end
end

def use_secp256k1
  host_os = RbConfig::CONFIG['host_os']
  case host_os
  when /darwin|mac os/
    ENV['SECP256K1_LIB_PATH'] = File.expand_path('lib/libsecp256k1.dylib', File.dirname(__FILE__))
  when /linux/
    ENV['SECP256K1_LIB_PATH'] = File.expand_path('lib/libsecp256k1.so', File.dirname(__FILE__))
  else
    raise "#{host_os} is an unsupported os."
  end
end

def use_ecdsa_gem
  ENV['SECP256K1_LIB_PATH'] = nil
end

def fixture_file(relative_path)
  file = File.read(File.join(File.dirname(__FILE__), 'fixtures', relative_path))
  JSON.parse(file)
end

def load_block(hash)
  File.read(File.join(File.dirname(__FILE__), 'fixtures', "block/#{hash}"))
end

def load_payment(file_name)
  File.read(File.join(File.dirname(__FILE__), 'fixtures', "payments/#{file_name}"))
end

GENESIS_BLOCK =
  Tapyrus::Block.parse_from_payload(
    '01000000000000000000000000000000000000000000000000000000000000000000000044cc181bd0e95c5b999a13d1fc0d193fa8223af97511ad2098217555a841b3518f18ec2536f0bb9d6d4834fcc712e9563840fe9f089db9e8fe890bffb82165849f52ba5e01210366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4b402b1ed9996920f57a425f6f9797557c0e73d0c9fbafdebcaa796b136e0946ffa98d928f8130b6a572f83da39530b13784eeb7007465b673aa95091619e7ee208501010000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a010000002776a92231415132437447336a686f37385372457a4b6533766636647863456b4a74356e7a4188ac00000000'
      .htb
  )
TEST_DB_PATH = "#{Dir.tmpdir}/#{ENV['TEST_ENV_NUMBER']}/spv"

def create_test_chain
  FileUtils.rm_r(TEST_DB_PATH) if Dir.exist?(TEST_DB_PATH)
  Tapyrus::Store::SPVChain.new(Tapyrus::Store::DB::LevelDB.new(TEST_DB_PATH), genesis: GENESIS_BLOCK)
end

TEST_WALLET_PATH = "#{Dir.tmpdir}/#{ENV['TEST_ENV_NUMBER']}/wallet-test/"

def test_wallet_path(wallet_id = 1)
  "#{TEST_WALLET_PATH}wallet#{wallet_id}/"
end

def create_test_wallet(wallet_id = 1)
  path = test_wallet_path(wallet_id)
  FileUtils.rm_r(path) if Dir.exist?(path)
  Tapyrus::Wallet::Base.create(wallet_id, TEST_WALLET_PATH)
end

def test_master_key
  words = %w[abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about]
  Tapyrus::Wallet::MasterKey.recover_from_words(words)
end

module Tapyrus
  autoload :TestScriptParser, 'tapyrus/script/test_script_parser'
end

RSpec::Matchers.define :custom_object do |clazz, properties|
  match do |actual|
    return false unless actual.is_a?(clazz)
    properties.each { |key, value| return false unless actual.send(key) == value }
    true
  end
end
