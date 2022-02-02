require 'spec_helper'

describe Tapyrus::RPC::TapyrusCoreClient do
  let!(:client) do
    # for Tapyrus::RPC::TapyrusCoreClient#initialize
    stub_request(:post, server_url).to_return(body: JSON.generate({ 'result': 'rpc_command' }))
    Tapyrus::RPC::TapyrusCoreClient.new(config)
  end
  let(:config) { { schema: 'http', host: 'localhost', port: 18_332, user: 'xxx', password: 'yyy' } }
  let(:server_url) { "#{config[:schema]}://#{config[:host]}:#{config[:port]}" }

  describe '#{rpc_command}' do
    it 'should return rpc response' do
      stub_request(:post, server_url).to_return(body: JSON.generate({ 'result': 'RESPONSE' }))
      expect(client.rpc_command).to eq('RESPONSE')
    end

    context 'error on requesting' do
      it 'should raise error' do
        stub_request(:post, server_url).to_raise(StandardError.new('ERROR'))
        expect { client.rpc_command }.to raise_error(StandardError, 'ERROR')
      end
    end

    context '500 internal server error' do
      it 'should raise with response' do
        stub_request(:post, server_url).to_return(status: [500, 'Internal Server Error'])
        expect { client.rpc_command }.to raise_error(
          Tapyrus::RPC::Error,
          { response_code: '500', response_msg: 'Internal Server Error' }.to_json
        )
      end
    end

    context '500 internal error with error message' do
      it 'should raise with response' do
        stub_request(:post, server_url).to_return(
          status: [500, 'Internal Server Error'],
          body: JSON.generate({ 'error': { 'code': '-1', 'message': 'RPC ERROR' } })
        )
        expect { client.rpc_command }.to raise_error do |e|
          expect(e.response[:rpc_error]).to eq({ 'code' => '-1', 'message' => 'RPC ERROR' })
          expect(e.message).to eq(
            "{\"response_code\":\"500\",\"response_msg\":\"Internal Server Error\",\"rpc_error\":{\"code\":\"-1\",\"message\":\"RPC ERROR\"}}"
          )
        end
      end
    end

    context 'contains float value' do
      it 'should convert string value' do
        stub_request(:post, server_url).to_return(body: JSON.generate({ 'result': { 'amount': 0.08495981 } }))
        expect(client.rpc_command['amount']).to eq('0.08495981')
      end
    end

    context 'wallet is specified in config' do
      let(:config) { super().merge({ wallet: 'mywallet' }) }
      let(:server_url) { "#{config[:schema]}://#{config[:host]}:#{config[:port]}/wallet/#{config[:wallet]}" }
      it 'should have wallet name in the path like "/wallet/[wallet_name]"' do
        assert_requested(:post, server_url)
        client.rpc_command
      end
    end

    context '401 unauthorized' do
      it 'should return rpc response' do
        stub_request(:post, server_url).to_return(status: [401, 'Unauthorized'])
        expect { client.rpc_command }.to raise_error(
          Tapyrus::RPC::Error,
          { response_code: '401', response_msg: 'Unauthorized' }.to_json
        )
      end
    end
  end
end
