require 'spec_helper'

describe Tapyrus::Message::VerAck do
  subject { Tapyrus::Message::VerAck.new }

  it 'should be generate verack message' do
    expect(subject.to_pkt.bth).to eq('0b11090776657261636b000000000000000000005df6e0e2')
  end
end
