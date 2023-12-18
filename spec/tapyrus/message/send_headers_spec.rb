require "spec_helper"

describe Tapyrus::Message::SendHeaders do
  describe "to_pkt" do
    subject { Tapyrus::Message::SendHeaders.new.to_pkt }
    it { expect(subject).to eq("0b11090773656e646865616465727300000000005df6e0e2".htb) }
  end
end
