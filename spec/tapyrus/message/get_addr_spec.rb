require "spec_helper"

describe Tapyrus::Message::GetAddr do
  describe "to_pkt" do
    subject { Tapyrus::Message::GetAddr.new.to_pkt }
    it { expect(subject).to eq("0b110907676574616464720000000000000000005df6e0e2".htb) }
  end
end
