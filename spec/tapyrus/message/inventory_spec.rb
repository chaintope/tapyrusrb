require "spec_helper"

describe Tapyrus::Message::Inventory do
  describe "parse payload" do
    context "tx payload" do
      subject do
        Tapyrus::Message::Inventory.parse_from_payload(
          "01000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab".htb
        )
      end
      it "should be parsed" do
        expect(subject.identifier).to eq(Tapyrus::Message::Inventory::MSG_TX)
        expect(subject.hash).to eq("cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab")
      end
    end

    context "block payload" do
      subject do
        Tapyrus::Message::Inventory.parse_from_payload(
          "02000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab".htb
        )
      end
      it "should be parsed" do
        expect(subject.identifier).to eq(Tapyrus::Message::Inventory::MSG_BLOCK)
        expect(subject.hash).to eq("cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab")
      end
    end

    context "invalid identifier" do
      it "raise error" do
        expect {
          Tapyrus::Message::Inventory.parse_from_payload(
            "04000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab"
          )
        }.to raise_error(Tapyrus::Message::Error)
      end
    end
  end

  describe "to_payload" do
    subject do
      Tapyrus::Message::Inventory.new(
        Tapyrus::Message::Inventory::MSG_TX,
        "cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab"
      ).to_payload
    end
    it "should generate payload" do
      expect(subject.bth).to eq("01000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab")
    end
  end
end
