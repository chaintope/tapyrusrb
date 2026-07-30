require "spec_helper"

describe Tapyrus::KeyPath do
  let(:test_class) { Struct.new(:key_path) { include Tapyrus::KeyPath } }
  let(:subject) { test_class.new }

  describe "#parse_key_path" do
    it "should parse a path" do
      expect(subject.parse_key_path("m")).to eq([])
      expect(subject.parse_key_path("m/0")).to eq([0])
      expect(subject.parse_key_path("m/0'")).to eq([2_147_483_648])
      expect(subject.parse_key_path("m/44'/2377'/0'/0/0")).to eq([2_147_483_692, 2_147_486_025, 2_147_483_648, 0, 0])
      expect(subject.parse_key_path("m/2147483647'")).to eq([4_294_967_295])
    end

    it "should reject a path which does not begin with m" do
      expect { subject.parse_key_path("") }.to raise_error(ArgumentError, " is invalid format.")
      expect { subject.parse_key_path("0/1") }.to raise_error(ArgumentError, "0/1 is invalid format.")
      expect { subject.parse_key_path("n/0") }.to raise_error(ArgumentError, "n/0 is invalid format.")
    end

    it "should reject an element which is not a decimal index" do
      expect { subject.parse_key_path("m/1abc") }.to raise_error(ArgumentError, "m/1abc is invalid format.")
      expect { subject.parse_key_path("m/1abc'") }.to raise_error(ArgumentError, "m/1abc' is invalid format.")
      expect { subject.parse_key_path("m/-1") }.to raise_error(ArgumentError, "m/-1 is invalid format.")
      expect { subject.parse_key_path("m/ 1") }.to raise_error(ArgumentError, "m/ 1 is invalid format.")
    end

    # String#to_i stops at the first character which is not a digit, so an element which carries
    # the hardened marker anywhere but at its end must be rejected before it is converted.
    it "should reject an element whose hardened marker is misplaced" do
      expect { subject.parse_key_path("m/1'2") }.to raise_error(ArgumentError, "m/1'2 is invalid format.")
      expect { subject.parse_key_path("m/12''") }.to raise_error(ArgumentError, "m/12'' is invalid format.")
      expect { subject.parse_key_path("m/'12") }.to raise_error(ArgumentError, "m/'12 is invalid format.")
    end

    it "should reject an index which has no representation in this notation" do
      expect { subject.parse_key_path("m/2147483648") }.to raise_error(ArgumentError, "m/2147483648 is invalid format.")
      expect { subject.parse_key_path("m/2147483648'") }.to raise_error(
        ArgumentError,
        "m/2147483648' is invalid format."
      )
      expect { subject.parse_key_path("m/4294967296") }.to raise_error(ArgumentError, "m/4294967296 is invalid format.")
    end
  end

  describe "#to_key_path" do
    it "should build a path" do
      expect(subject.to_key_path([])).to eq("m/")
      expect(subject.to_key_path([0])).to eq("m/0")
      expect(subject.to_key_path([2_147_483_692, 2_147_486_025, 2_147_483_648, 0, 0])).to eq("m/44'/2377'/0'/0/0")
    end

    it "should be the inverse of #parse_key_path" do
      %w[m/0 m/0' m/44'/2377'/0'/0/0 m/2147483647'].each do |path|
        expect(subject.to_key_path(subject.parse_key_path(path))).to eq(path)
      end
    end
  end
end
