require "spec_helper"

RSpec.describe Tapyrus::TIP0020::Metadata do
  describe "#initialize" do
    context "with valid parameters" do
      it "creates metadata with required fields and default version" do
        metadata = described_class.new(token_type: :reissuable, name: "Test Token", symbol: "TEST")
        expect(metadata.token_type).to eq(:reissuable)
        expect(metadata.version).to eq("1.0")
        expect(metadata.name).to eq("Test Token")
        expect(metadata.symbol).to eq("TEST")
        expect(metadata.decimals).to eq(0)
      end

      it "creates metadata with all fields for reissuable token" do
        metadata = described_class.new(
          token_type: :reissuable,
          version: "1.0",
          name: "Test Token",
          symbol: "TEST",
          decimals: 8,
          description: "A test token",
          icon: "https://example.com/icon.png",
          issuer: { name: "Test Issuer" },
          website: "https://example.com",
          terms: "https://example.com/terms",
          properties: { category: "utility" }
        )
        expect(metadata.version).to eq("1.0")
        expect(metadata.name).to eq("Test Token")
        expect(metadata.symbol).to eq("TEST")
        expect(metadata.decimals).to eq(8)
        expect(metadata.description).to eq("A test token")
        expect(metadata.icon).to eq("https://example.com/icon.png")
        expect(metadata.issuer).to eq({ name: "Test Issuer" })
        expect(metadata.website).to eq("https://example.com")
        expect(metadata.terms).to eq("https://example.com/terms")
        expect(metadata.properties).to eq({ category: "utility" })
      end

      it "creates NFT metadata with NFT-specific fields" do
        metadata = described_class.new(
          token_type: :nft,
          name: "Test NFT",
          symbol: "TNFT",
          image: "https://example.com/image.png",
          animation_url: "https://example.com/video.mp4",
          external_url: "https://example.com/nft/1",
          attributes: [{ trait_type: "Color", value: "Blue" }]
        )
        expect(metadata.token_type).to eq(:nft)
        expect(metadata.image).to eq("https://example.com/image.png")
        expect(metadata.animation_url).to eq("https://example.com/video.mp4")
        expect(metadata.external_url).to eq("https://example.com/nft/1")
        expect(metadata.attributes).to eq([{ trait_type: "Color", value: "Blue" }])
      end
    end

    context "with invalid parameters" do
      it "raises error when token_type is missing" do
        expect { described_class.new(name: "Test", symbol: "TEST") }.to raise_error(ArgumentError)
      end

      it "raises error when token_type is invalid" do
        expect { described_class.new(token_type: :invalid, name: "Test", symbol: "TEST") }.to raise_error(ArgumentError, /token_type must be one of/)
      end

      it "raises error when NFT fields are used with reissuable token" do
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: "TEST", image: "https://example.com/image.png") }.to raise_error(ArgumentError, /image.*can only be used with NFT token type/)
      end

      it "raises error when NFT fields are used with non_reissuable token" do
        expect { described_class.new(token_type: :non_reissuable, name: "Test", symbol: "TEST", attributes: [{ trait_type: "Color", value: "Blue" }]) }.to raise_error(ArgumentError, /attributes.*can only be used with NFT token type/)
      end

      it "raises error when version is empty" do
        expect { described_class.new(token_type: :reissuable, version: "", name: "Test", symbol: "TEST") }.to raise_error(ArgumentError, "version is required")
      end

      it "raises error when version is not 1.0" do
        expect { described_class.new(token_type: :reissuable, version: "2.0", name: "Test", symbol: "TEST") }.to raise_error(ArgumentError, "version must be 1.0")
      end

      it "raises error when name is missing" do
        expect { described_class.new(token_type: :reissuable, name: nil, symbol: "TEST") }.to raise_error(ArgumentError, "name is required")
      end

      it "raises error when name is empty" do
        expect { described_class.new(token_type: :reissuable, name: "", symbol: "TEST") }.to raise_error(ArgumentError, "name is required")
      end

      it "raises error when name exceeds 64 characters" do
        long_name = "a" * 65
        expect { described_class.new(token_type: :reissuable, name: long_name, symbol: "TEST") }.to raise_error(ArgumentError, /name must be 64 characters or less/)
      end

      it "raises error when symbol is missing" do
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: nil) }.to raise_error(ArgumentError, "symbol is required")
      end

      it "raises error when symbol exceeds 12 characters" do
        long_symbol = "a" * 13
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: long_symbol) }.to raise_error(ArgumentError, /symbol must be 12 characters or less/)
      end

      it "raises error when decimals is out of range" do
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: "TEST", decimals: -1) }.to raise_error(ArgumentError, /decimals must be between/)
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: "TEST", decimals: 19) }.to raise_error(ArgumentError, /decimals must be between/)
      end

      it "raises error when description exceeds 256 characters" do
        long_desc = "a" * 257
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: "TEST", description: long_desc) }.to raise_error(ArgumentError, /description must be 256 characters or less/)
      end

      it "raises error when website is not HTTPS" do
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: "TEST", website: "http://example.com") }.to raise_error(ArgumentError, /website must be an HTTPS URL/)
      end

      it "raises error when icon is not valid format" do
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: "TEST", icon: "http://example.com/icon.png") }.to raise_error(ArgumentError, /icon must be an HTTPS URL or Data URI/)
      end

      it "raises error when terms is not HTTPS" do
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: "TEST", terms: "http://example.com/terms") }.to raise_error(ArgumentError, /terms must be an HTTPS URL/)
      end

      it "raises error when issuer.url is not HTTPS" do
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: "TEST", issuer: { name: "Test", url: "http://example.com" }) }.to raise_error(ArgumentError, /issuer\.url must be an HTTPS URL/)
      end

      it "raises error when issuer.email is invalid" do
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: "TEST", issuer: { name: "Test", email: "not-an-email" }) }.to raise_error(ArgumentError, /issuer\.email must be a valid email address/)
      end

      it "raises error when Data URI exceeds 32KB" do
        large_data_uri = "data:image/png;base64," + ("A" * 33 * 1024)
        expect { described_class.new(token_type: :reissuable, name: "Test", symbol: "TEST", icon: large_data_uri) }.to raise_error(ArgumentError, /icon must be an HTTPS URL or Data URI/)
      end

      it "accepts Data URI within 32KB limit" do
        small_data_uri = "data:image/png;base64," + ("A" * 30 * 1024)
        metadata = described_class.new(token_type: :reissuable, name: "Test", symbol: "TEST", icon: small_data_uri)
        expect(metadata.icon).to eq(small_data_uri)
      end
    end
  end

  describe "#to_h" do
    it "returns hash with required fields including version" do
      metadata = described_class.new(token_type: :reissuable, name: "Test Token", symbol: "TEST")
      expect(metadata.to_h).to eq({ version: "1.0", name: "Test Token", symbol: "TEST" })
    end

    it "includes decimals only when not 0" do
      metadata = described_class.new(token_type: :reissuable, name: "Test Token", symbol: "TEST", decimals: 8)
      expect(metadata.to_h).to include(decimals: 8)
    end

    it "includes optional fields when present" do
      metadata = described_class.new(
        token_type: :reissuable,
        name: "Test Token",
        symbol: "TEST",
        description: "A test token",
        terms: "https://example.com/terms",
        properties: { category: "utility" }
      )
      expect(metadata.to_h).to include(description: "A test token")
      expect(metadata.to_h).to include(terms: "https://example.com/terms")
      expect(metadata.to_h).to include(properties: { category: "utility" })
    end
  end

  describe "#canonicalize" do
    it "returns JSON with sorted keys including version" do
      metadata = described_class.new(token_type: :reissuable, name: "Test Token", symbol: "TEST")
      canonical = metadata.canonicalize
      expect(canonical).to eq('{"name":"Test Token","symbol":"TEST","version":"1.0"}')
    end

    it "sorts keys alphabetically" do
      metadata = described_class.new(
        token_type: :reissuable,
        name: "Test Token",
        symbol: "TEST",
        decimals: 8,
        description: "A test token"
      )
      canonical = metadata.canonicalize
      # Keys should be in alphabetical order
      expect(canonical).to match(/\{"decimals":8,"description":"A test token","name":"Test Token","symbol":"TEST","version":"1\.0"\}/)
    end
  end

  describe "#hash and #hash_hex" do
    it "calculates SHA256 hash of canonicalized metadata" do
      metadata = described_class.new(token_type: :reissuable, name: "Test Token", symbol: "TEST")
      expect(metadata.hash.bytesize).to eq(32)
      expect(metadata.hash_hex.length).to eq(64)
      expect(metadata.hash_hex).to match(/^[0-9a-f]{64}$/)
    end

    it "returns consistent hash for same metadata" do
      metadata1 = described_class.new(token_type: :reissuable, name: "Test Token", symbol: "TEST")
      metadata2 = described_class.new(token_type: :reissuable, name: "Test Token", symbol: "TEST")
      expect(metadata1.hash_hex).to eq(metadata2.hash_hex)
    end

    it "returns different hash for different metadata" do
      metadata1 = described_class.new(token_type: :reissuable, name: "Test Token 1", symbol: "TEST1")
      metadata2 = described_class.new(token_type: :reissuable, name: "Test Token 2", symbol: "TEST2")
      expect(metadata1.hash_hex).not_to eq(metadata2.hash_hex)
    end
  end

  describe "#commitment and #commitment_hex", network: :prod do
    let(:key) { Tapyrus::Key.generate }
    let(:pubkey) { key.pubkey }
    let(:metadata) { described_class.new(token_type: :reissuable, name: "Test Token", symbol: "TEST") }

    it "calculates commitment from pubkey and metadata hash" do
      expect(metadata.commitment(pubkey).bytesize).to eq(32)
      expect(metadata.commitment_hex(pubkey).length).to eq(64)
    end

    it "raises error for invalid pubkey" do
      expect { metadata.commitment("invalid") }.to raise_error(ArgumentError)
    end
  end

  describe "#derive_p2c_pubkey", network: :prod do
    let(:key) { Tapyrus::Key.generate }
    let(:pubkey) { key.pubkey }
    let(:metadata) { described_class.new(token_type: :reissuable, name: "Test Token", symbol: "TEST") }

    it "derives P2C public key" do
      p2c_pubkey = metadata.derive_p2c_pubkey(pubkey)
      expect(p2c_pubkey.length).to eq(66) # 33 bytes compressed = 66 hex chars
      expect(p2c_pubkey).to match(/^0[23][0-9a-f]{64}$/)
    end

    it "derives different P2C pubkey for different metadata" do
      metadata2 = described_class.new(token_type: :reissuable, name: "Another Token", symbol: "ANOT")
      p2c_pubkey1 = metadata.derive_p2c_pubkey(pubkey)
      p2c_pubkey2 = metadata2.derive_p2c_pubkey(pubkey)
      expect(p2c_pubkey1).not_to eq(p2c_pubkey2)
    end
  end

  describe "#derive_p2c_address", network: :prod do
    let(:key) { Tapyrus::Key.generate }
    let(:pubkey) { key.pubkey }
    let(:metadata) { described_class.new(token_type: :reissuable, name: "Test Token", symbol: "TEST") }

    it "derives P2C address" do
      address = metadata.derive_p2c_address(pubkey)
      expect(address).to be_a(String)
      expect(address.length).to be > 25
    end
  end

  describe "#derive_color_id", network: :prod do
    let(:key) { Tapyrus::Key.generate }
    let(:pubkey) { key.pubkey }
    let(:out_point) { Tapyrus::OutPoint.from_txid("0000000000000000000000000000000000000000000000000000000000000001", 0) }

    context "with reissuable token_type" do
      let(:metadata) { described_class.new(token_type: :reissuable, name: "Test Token", symbol: "TEST") }

      it "derives reissuable color identifier" do
        color_id = metadata.derive_color_id(pubkey: pubkey)
        expect(color_id).to be_a(Tapyrus::Color::ColorIdentifier)
        expect(color_id.valid?).to be true
        expect(color_id.type).to eq(Tapyrus::Color::TokenTypes::REISSUABLE)
      end

      it "raises error when pubkey is missing" do
        expect { metadata.derive_color_id }.to raise_error(ArgumentError, /pubkey is required/)
      end
    end

    context "with non_reissuable token_type" do
      let(:metadata) { described_class.new(token_type: :non_reissuable, name: "Test Token", symbol: "TEST") }

      it "derives non_reissuable color identifier" do
        color_id = metadata.derive_color_id(out_point: out_point)
        expect(color_id).to be_a(Tapyrus::Color::ColorIdentifier)
        expect(color_id.valid?).to be true
        expect(color_id.type).to eq(Tapyrus::Color::TokenTypes::NON_REISSUABLE)
      end

      it "raises error when out_point is missing" do
        expect { metadata.derive_color_id }.to raise_error(ArgumentError, /out_point is required/)
      end
    end

    context "with nft token_type" do
      let(:metadata) { described_class.new(token_type: :nft, name: "Test NFT", symbol: "TNFT") }

      it "derives nft color identifier" do
        color_id = metadata.derive_color_id(out_point: out_point)
        expect(color_id).to be_a(Tapyrus::Color::ColorIdentifier)
        expect(color_id.valid?).to be true
        expect(color_id.type).to eq(Tapyrus::Color::TokenTypes::NFT)
      end

      it "raises error when out_point is missing" do
        expect { metadata.derive_color_id }.to raise_error(ArgumentError, /out_point is required/)
      end
    end
  end

  describe ".parse" do
    it "parses JSON string to metadata" do
      json = '{"name":"Test Token","symbol":"TEST","decimals":8}'
      metadata = described_class.parse(json, token_type: :reissuable)
      expect(metadata.name).to eq("Test Token")
      expect(metadata.symbol).to eq("TEST")
      expect(metadata.decimals).to eq(8)
    end

    it "handles missing optional fields" do
      json = '{"name":"Test Token","symbol":"TEST"}'
      metadata = described_class.parse(json, token_type: :reissuable)
      expect(metadata.decimals).to eq(0)
      expect(metadata.description).to be_nil
    end
  end

  describe "fixture test vectors" do
    let(:fixtures) { fixture_file("tip0020_metadata.json") }

    # Determine token type based on NFT-specific fields
    def detect_token_type(data)
      nft_fields = %w[image animation_url external_url attributes]
      has_nft_fields = nft_fields.any? { |f| data[f] }
      has_nft_fields ? :nft : :reissuable
    end

    def build_metadata(data)
      token_type = detect_token_type(data)
      described_class.new(
        token_type: token_type,
        version: data["version"] || Tapyrus::TIP0020::Metadata::CURRENT_VERSION,
        name: data["name"],
        symbol: data["symbol"],
        decimals: data["decimals"] || 0,
        description: data["description"],
        icon: data["icon"],
        issuer: data["issuer"]&.transform_keys(&:to_sym),
        website: data["website"],
        terms: data["terms"],
        properties: data["properties"]&.transform_keys(&:to_sym),
        image: data["image"],
        animation_url: data["animation_url"],
        external_url: data["external_url"],
        attributes: data["attributes"]
      )
    end

    describe "valid test cases" do
      it "validates all valid test vectors" do
        fixtures["valid_test_cases"].each do |test_case|
          metadata = build_metadata(test_case["metadata"])

          expect(metadata.canonicalize).to eq(test_case["canonical"]),
            "#{test_case['name']}: canonical mismatch"
          expect(metadata.hash_hex).to eq(test_case["hash"]),
            "#{test_case['name']}: hash mismatch"
        end
      end

      describe "minimal (required fields only)" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "minimal" } }

        it "has correct canonical form and hash" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end

      describe "reissuable token" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "reissuable" } }

        it "has correct canonical form and hash" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end

      describe "non-reissuable token" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "non_reissuable" } }

        it "has correct canonical form and hash" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end

      describe "NFT" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "nft" } }

        it "has correct canonical form and hash" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end

      describe "token with issuer" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "with_issuer" } }

        it "has correct canonical form and hash" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end

      describe "max length name" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "max_length_name" } }

        it "has correct canonical form and hash" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end

      describe "max length symbol" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "max_length_symbol" } }

        it "has correct canonical form and hash" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end

      describe "decimals zero" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "decimals_zero" } }

        it "has correct canonical form and hash (decimals=0 should not appear in canonical)" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end

      describe "decimals max" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "decimals_max" } }

        it "has correct canonical form and hash" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end

      describe "data URI icon" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "data_uri_icon" } }

        it "has correct canonical form and hash" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end

      describe "with terms" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "with_terms" } }

        it "has correct canonical form and hash" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end

      describe "with properties" do
        let(:test_case) { fixtures["valid_test_cases"].find { |t| t["name"] == "with_properties" } }

        it "has correct canonical form and hash" do
          metadata = build_metadata(test_case["metadata"])
          expect(metadata.canonicalize).to eq(test_case["canonical"])
          expect(metadata.hash_hex).to eq(test_case["hash"])
        end
      end
    end

    describe "invalid test cases" do
      it "rejects all invalid test vectors with appropriate errors" do
        fixtures["invalid_test_cases"].each do |test_case|
          data = test_case["metadata"]
          token_type = detect_token_type(data)
          expect {
            described_class.new(
              token_type: token_type,
              version: data["version"] || Tapyrus::TIP0020::Metadata::CURRENT_VERSION,
              name: data["name"],
              symbol: data["symbol"],
              decimals: data["decimals"] || 0,
              description: data["description"],
              icon: data["icon"],
              issuer: data["issuer"]&.transform_keys(&:to_sym),
              website: data["website"],
              terms: data["terms"],
              properties: data["properties"]&.transform_keys(&:to_sym),
              image: data["image"],
              animation_url: data["animation_url"],
              external_url: data["external_url"],
              attributes: data["attributes"]
            )
          }.to raise_error(ArgumentError, /#{Regexp.escape(test_case["error"])}/),
            "#{test_case['name']}: expected error '#{test_case['error']}'"
        end
      end

      describe "missing_version" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "missing_version" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, version: data["version"], name: data["name"], symbol: data["symbol"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "invalid_version" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "invalid_version" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, version: data["version"], name: data["name"], symbol: data["symbol"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "missing_name" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "missing_name" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "empty_name" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "empty_name" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "name_too_long" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "name_too_long" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "missing_symbol" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "missing_symbol" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "empty_symbol" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "empty_symbol" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "symbol_too_long" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "symbol_too_long" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "decimals_negative" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "decimals_negative" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"], decimals: data["decimals"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "decimals_too_large" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "decimals_too_large" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"], decimals: data["decimals"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "description_too_long" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "description_too_long" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"], description: data["description"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "website_http" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "website_http" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"], website: data["website"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "website_invalid_url" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "website_invalid_url" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"], website: data["website"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "icon_http" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "icon_http" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"], icon: data["icon"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "icon_invalid_format" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "icon_invalid_format" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"], icon: data["icon"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "terms_http" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "terms_http" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"], terms: data["terms"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end

      describe "terms_invalid_url" do
        let(:test_case) { fixtures["invalid_test_cases"].find { |t| t["name"] == "terms_invalid_url" } }

        it "raises ArgumentError" do
          data = test_case["metadata"]
          expect {
            described_class.new(token_type: :reissuable, name: data["name"], symbol: data["symbol"], terms: data["terms"])
          }.to raise_error(ArgumentError, /#{test_case["error"]}/)
        end
      end
    end
  end
end