require "spec_helper"

describe Tapyrus::Opcodes do
  describe "convert opcode to name" do
    it "should be convert" do
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_DROP)).to eq("OP_DROP")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_0)).to eq("0")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_1)).to eq("1")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_2)).to eq("2")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_3)).to eq("3")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_4)).to eq("4")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_5)).to eq("5")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_6)).to eq("6")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_7)).to eq("7")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_8)).to eq("8")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_9)).to eq("9")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_10)).to eq("10")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_11)).to eq("11")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_12)).to eq("12")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_13)).to eq("13")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_14)).to eq("14")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_15)).to eq("15")
      expect(Tapyrus::Opcodes.opcode_to_name(Tapyrus::Opcodes::OP_16)).to eq("16")
    end
  end

  describe "convert name to opcode" do
    it "should be convert" do
      expect(Tapyrus::Opcodes.name_to_opcode("OP_DROP")).to eq(Tapyrus::Opcodes::OP_DROP)
      expect(Tapyrus::Opcodes.name_to_opcode("0")).to eq(Tapyrus::Opcodes::OP_0)
      expect(Tapyrus::Opcodes.name_to_opcode("1")).to eq(Tapyrus::Opcodes::OP_1)
      expect(Tapyrus::Opcodes.name_to_opcode("2")).to eq(Tapyrus::Opcodes::OP_2)
      expect(Tapyrus::Opcodes.name_to_opcode("3")).to eq(Tapyrus::Opcodes::OP_3)
      expect(Tapyrus::Opcodes.name_to_opcode("4")).to eq(Tapyrus::Opcodes::OP_4)
      expect(Tapyrus::Opcodes.name_to_opcode("5")).to eq(Tapyrus::Opcodes::OP_5)
      expect(Tapyrus::Opcodes.name_to_opcode("6")).to eq(Tapyrus::Opcodes::OP_6)
      expect(Tapyrus::Opcodes.name_to_opcode("7")).to eq(Tapyrus::Opcodes::OP_7)
      expect(Tapyrus::Opcodes.name_to_opcode("8")).to eq(Tapyrus::Opcodes::OP_8)
      expect(Tapyrus::Opcodes.name_to_opcode("9")).to eq(Tapyrus::Opcodes::OP_9)
      expect(Tapyrus::Opcodes.name_to_opcode("10")).to eq(Tapyrus::Opcodes::OP_10)
      expect(Tapyrus::Opcodes.name_to_opcode("11")).to eq(Tapyrus::Opcodes::OP_11)
      expect(Tapyrus::Opcodes.name_to_opcode("12")).to eq(Tapyrus::Opcodes::OP_12)
      expect(Tapyrus::Opcodes.name_to_opcode("13")).to eq(Tapyrus::Opcodes::OP_13)
      expect(Tapyrus::Opcodes.name_to_opcode("14")).to eq(Tapyrus::Opcodes::OP_14)
      expect(Tapyrus::Opcodes.name_to_opcode("15")).to eq(Tapyrus::Opcodes::OP_15)
      expect(Tapyrus::Opcodes.name_to_opcode("16")).to eq(Tapyrus::Opcodes::OP_16)
    end
  end

  describe "#defined?" do
    context "defined" do
      it "should be true" do
        expect(Tapyrus::Opcodes.defined?(Tapyrus::Opcodes::OP_DROP)).to be true
        expect(Tapyrus::Opcodes.defined?(0xb9.chr.opcode)).to be true
      end
    end

    context "undefined" do
      it "should be false" do
        expect(Tapyrus::Opcodes.defined?(0xc1.chr.opcode)).to be false
        expect(Tapyrus::Opcodes.defined?(0xfff)).to be false
        expect(Tapyrus::Opcodes.defined?(0xbd.chr.opcode)).to be false
      end
    end
  end
end
