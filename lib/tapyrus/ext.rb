module Tapyrus
  module Ext
    autoload :JsonParser, "tapyrus/ext/json_parser"

    refine Object do
      def build_json
        self.is_a?(Array) ? "[#{self.map { |o| o.to_h.to_json }.join(",")}]" : to_h.to_json
      end

      def to_h
        return self if self.is_a?(String)
        instance_variables.inject({}) do |result, var|
          key = var.to_s
          key.slice!(0) if key.start_with?("@")
          value = instance_variable_get(var)
          value.is_a?(Array) ? result.update(key => value.map { |v| v.to_h }) : result.update(key => value)
        end
      end
    end
  end
end
