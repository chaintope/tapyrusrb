module Tapyrus
  module KeyPath
    # key path convert an array of derive number
    # @param [String] path_string
    # @return [Array[Integer]] key path numbers.
    # @raise [ArgumentError] if the path is not a sequence of decimal indexes, each optionally
    #   followed by the hardened marker and each below Tapyrus::HARDENED_THRESHOLD.
    def parse_key_path(path_string)
      elements = path_string.split("/")
      raise ArgumentError.new("#{path_string} is invalid format.") unless elements.first == "m"
      elements[1..-1].map do |element|
        hardened = element.end_with?("'")
        # The index is validated before it is converted, since String#to_i stops at the first
        # character which is not a digit and returns what it read so far. An element such as
        # "1'2" would otherwise be taken for the index 1.
        digits = hardened ? element[0..-2] : element
        raise ArgumentError.new("#{path_string} is invalid format.") unless digits =~ /\A[0-9]+\z/
        index = digits.to_i
        # An index of Tapyrus::HARDENED_THRESHOLD or above is the hardened child of a smaller
        # index, so it has no representation of its own in this notation.
        raise ArgumentError.new("#{path_string} is invalid format.") if index >= Tapyrus::HARDENED_THRESHOLD
        hardened ? index + Tapyrus::HARDENED_THRESHOLD : index
      end
    end

    # key path numbers convert to path string.
    # @param [Array[Integer]] key path numbers.
    # @return [String] path string.
    def to_key_path(numbers)
      "m/#{numbers.map { |p| p >= Tapyrus::HARDENED_THRESHOLD ? "#{p - Tapyrus::HARDENED_THRESHOLD}'" : p.to_s }.join("/")}"
    end
  end
end
