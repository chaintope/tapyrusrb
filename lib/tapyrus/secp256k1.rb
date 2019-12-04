module Tapyrus

  module Secp256k1

    GROUP = ECDSA::Group::Secp256k1

    autoload :Ruby, 'tapyrus/secp256k1/ruby'
    autoload :Native, 'tapyrus/secp256k1/native'

  end

end
