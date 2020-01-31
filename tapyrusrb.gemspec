# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'tapyrus/version'

Gem::Specification.new do |spec|

  spec.name          = "tapyrus"
  spec.version       = Tapyrus::VERSION
  spec.authors       = ["azuchi"]
  spec.email         = ["azuchi@chaintope.com"]

  spec.summary       = %q{[WIP]The implementation of Tapyrus Protocol for Ruby.}
  spec.description   = %q{[WIP]The implementation of Tapyrus Protocol for Ruby.}
  spec.homepage      = 'https://github.com/chaintope/tapyrusrb'
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency 'schnorr'
  spec.add_runtime_dependency 'eventmachine'
  spec.add_runtime_dependency 'murmurhash3'
  spec.add_runtime_dependency 'daemon-spawn'
  spec.add_runtime_dependency 'thor'
  spec.add_runtime_dependency 'ffi'
  spec.add_runtime_dependency 'leb128', '~> 1.0.0'
  spec.add_runtime_dependency 'eventmachine_httpserver'
  spec.add_runtime_dependency 'rest-client'
  spec.add_runtime_dependency 'iniparse'
  spec.add_runtime_dependency 'siphash'
  spec.add_runtime_dependency 'protobuf', '3.8.5'
  spec.add_runtime_dependency 'scrypt'
  spec.add_runtime_dependency 'activesupport', '>= 5.2.3'

  # for options
  spec.add_development_dependency 'leveldb-native'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'timecop'

end