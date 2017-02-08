Gem::Specification.new do |s|
  s.name        = "cfcrypto"
  s.version     = "0.0.1"
  s.summary     = "CF's Crypto"
  s.description = "CF's repository of Cryptopals stuff"
  s.authors     = ["Chiang Fong Lee"]
  s.email       = "myself@cflee.net"
  s.homepage    = "https://github.com/cflee/cfcrypto"
  # s.files       = ["lib/cfcrypto.rb"]
  s.files = Dir["Rakefile", "{bin,lib,man,test,spec}/**/*", "README*", "LICENSE*"]
end
