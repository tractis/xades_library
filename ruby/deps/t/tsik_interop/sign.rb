#!/usr/bin/env ruby
require 'xmlsig'

in_path = '../res/tsik/in/'
key_path = '../res/tsik/keys/'
out_path = '../'

x = Xmlsig::XmlDoc.new
x.loadFromFile(in_path + "in.xml")
k = Xmlsig::Key.new
k.loadFromFile(key_path + 'alice.pfx','pkcs12','password')
s = Xmlsig::Signer.new(x,k)
s.signInPlace()
x.toFile(out_path + "out_1.xml")



x = Xmlsig::XmlDoc.new
x.loadFromFile(in_path + "in.xml")
k = Xmlsig::Key.new
k.loadFromFile(key_path + 'alice.pfx','pkcs12','password')
s = Xmlsig::Signer.new(x,k)
s.addCertFromFile(key_path + 'Alice.cer', 'cert_der')
xp = Xmlsig::XPath.new()
xp.addNamespace('cert', 'http://example.com/cert')
xp.setXPath('/cert:cert')
x = s.sign(xp)
x.toFile(out_path + "out_2.xml")



x = Xmlsig::XmlDoc.new
x.loadFromFile(in_path + "in.xml")
k = Xmlsig::Key.new
k.loadFromFile(key_path + 'alice.pfx','pkcs12','password')

pk = Xmlsig::Key.new
pk.loadFromFile(key_path + 'Alice.cer', 'cert_der', '')

s = Xmlsig::Signer.new(x,k,pk)
xp = Xmlsig::XPath.new()
xp.addNamespace('cert', 'http://example.com/cert')
xp.setXPath('/cert:cert')
x = s.sign(xp)
x.toFile(out_path + "out_3.xml")



