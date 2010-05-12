#!/usr/bin/env ruby
require 'xmlsig'

in_path = '../res/tsik/in/'
key_path = '../res/tsik/keys/'

x = Xmlsig::XmlDoc.new
x.loadFromFile(in_path + "out.xml")
xp = Xmlsig::XPath.new()
xp.addNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
xp.setXPath('/descendant::ds:Signature[position()=1]')
v = Xmlsig::Verifier.new(x,xp)
puts "error in #1" if (v.verify != 1)

x = Xmlsig::XmlDoc.new
x.loadFromFile(in_path + "cert_only_out.xml")
xp = Xmlsig::XPath.new()
xp.addNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
xp.setXPath('/descendant::ds:Signature[position()=1]')
v = Xmlsig::Verifier.new(x,xp)
ks = Xmlsig::KeyStore.new
ks.addTrustedCertFromFile(key_path + 'root.cer', 'cert_der')
ks.addTrustedCertFromFile(key_path + 'ca.cer', 'cert_der')
v.setKeyStore(ks)
puts "error in #2" if (v.verify != 1)






