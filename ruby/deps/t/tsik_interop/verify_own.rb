#!/usr/bin/env ruby
require 'xmlsig'

key_path = '../res/tsik/keys/'
out_path = '../'

x = Xmlsig::XmlDoc.new
x.loadFromFile(out_path + "out_1.xml")
xp = Xmlsig::XPath.new()
xp.addNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
xp.setXPath('/descendant::ds:Signature[position()=1]')
v = Xmlsig::Verifier.new(x,xp)
vk = Xmlsig::Key.new
vk.loadFromFile(key_path + 'Alice.cer','cert_der','')
puts "error in #1" if (v.verify(vk) != 1)


x = Xmlsig::XmlDoc.new
x.loadFromFile(out_path + "out_2.xml")
xp = Xmlsig::XPath.new()
xp.addNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
xp.setXPath('/descendant::ds:Signature[position()=1]')
v = Xmlsig::Verifier.new(x,xp)
ks = Xmlsig::KeyStore.new
ks.addTrustedCertFromFile(key_path + 'root.cer', 'cert_der')
ks.addTrustedCertFromFile(key_path + 'ca.cer', 'cert_der')
v.setKeyStore(ks)
puts "error in #2" if (v.verify != 1)


x = Xmlsig::XmlDoc.new
x.loadFromFile(out_path + "out_3.xml")
xp = Xmlsig::XPath.new()
xp.addNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
xp.setXPath('/descendant::ds:Signature[position()=1]')
v = Xmlsig::Verifier.new(x,xp)
ks = Xmlsig::KeyStore.new
ks.addTrustedCertFromFile(key_path + 'root.cer', 'cert_der')
ks.addTrustedCertFromFile(key_path + 'ca.cer', 'cert_der')
v.setKeyStore(ks)
puts "error in #3" if (v.verify != 1)





