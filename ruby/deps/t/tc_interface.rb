#!/usr/bin/env ruby

# (C) Copyright 2006 VeriSign, Inc.
# Developed by Sxip Identity
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'test/unit'
require 'xmlsig'

class TC_Interface < Test::Unit::TestCase
    # def setup
    # end

    # def teardown
    # end

    def xmlDoc
        x = Xmlsig::XmlDoc.new
        xml = <<-XML
<greeting>
<hello>foo</hello>
<hello>bar</hello>
<goodbye>foo</goodbye>
<goodbye>bar</goodbye>
</greeting>
        XML
        result = x.loadFromString(xml)
        if result == -1
            raise "failed to create XML document"
        end
        assert_equal(0, result, "loadFromString on XmlDoc")
        return x
    end

    def privateKey
        k = Xmlsig::Key.new
        result = k.loadFromFile('t/res/rsakey.pem','pem','')
        if result < 0
            raise "failed to load key"
        end
        assert_equal(0, result, "loadFromString on Key")
        return k
    end

    def pubKey
        k = Xmlsig::Key.new
        result = k.loadFromFile('t/res/rsapub.pem','pem','')
        if result < 0
            raise "failed to load key"
        end
        assert_equal(0, result, "loadFromString on Key")
        return k
    end

    def HMACKey
        k = Xmlsig::Key.new
        result = k.loadHMACFromString('secret')
        if result < 0
            raise "failed to create HMAC key"
        end
        assert_equal(0, result, "loadHMACFromString on Key")
        return k
    end

    def test_interface
        signer = Xmlsig::Signer.new(xmlDoc, privateKey)
        verifier = Xmlsig::Verifier.new(signer.sign())
        assert_equal(1, verifier.verify(pubKey), "verify with public key")
        begin
            result = verifier.verify()
            rescue RuntimeError
                result = 1
            ensure
                assert_equal(1, result, "verify without key")
        end

        signer = Xmlsig::Signer.new(xmlDoc, privateKey)
        x = signer.sign(Xmlsig::XPath.new('//greeting'))
        xml = Xmlsig::XmlDoc.new()
        assert_equal(0, xml.loadFromFile('t/res/sign_enveloped.xml'), "loadFromFile on XmlDoc")
        assert_equal(x.toString(), xml.toString(), "compare signed with desired result")

        verifier = Xmlsig::Verifier.new(x)
        assert_equal(1, verifier.verify(pubKey), "verify with public key")

        signer = Xmlsig::Signer.new(xmlDoc, privateKey)
        signer.addReference(Xmlsig::XPath.new('//hello'))
        x = signer.sign(Xmlsig::XPath.new('//greeting'))
        xml = Xmlsig::XmlDoc.new()
        assert_equal(0, xml.loadFromFile('t/res/sign_detached.xml'), "loadFromFile on XmlDoc")
        assert_equal(x.toString(), xml.toString(), "compare signed with desired result")

        verifier = Xmlsig::Verifier.new(x)
        assert_equal(1, verifier.verify(pubKey), "verify with public key")
        assert_equal(1, verifier.isReferenced(Xmlsig::XPath.new('//hello[1]')), "isReferenced on verify")

        xml = xmlDoc
        signer = Xmlsig::Signer.new(xml, privateKey)
        signer.addReference(Xmlsig::XPath.new('//hello'))
        assert_equal(0, signer.signInPlace(Xmlsig::XPath.new('//greeting')), "signInPlace on signer")
        x = Xmlsig::XmlDoc.new()
        assert_equal(0, x.loadFromFile('t/res/sign_detached.xml'), "loadFromFile on XmlDoc")
        assert_equal(x.toString(), xml.toString(), "compare signed with desired result")

        xml = xmlDoc
        signer = Xmlsig::Signer.new(xml, privateKey)
        assert_equal(0, signer.signInPlace(), "signInPlace on signer")
        verifier = Xmlsig::Verifier.new(xml)
        assert_equal(1, verifier.verify(pubKey), "verify with public key")

        xml = xmlDoc
        signer = Xmlsig::Signer.new(xml, privateKey, pubKey)
        assert_equal(0, signer.signInPlace(Xmlsig::XPath.new('//greeting')), "signInPlace on signer")
        x = Xmlsig::XmlDoc.new()
        assert_equal(0, x.loadFromFile('t/res/sign_enveloped_withkey.xml'), "loadFromFile on XmlDoc")
        assert_equal(x.toString(), xml.toString(), "compare signed with desired result")

        xml = xmlDoc
        signer = Xmlsig::Signer.new(xml, privateKey)
        signer.useExclusiveCanonicalizer('')
        assert_equal(0, signer.signInPlace(Xmlsig::XPath.new('//greeting')), "signInPlace on signer")
        x = Xmlsig::XmlDoc.new()
        assert_equal(0, x.loadFromFile('t/res/sign_enveloped_exc_c14n.xml'), "loadFromFile on XmlDoc")
        assert_equal(x.toString(), xml.toString(), "compare signed with desired result")

        signer = Xmlsig::Signer.new(xmlDoc, privateKey)
        signer.addCertFromFile('t/res/rsacert.pem', 'pem')
        signer.attachPublicKey(1)
        xml = signer.sign(Xmlsig::XPath.new('//greeting'))
        x = Xmlsig::XmlDoc.new()
        assert_equal(0, x.loadFromFile('t/res/sign_enveloped_withcert.xml'), "loadFromFile on XmlDoc")
        assert_equal(x.toString(), xml.toString(), "compare signed with desired result")

        verifier = Xmlsig::Verifier.new(xml)
        eCert = verifier.getCertificate()
        assert_kind_of(Object, eCert, "getCertificate on verifier")

        xml = xmlDoc
        signer = Xmlsig::Signer.new(xml, HMACKey())
        assert_equal(0, signer.signInPlace(Xmlsig::XPath.new('//greeting')), "signInPlace on signer")

        x = Xmlsig::XmlDoc.new()
        assert_equal(0, x.loadFromFile('t/res/sign_enveloped_hmac.xml'), "loadFromFile on XmlDoc")
        assert_equal(x.toString(), xml.toString(), "compare signed with desired result")
    end
end

