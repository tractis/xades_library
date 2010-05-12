#!/usr/bin/env ruby

# (C) Copyright 2006 VeriSign, Inc.
# Developed by Sxip Identity
#
# Licensed under the Apache License, Version 2.0 (the "License")
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

class TC_TSIK < Test::Unit::TestCase


    # def setup
    # end

    # def teardown
    # end

    def resdir
	    return 't/res/tsik_tcport/'
	end

    def publicKey
        key = Xmlsig::Key.new
        assert_equal(0, key.loadFromFile(resdir() + 'mypub.pem', 'pem', ''), "loadFromFile of a key")
        assert_equal(1, key.isValid(), "isValid key")
        return key
    end
    
    def privateKey
        key = Xmlsig::Key.new
        assert_equal(0, key.loadFromFile(resdir() + 'mypriv.pem', 'pem', ''), "loadFromFile of a key")
        assert_equal(1, key.isValid(), "isValid key")
        key.setName("")
        return key
    end
	       
    def loadDoc(filename)
        doc = Xmlsig::XmlDoc.new
        fullfilename = resdir() + filename
        assert_equal(0, doc.loadFromFile(fullfilename), "loadFromFile of a XmlDoc")
        return doc
    end

    def sign1(inFileName, privateKey, publicKey, cert)
        doc = loadDoc(inFileName)
        if (cert != NIL)
            signer = Xmlsig::Signer.new(doc, privateKey)
            signer.addCertFromFile(cert, 'pem')
            return signer
        elsif (publicKey != NIL)
            return Xmlsig::Signer.new(doc, privateKey, publicKey)
        else
		    return Xmlsig::Signer.new(doc, privateKey)
        end
    end

    def sign2(signer, type, outFileName)
        if (type == "")
            d = signer.sign()
        else
            d = signer.sign(Xmlsig::XPath.new(type))
            if (outFileName != NIL)
                d.toFile(outFileName)
            end
        end
        return d
    end

    def verify(inDoc, signatureLocation, publicKey, mustHavePublicKey, mustHaveCert)
        xpath = Xmlsig::XPath.new(signatureLocation)
        xpath.addNamespace("ds", "http://www.w3.org/2000/09/xmldsig#")
        xpath.addNamespace("s2", "http://ns.s2ml.org/s2ml")
        xpath.addNamespace("SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/")
        xpath.addNamespace("EMS", "http://ems.verisign.com/2001/05/ems-s2ml#")

        verifier = Xmlsig::Verifier.new(inDoc, xpath)
        pubKey = publicKey
        if (mustHavePublicKey)
            pubKey = verifier.getVerifyingKey()
            if (pubKey == NIL)
                print("Cannot find public key")
                return 0
            end
        end
        if (mustHaveCert)
            cert = verifier.getCertificate()
            if (cert == NIL)
                print("Cannot find certificate")
                return 0
            end
        end
        verified = 0
        verified = verifier.verify(pubKey) == 1
        return verified
    end

    ### Port of the TSIK org.apache.tsik.xmlsig.test.XmlSigTest class
    ###

    def test_SignInPlace
        ### TSIK XmlSigTest.testSignInPlace
        # Load document
        doc = loadDoc("SomeTest.xml")

        # Sign document
        signer = Xmlsig::Signer.new(doc, privateKey(), publicKey())
        xpath = Xmlsig::XPath.new('/')
        assert_equal(0, signer.signInPlace(xpath), "signInPlace")

        # Verify document
        xpath = Xmlsig::XPath.new('//ds:Signature')
        xpath.addNamespace('ds', "http://www.w3.org/2000/09/xmldsig#")
        v = Xmlsig::Verifier.new(doc, xpath)
        assert_equal(1, v.verify(publicKey()), "Verify")
	end

    def test_SignInPlace2
        ### TSIK XmlSigTest.testSignInPlace2
        # Load document
        doc = loadDoc("Test2.xml")

        # Sign document
        signer = Xmlsig::Signer.new(doc, privateKey(), publicKey())
        xpath = Xmlsig::XPath.new('/test/test2')
        assert_equal(0, signer.signInPlace(xpath, 1), "signInPlace")

        # Verify document
        xpath = Xmlsig::XPath.new('//ds:Signature')
        xpath.addNamespace('ds', "http://www.w3.org/2000/09/xmldsig#")
        v = Xmlsig::Verifier.new(doc, xpath)
        assert_equal(1, v.verify(publicKey()), "Verify")
    end

    def test_SignInPlaceEnveloping
        ### TSIK XmlSigTest.testSignInPlaceEnveloping
        # Load document
        doc = loadDoc("Test2.xml")

        # Sign document
        signer = Xmlsig::Signer.new(doc, privateKey(), publicKey())
        assert_equal(0, signer.signInPlace(), "signInPlace")

        # Verify document
        xpath = Xmlsig::XPath.new('//ds:Signature')
        xpath.addNamespace('ds', "http://www.w3.org/2000/09/xmldsig#")
        v = Xmlsig::Verifier.new(doc, xpath)
        assert_equal(1, v.verify(publicKey()), "Verify")
    end

    def test_VerifyingKeyWithCerts
        ### TSIK XmlSigTest.testVerifyingKeyWithCerts
        doc = loadDoc('in.xml')
        cert = Xmlsig::X509Certificate.new
        if (cert.loadFromFile(resdir() +  'mycert.x509', 'cert_pem') < 0)
            raise "IOException - Couldn't load 'mycert.x509'"
        end
        verifyingKey = cert.getKey()
        # Sign document
        signer = Xmlsig::Signer.new(doc, privateKey(), verifyingKey)
        xpath = Xmlsig::XPath.new('/')
        d = signer.sign(xpath)

        # Verify document
        xpath = Xmlsig::XPath.new('//ds:Signature')
        xpath.addNamespace('ds', "http://www.w3.org/2000/09/xmldsig#")
        v = Xmlsig::Verifier.new(d, xpath)
        v.setKeyStore(Xmlsig::KeyStore.new)
        assert_equal(1, v.verify(publicKey()), "Verify")
        assert_equal(1, v.verify(), "Verify")
    end

    def test_SigningAndVerifyingKey
        ### TSIK XmlSigTest.testSigningAndVerifyingKey
        doc = loadDoc('in.xml')
        # Sign document
        signer = Xmlsig::Signer.new(doc, privateKey(), publicKey())
        xpath = Xmlsig::XPath.new('/books')
        signer.attachPublicKey(1)
        d = signer.sign(xpath)
        # Verify document
        xpath = Xmlsig::XPath.new('//ds:Signature')
        xpath.addNamespace('ds', "http://www.w3.org/2000/09/xmldsig#")
        v = Xmlsig::Verifier.new(d, xpath)
        assert_equal(1, v.verify(publicKey()), "Verify")
        assert_equal(1, v.verify(), "Verify")
    end

    def test_CertOnly
        ### TSIK XmlSigTest.testCertOnly
        doc = loadDoc('testCertOnly_in.xml')
        xpath = Xmlsig::XPath.new('//ds:Signature')
        xpath.addNamespace('ds', "http://www.w3.org/2000/09/xmldsig#")
        v = Xmlsig::Verifier.new(doc, xpath)
        assert_equal(1, v.verify(), "Verify")
    end

    def test_Hmac
        ### TSIK XmlSigTest.testHmac
        doc = loadDoc('in.xml')
        sigKey = Xmlsig::Key.new
        sigKey.loadHMACFromString('ab')
        signer = Xmlsig::Signer.new(doc, sigKey)
        xpath = Xmlsig::XPath.new('/')
        d = signer.sign(xpath)
        xpath = Xmlsig::XPath.new('//ds:Signature')
        xpath.addNamespace('ds', "http://www.w3.org/2000/09/xmldsig#")
        v = Xmlsig::Verifier.new(d, xpath)
        verKey = Xmlsig::Key.new
        verKey.loadHMACFromString('ab')
        assert_equal(1, v.verify(verKey), "Verify")
        verKey.loadHMACFromString('bb')
        assert_equal(0, v.verify(verKey), "Verify")
    end

    def test_EmptyNamespace
        ### TSIK XmlSigTest.testEmptyNamespace
        # original testEmptyNamespace.xml was
        #  <elem xmlns="default namespace"/>
        # changed to
        #  <elem xmlns="http://default/namespace"/>
        # because the former was being flagged by the libxml2 parser as
        # having an invalid URI
        signer = sign1('testEmptyNamespace.xml', privateKey(), publicKey(), NIL)
        doc = sign2(signer, '/', NIL)
        assert_equal(false, doc.nil?)
        assert_equal(true, verify(doc, '//ds:Signature', publicKey(), 0, 0), "Verify")
    end

    def test_Stele
        ### TSIK XmlSigTest.testStele
        signer = sign1('testStele.xml', privateKey(), publicKey(), NIL)
        xpath = Xmlsig::XPath.new("/SOAP-ENV:Envelope/SOAP-ENV:Body")
        xpath.addNamespace("SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/")
        signer.addReference(xpath)
        doc = sign2(signer, '/', NIL)
        assert_equal(false, doc.nil?)
        assert_equal(true, verify(doc, '//ds:Signature', publicKey(), 0, 0), "Verify")
    end

    def test_Cert
        ### TSIK XmlSigTest.testCert
        signer = sign1('in.xml', privateKey(), NIL, resdir() + 'mycert.x509')
        signer.attachPublicKey(1)
        assert_equal(false, signer.nil?)
        doc = sign2(signer, '/', NIL)
        assert_equal(false, doc.nil?)
        sigLoc = '/books/ds:Signature'

        assert_equal(true, verify(doc, sigLoc, publicKey(), 0, 0), "Verify")
        assert_equal(true, verify(doc, sigLoc, NIL, 1, 0), "Verify")
        assert_equal(true, verify(doc, sigLoc, NIL, 1, 1), "Verify")
        xpath = Xmlsig::XPath.new(sigLoc)
        xpath.addNamespace("ds", "http://www.w3.org/2000/09/xmldsig#")
        verifier = Xmlsig::Verifier.new(doc, xpath)
        l = verifier.getCertificateChain()
        assert_equal(1, l.length, "Chain length")
    end

    def test_MultipleCert
        ### TSIK XmlSigTest.testMultipleCert
        cert = Xmlsig::X509Certificate.new
        if (cert.loadFromFile(resdir() +  'mycert.x509', 'cert_pem') < 0)
            raise "IOException - Couldn't load 'mycert.x509'"
        end
        verifyingKey = cert.getKey()
        doc = loadDoc('in.xml')
        signer = Xmlsig::Signer.new(doc, privateKey(), verifyingKey)
        signer.attachPublicKey(1)
        signer.addReference(Xmlsig::XPath.new("/books/book[2]"))
        d = signer.sign(Xmlsig::XPath.new("/books/book[1]"))
		assert_equal(false, d.nil?)
        sigLoc = '//ds:Signature'

        assert_equal(true, verify(d, sigLoc, publicKey(), 0, 0), "Verify")
        assert_equal(true, verify(d, sigLoc, NIL, 1, 0), "Verify")
        assert_equal(true, verify(d, sigLoc, NIL, 1, 1), "Verify")
        xpath = Xmlsig::XPath.new(sigLoc)
        xpath.addNamespace("ds", "http://www.w3.org/2000/09/xmldsig#")
        verifier = Xmlsig::Verifier.new(d, xpath)
        l = verifier.getCertificateChain()
        assert_equal(1, l.length, "Chain length")
	end

    def test_Enveloped
        ### TSIK XmlSigTest.testEnveloped
        signer = sign1('in.xml', privateKey(), publicKey(), NIL)
        doc = sign2(signer, '/', NIL)
        assert_equal(false, doc.nil?)
        assert_equal(true, verify(doc, '/books/ds:Signature', publicKey(), 0, 0), "Verify")
    end

    def test_Enveloping
        ### TSIK XmlSigTest.testEnveloping
        signer = sign1('in.xml', privateKey(), publicKey(), NIL)
        doc = sign2(signer, '', NIL)
        assert_equal(false, doc.nil?)
        assert_equal(true, verify(doc, '/ds:Signature', publicKey(), 0, 0), "Verify")
        assert_equal(true, verify(doc, '/ds:Signature', NIL, 1, 0), "Verify")
    end

    def test_Detached
        ### TSIK XmlSigTest.testDetached
        signer = sign1('in.xml', privateKey(), publicKey(), NIL)
        doc = sign2(signer, '/books/book[1]', NIL)
        assert_equal(false, doc.nil?)
        assert_equal(true, verify(doc, '/books/book[1]/ds:Signature', publicKey(), 0, 0), "Verify")
        assert_equal(true, verify(doc, '/books/book[1]/ds:Signature', NIL, 1, 0), "Verify")
    end

    def test_MultipleRefsDetached
        ### TSIK XmlSigTest.testMultipleRefsDetached
        signer = sign1('in.xml', privateKey(), publicKey(), NIL)

        for expr in ['/', '/books', '/books/book[2]', '/books/book[1]',
                    "/books/book[@name='Professional XML']"]
            xpath = Xmlsig::XPath.new(expr)
            signer.addReference(xpath)
        end

        doc = sign2(signer, '/books/book[1]', NIL)
        assert_equal(false, doc.nil?)
        assert_equal(true, verify(doc, '/books/book[1]/ds:Signature', publicKey(), 0, 0), "Verify")
        assert_equal(true, verify(doc, '/books/book[1]/ds:Signature', NIL, 1, 0), "Verify")
    end

    def test_BadXPath1
        ### TSIK XmlSigTest.testBadXPath1
        signer = sign1('in.xml', privateKey(), publicKey(), NIL)
        xpath = Xmlsig::XPath.new('bad xpath')
        signer.addReference(xpath)
        d = sign2(signer, '/', NIL)
        rescue
        assert_equal(true, d.nil?)
    end

    def test_BadXPath2
        ### TSIK XmlSigTest.testBadXPath2
        signer = sign1('in.xml', privateKey(), publicKey(), NIL)
        xpath = Xmlsig::XPath.new('here()')
        signer.addReference(xpath)
        d = sign2(signer, '/', NIL)
        rescue
        assert_equal(true, d.nil?)
    end

    def test_MultipleSignatures
        ### TSIK XmlSigTest.testMultipleSignatures
        signer = sign1('in.xml', privateKey(), publicKey(), NIL)
        signer.addReference(Xmlsig::XPath.new('/books/book[2]'))
        doc = signer.sign(Xmlsig::XPath.new('/books/book[1]'), 1)
        assert_equal(false, doc.nil?)
        signer = Xmlsig::Signer.new(doc, privateKey(), publicKey())
        # TSIK uses /books/ds:Signature for this reference, which
        # matches multiple Signature elements. This causes problems
        # because a Signature should not refer to itself, so we've
        # changed it to refer to the first Signature only which was
        # presumably the intent. (modified TSIK output reference xml)
        xpath = Xmlsig::XPath.new('/books/ds:Signature[1]')
        xpath.addNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
        signer.addReference(xpath)
        doc = signer.sign(Xmlsig::XPath.new('/books/book[2]'), 1)
        assert_equal(false, doc.nil?)
        sigLoc1 = '/books/ds:Signature[1]'
        sigLoc2 = '/books/ds:Signature[2]'
        assert_equal(true, verify(doc, sigLoc1, publicKey(), 0, 0), "Verify")
        assert_equal(true, verify(doc, sigLoc2, publicKey(), 0, 0), "Verify")
        assert_equal(true, verify(doc, sigLoc1, NIL, 1, 0), "Verify")
        assert_equal(true, verify(doc, sigLoc2, NIL, 1, 0), "Verify")
    end

    def test_MerlinEnvelopedDsa
        ### TSIK XmlSigTest.testMerlinEnvelopedDsa
        doc = loadDoc("merlin-xmldsig-fifteen/signature-enveloped-dsa.xml")
        assert_equal(true, verify(doc, '//ds:Signature', NIL, 1, 0), "Verify")
    end

    def test_MerlinEnvelopingDsa
        ### TSIK XmlSigTest.testMerlinEnvelopingDsa
        doc = loadDoc("merlin-xmldsig-fifteen/signature-enveloping-dsa.xml")
        assert_equal(true, verify(doc, '//ds:Signature', NIL, 1, 0), "Verify")
    end

    def test_MerlinEnvelopingBase64Dsa
        ### TSIK XmlSigTest.testMerlinEnvelopingBase64Dsa
        doc = loadDoc("merlin-xmldsig-fifteen/signature-enveloping-b64-dsa.xml")
        assert_equal(true, verify(doc, '//ds:Signature', NIL, 1, 0), "Verify")
    end

    ### Port of the TSIK org.apache.tsik.xmlsig.test.XmlSigTestExcC14n class
    ###

    def test_EmptyList
        ### TSIK XmlSigTestExcC14n.testEmptyList
        s = sign1('testStele.xml', privateKey(), publicKey(), NIL)
        s.useExclusiveCanonicalizer('')
        xp = Xmlsig::XPath.new("//*[@Id='ID1']")
        # Unused in TSIK, if we leave this out our Reference URIs match
        #xp.addNamespace("s", "http://schemas.xmlsoap.org/soap/envelope/")
        s.addReference(xp)
        doc = sign2(s, '/', NIL)
        assert_equal(false, doc.nil?)
        assert_equal(true, verify(doc, '//ds:Signature', publicKey(), 0, 0), "Verify")
        assert_equal(true, verify(doc, '//ds:Signature', NIL, 1, 0), "Verify")
    end
        
    ### Port of the TSIK org.apache.tsik.xmlsig.test.XmlSigTestDigsig class
    ###

    def test_XPath
        ### TSIK XmlSigTestDigsig.testXPath
        doc = loadDoc("digsig-ratified/xpath_out.xml")
        sigLoc = "//ds:Signature"
        assert_equal(true, verify(doc, sigLoc, NIL, 1, 0), "Verify")
    end

    def test_XPointer
        ### TSIK XmlSigTestDigsig.testXPointer
        doc = loadDoc("digsig-ratified/xpointer_out.xml")
        # Id attribute must be set, see
        # http://www.aleksey.com/xmlsec/faq.html#section_3_2
        doc.addIdAttr('Id', 'elem', '')
        sigLoc = "//ds:Signature"
        assert_equal(true, verify(doc, sigLoc, NIL, 1, 0), "Verify")
    end

    def test_XPathEnveloped
        ### TSIK XmlSigTestDigsig.testXPathEnveloped
        doc = loadDoc("digsig-ratified/envelopedsignature_out.xml")
        # Id attribute must be set, see
        # http://www.aleksey.com/xmlsec/faq.html#section_3_2
        doc.addIdAttr('Id', 'RegisterResult', 'http://www.xkms.org/schema/xkms-2001-01-20')
        sigLoc = "//ds:Signature"
        assert_equal(true, verify(doc, sigLoc, NIL, 1, 0), "Verify")
    end

    def test_Merlin2
        ### TSIK XmlSigTestDigsig.testMerlin2
        doc = loadDoc("merlin-xmldsig-fifteen/signature-enveloping-rsa.xml")
        sigLoc = "//ds:Signature"
        assert_equal(true, verify(doc, sigLoc, NIL, 1, 0), "Verify")
    end


    ### Port of the TSIK org.apache.tsik.xmlsig.test.XmlSigTestMerlin23 class
    ###

    def HMACKey
        key = Xmlsig::Key.new
        key.loadHMACFromString('secret')
        return key
    end

    def test_Merlin23
        ### TSIK XmlSigTestMerlin23
        xpath = Xmlsig::XPath.new("//ds:Signature")
        xpath.addNamespace("ds", "http://www.w3.org/2000/09/xmldsig#")
        for res in ['signature-enveloped-dsa',
                     'signature-enveloping-b64-dsa',
                     'signature-enveloping-rsa',
                     'signature-external-b64-dsa',
                     'signature-external-dsa',
                     'signature-x509-crt-crl',
                     'signature-x509-crt',
                     'signature-enveloping-hmac-sha1']
            fullfilename = resdir() + "merlin-xmldsig-twenty-three/" + res + ".xml"
            doc = Xmlsig::XmlDoc.new
            if doc.loadFromFile(fullfilename) < 0
                raise "IOError - Couldn't open XML file " + fullfilename
            end
            verifier = Xmlsig::Verifier.new(doc, xpath)
            if res == 'signature-enveloping-hmac-sha1'
                assert_equal(1, verifier.verify(HMACKey()), "Verify Merlin32")
            else 
                assert_equal(1, verifier.verify(), "Verify Merlin32")
            end
        end
	end
end
