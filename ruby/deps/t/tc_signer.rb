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

class TC_Signer < Test::Unit::TestCase
    # def setup
    # end

    # def teardown
    # end

    def clear_enveloping (str)
        str = str.gsub(/Reference URI=".*"/, 'Reference URI=""')
        str = str.gsub(/Object Id=".*"/, 'Object Id=""')
        str = str.gsub(/<DigestValue>.*<\/DigestValue>/, 
                       '<DigestValue></DigestValue>')
        str = str.gsub(/<SignatureValue>.*<\/SignatureValue>/m, 
                       '<SignatureValue></SignatureValue>')
        return str
    end

    def test_signer_basics
        x = Xmlsig::XmlDoc.new
        if x.loadFromString('<hello>world!</hello>') < 0
            raise "failed to create XML document"
        end
        k = Xmlsig::Key.new
        if k.loadFromFile('t/res/rsakey.pem','pem','') < 0
            raise "failed to load key"
        end
        s = Xmlsig::Signer.new(x,k)
        s.signInPlace()
        expected = <<-XML
<?xml version="1.0"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference URI="#obj1">
<Transforms>
<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>YSHe8XZ7FyBg4bJyb9nB4m0x+uo=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>cAWu6o1UKCUSfsVDlNG6JvE7bj6TrInQPdYYBWn/kR4zkyeSR45IjTjk8ug4w0lP
RJnPkFcxt9KZystNh/84boNPr8dV4aitMVBcwI9KC+wVyTSiNSGoQ97xwNWvV3P0
MuP0IfzwMYEYzaz4BcnLAeBS/zJj1nKBrQl4cPendKz258wND3sCx44gGPBWOe6S
+bgvzO31Dk6bXVid92DU2BBfzJ+vLC/R1pA7zzSbi4IbVOGGxcDwWz1UnXrBWVRv
l0BUrEO/ggm11KrDPywYpDk4K+S77uirJ5ZnE7/80gtVqeUNXFwPDXwxanr4OAYX
Oqke+lk6t9sVyzTbB/AhDw==</SignatureValue>
<Object Id="obj1"><hello>world!</hello></Object>
</Signature>
        XML
        assert_equal(clear_enveloping(expected), 
                     clear_enveloping(x.toString), "check signed xml")

        if x.loadFromString('<hello>world!</hello>') < 0
            raise "failed to create XML document"
        end
        s = Xmlsig::Signer.new(x,k)
        s.signInPlace()
        assert_equal(clear_enveloping(expected), 
                     clear_enveloping(x.toString), "should be able to sign again")


        if x.loadFromString('<hello>world!</hello>') < 0
            raise "failed to create XML document"
        end
        s = Xmlsig::Signer.new(x,k)
        x_dup = s.sign()
        original = <<-XML
<?xml version="1.0"?>
<hello>world!</hello>
        XML
        assert_equal(original, x.toString, "sign should preserve the original")
        assert_equal(clear_enveloping(expected), 
                     clear_enveloping(x_dup.toString), "sign should produce a copy")
        s.signInPlace()
        assert_equal(clear_enveloping(expected), 
                     clear_enveloping(x.toString), "signInPlace should still work")


        enveloped = <<-XML
<n0:pdu xmlns:n0="http://a.example">
<n1:elem1 xmlns:n1="http://b.example">
content
</n1:elem1>
</n0:pdu>
        XML
        if x.loadFromString(enveloped) < 0
            raise "failed to create XML document"
        end
        s = Xmlsig::Signer.new(x,k)
        x_dup = s.sign
        expected = <<-XML
<?xml version="1.0"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference URI="#obj1">
<Transforms>
<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>Z1BLe+Di+r3Q88UGYMg0U98+SkQ=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>XnIMidjeC2cwjpx1g5cdUjJhaeOrUn7QVbOp3nZfZ9pX9h0RzNr7IbyBDIFYDz8V
x/pJTrIBwtNRNv/zipgNdO3Zz6k5cKOeh518F+tIVa6LiApywRIUSZJRJRDrkfRI
D+qllTfEz0nBZIkW6R40xawHYXbMi7/jirJPFptIqYW0P/X2QUqoR7tKMB6U7z97
6YXwLTO32O2R1udK8psoKwalOqdmWdR/8xWxLSjLoywyhF6c2+sNIa16BWMilFPX
hCz91erW1LWKcUXgVGbsniG/3Wqz7VXmROf0iYZ56gTLWA2qKRBS8DC3uZo830bq
cG04ZgJEZyAdMCjFcN0kaA==</SignatureValue>
<Object Id="obj1"><n0:pdu xmlns:n0="http://a.example">
<n1:elem1 xmlns:n1="http://b.example">
content
</n1:elem1>
</n0:pdu></Object>
</Signature>
        XML
        assert_equal(clear_enveloping(expected), 
                     clear_enveloping(x_dup.toString), "inclusive c14n")
        s.useExclusiveCanonicalizer('')
        x_dup = s.sign
        expected = <<-XML
<?xml version="1.0"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference URI="#obj1">
<Transforms>
<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>Z1BLe+Di+r3Q88UGYMg0U98+SkQ=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>V/BJBFvJNWJmrPoTcCiEJ+Kiho3oNcwWzBrJIA9uCgl5LXvgJsH1iedVHzPlDyfH
zRxxjx3EiXBpmh92sPmboBcBEOJxEsXRmNNspLjdBlywoAJNSCXqdpWTKpjCeFxe
tefTsPt2u3FvMrHHPzqWJBegHkO1egsAJQ4ZenyfJw6OkXttdj52UJDiUNaoa5mr
ucKC4ccFxbOgtGg7pkfJ1mStvChRABb1a27glf0HkgXrffDkXklVwqmGLw+QD2VK
I3p3jWjicltVHHYazr1GzBG2MJ6JH/6q0cAS1tmXDQZPl/iV7kVX1kiJcjnUHbxi
DaJbsDL5hmar/m7hOKDgHA==</SignatureValue>
<Object Id="obj1"><n0:pdu xmlns:n0="http://a.example">
<n1:elem1 xmlns:n1="http://b.example">
content
</n1:elem1>
</n0:pdu></Object>
</Signature>
        XML
        assert_equal(clear_enveloping(expected), 
                     clear_enveloping(x_dup.toString), "exclusive c14n")

        x = Xmlsig::XmlDoc.new
        if x.loadFromString('<hello>world!</hello>') < 0
            raise "failed to create XML document"
        end
        k = Xmlsig::Key.new
        if k.loadFromFile('t/res/rsakey.pem','pem','') < 0
            raise "failed to load key"
        end
        s = Xmlsig::Signer.new(x,k)
        if s.addCertFromFile('t/res/rsacert.pem', 'pem') < 0
            raise "failed to add cert"
        end
        x_dup = s.sign
        expected = <<-XML
<?xml version="1.0"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference URI="#obj-gXKdX4PpMA">
<Transforms>
<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>FmuiTWZt7LioHNUGy5rSu+lqcNA=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>M7eBJdXlzNuyAFdsFG/6ZHydmmq4X7VLXWixvRnXDZM2xVY1eCi3JtPtOI/qNdEp
FiV8/PvZ2fUQqMdGmKU2HX4RJyf2BuzlrsJ3lGXu84HDSDRnt6TChO2PThFjw7ZP
vicru6g8PN6uK5aWDZ6AXT/aDvwiar1wN0LfAnthnXXByQtIwDbtQLvkbdcoDjVh
YNn2FD/XjXsNtEH2Ny7wWsd3zsX3X3TbYJWyuXfvsg1/rS7m0hLYNM4EDIyAj8CF
BAgYY55DLt8GX7jiKQD/0gYebp0NQCepL02drQ090URMksNyOYIpZwPv2lUfCOAn
5LnFffld7w+CGCIdMegVaQ==</SignatureValue>
<KeyInfo>
<X509Data>
<X509Certificate>MIIE3zCCBEigAwIBAgIBBTANBgkqhkiG9w0BAQQFADCByzELMAkGA1UEBhMCVVMx
EzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1bm55dmFsZTE9MDsGA1UE
ChM0WE1MIFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20v
eG1sc2VjKTEZMBcGA1UECxMQUm9vdCBDZXJ0aWZpY2F0ZTEWMBQGA1UEAxMNQWxl
a3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tMB4X
DTAzMDMzMTA0MDIyMloXDTEzMDMyODA0MDIyMlowgb8xCzAJBgNVBAYTAlVTMRMw
EQYDVQQIEwpDYWxpZm9ybmlhMT0wOwYDVQQKEzRYTUwgU2VjdXJpdHkgTGlicmFy
eSAoaHR0cDovL3d3dy5hbGVrc2V5LmNvbS94bWxzZWMpMSEwHwYDVQQLExhFeGFt
cGxlcyBSU0EgQ2VydGlmaWNhdGUxFjAUBgNVBAMTDUFsZWtzZXkgU2FuaW4xITAf
BgkqhkiG9w0BCQEWEnhtbHNlY0BhbGVrc2V5LmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAJe4/rQ/gzV4FokE7CthjL/EXwCBSkXm2c3p4jyXO0Wt
quaNC3dxBwFPfPl94hmq3ZFZ9PHPPbp4RpYRnLZbRjlzVSOq954AXOXpSew7nD+E
mTqQrd9+ZIbGJnLOMQh5fhMVuOW/1lYCjWAhTCcYZPv7VXD2M70vVXDVXn6ZrqTg
qkVHE6gw1aCKncwg7OSOUclUxX8+Zi10v6N6+PPslFc5tKwAdWJhVLTQ4FKG+F53
7FBDnNK6p4xiWryy/vPMYn4jYGvHUUk3eH4lFTCr+rSuJY8i/KNIf/IKim7g/o3w
Ae3GM8xrof2mgO8GjK/2QDqOQhQgYRIf4/wFsQXVZcMCAwEAAaOCAVcwggFTMAkG
A1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRp
ZmljYXRlMB0GA1UdDgQWBBQkhCzy1FkgYosuXIaQo6owuicanDCB+AYDVR0jBIHw
MIHtgBS0ue+a5pcOaGUemM76VQ2JBttMfKGB0aSBzjCByzELMAkGA1UEBhMCVVMx
EzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1bm55dmFsZTE9MDsGA1UE
ChM0WE1MIFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20v
eG1sc2VjKTEZMBcGA1UECxMQUm9vdCBDZXJ0aWZpY2F0ZTEWMBQGA1UEAxMNQWxl
a3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tggEA
MA0GCSqGSIb3DQEBBAUAA4GBALU/mzIxSv8vhDuomxFcplzwdlLZbvSQrfoNkMGY
1UoS3YJrN+jZLWKSyWE3mIaPpElqXiXQGGkwD5iPQ1iJMbI7BeLvx6ZxX/f+c8Wn
ss0uc1NxfahMaBoyG15IL4+beqO182fosaKJTrJNG3mc//ANGU9OsQM9mfBEt4oL
NJ2D</X509Certificate>
</X509Data>
</KeyInfo>
<Object Id="obj-gXKdX4PpMA"><hello>world!</hello></Object>
</Signature>
        XML
        assert_equal(clear_enveloping(expected), 
                     clear_enveloping(x_dup.toString), 
                     "sign and attach pubkey x509 cert")

        x = Xmlsig::XmlDoc.new
        if x.loadFromString('<hello>world!</hello>') < 0
            raise "failed to create XML document"
        end
        k = Xmlsig::Key.new
        if k.loadHMACFromString('secret') < 0
            raise "failed to load key"
        end
        s = Xmlsig::Signer.new(x,k)
        x_dup = s.sign
        expected = <<-XML
<?xml version="1.0"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>
<Reference URI="#obj1">
<Transforms>
<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>YSHe8XZ7FyBg4bJyb9nB4m0x+uo=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>a2xSwgkUYkby86Rw32ZuJjzrkJQ=</SignatureValue>
<Object Id="obj1"><hello>world!</hello></Object>
</Signature>
        XML
        assert_equal(clear_enveloping(expected), 
                     clear_enveloping(x_dup.toString), 
                     "sign with HMAC")
    end

    def test_id_attr
        xml = <<-XML
<foo>
    <thing id="me">ha ha ha</thing>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1" />
    <Reference URI="#xpointer(id('me'))">
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
      <DigestValue/>
    </Reference>
  </SignedInfo>
  <SignatureValue/>
</Signature>
</foo>
        XML
        x = Xmlsig::XmlDoc.new
        if x.loadFromString(xml) < 0
            raise "error loading XML"
        end
        x.addIdAttr('id','thing','')
        k = Xmlsig::Key.new
        if k.loadHMACFromString("secret") < 0
            raise "error loading key"
        end
        s = Xmlsig::Signer.new(x,k)
        s.signInPlace
        expected = <<-XML
<?xml version="1.0"?>
<foo>
    <thing id="me">ha ha ha</thing>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>
    <Reference URI="#xpointer(id('me'))">
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <DigestValue>LtCo7+kPydkEmDCmDeHN/uw3n7c=</DigestValue>
    </Reference>
  </SignedInfo>
  <SignatureValue>PqQMfXh6WV+vLS2Hn/0kFR2Sl8c=</SignatureValue>
</Signature>
</foo>
        XML
        assert_equal(expected, x.toString, "signedInPlace with ID attribute")
        x = Xmlsig::XmlDoc.new
        if x.loadFromString(xml) < 0
            raise "error loading XML"
        end
        x.addIdAttr('id','thing','')
        s = Xmlsig::Signer.new(x,k)
        x_signed = s.sign
        expected = <<-XML
<?xml version="1.0"?>
<foo>
    <thing id="me">ha ha ha</thing>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>
    <Reference URI="#xpointer(id('me'))">
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <DigestValue>LtCo7+kPydkEmDCmDeHN/uw3n7c=</DigestValue>
    </Reference>
  </SignedInfo>
  <SignatureValue>PqQMfXh6WV+vLS2Hn/0kFR2Sl8c=</SignatureValue>
</Signature>
</foo>
        XML
        assert_equal(expected, x_signed.toString, "signed copy with ID attribute")
    end
    def test_add_verifying_key
        xml = <<-XML
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/> 
    <Reference URI="#object">
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
      <DigestValue/>
    </Reference>
  </SignedInfo>
  <SignatureValue/>
  <KeyInfo>
      <KeyValue/>
  </KeyInfo>
  <Object Id="object">some text</Object>
</Signature>
        XML
        xml = <<-XML
        <hello>world!</hello>
        XML
        x = Xmlsig::XmlDoc.new
        if x.loadFromString(xml) < 0
            raise "error loading XML"
        end
        k = Xmlsig::Key.new
        if k.loadFromFile("t/res/rsakey.pem","pem","") < 0
            raise "error loading key"
        end
        s = Xmlsig::Signer.new(x,k)
        s.attachPublicKey(1)
        s.signInPlace
        expected = <<-XML
<?xml version="1.0"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference URI="#obj1">
<Transforms>
<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>YSHe8XZ7FyBg4bJyb9nB4m0x+uo=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>cAWu6o1UKCUSfsVDlNG6JvE7bj6TrInQPdYYBWn/kR4zkyeSR45IjTjk8ug4w0lP
RJnPkFcxt9KZystNh/84boNPr8dV4aitMVBcwI9KC+wVyTSiNSGoQ97xwNWvV3P0
MuP0IfzwMYEYzaz4BcnLAeBS/zJj1nKBrQl4cPendKz258wND3sCx44gGPBWOe6S
+bgvzO31Dk6bXVid92DU2BBfzJ+vLC/R1pA7zzSbi4IbVOGGxcDwWz1UnXrBWVRv
l0BUrEO/ggm11KrDPywYpDk4K+S77uirJ5ZnE7/80gtVqeUNXFwPDXwxanr4OAYX
Oqke+lk6t9sVyzTbB/AhDw==</SignatureValue>
<KeyInfo>
<KeyValue>
<RSAKeyValue>
<Modulus>
l7j+tD+DNXgWiQTsK2GMv8RfAIFKRebZzeniPJc7Ra2q5o0Ld3EHAU98+X3iGard
kVn08c89unhGlhGctltGOXNVI6r3ngBc5elJ7DucP4SZOpCt335khsYmcs4xCHl+
ExW45b/WVgKNYCFMJxhk+/tVcPYzvS9VcNVefpmupOCqRUcTqDDVoIqdzCDs5I5R
yVTFfz5mLXS/o3r48+yUVzm0rAB1YmFUtNDgUob4XnfsUEOc0rqnjGJavLL+88xi
fiNga8dRSTd4fiUVMKv6tK4ljyL8o0h/8gqKbuD+jfAB7cYzzGuh/aaA7waMr/ZA
Oo5CFCBhEh/j/AWxBdVlww==
</Modulus>
<Exponent>
AQAB
</Exponent>
</RSAKeyValue>
</KeyValue>
</KeyInfo>
<Object Id="obj1"><hello>world!</hello></Object>
</Signature>
        XML
        assert_equal(clear_enveloping(expected), 
                     clear_enveloping(x.toString), 
                     "add raw verifying key")
        x = Xmlsig::XmlDoc.new
        if x.loadFromString('<hello>world!</hello>') < 0
            raise "failed to create XML document"
        end
        k = Xmlsig::Key.new
        if k.loadHMACFromString('secret') < 0
            raise "failed to load key"
        end
        s = Xmlsig::Signer.new(x,k)
        s.attachPublicKey(1)
        x_dup = s.sign
        expected = <<-XML
<?xml version="1.0"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>
<Reference URI="#obj1">
<Transforms>
<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>YSHe8XZ7FyBg4bJyb9nB4m0x+uo=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>a2xSwgkUYkby86Rw32ZuJjzrkJQ=</SignatureValue>
<KeyInfo>
<KeyValue/>
</KeyInfo>
<Object Id="obj1"><hello>world!</hello></Object>
</Signature>
        XML
        assert_equal(clear_enveloping(expected), 
                     clear_enveloping(x_dup.toString), 
                     "sign with HMAC - should not attach key")
    end

    def test_enveloped
        x = Xmlsig::XmlDoc.new
        if x.loadFromString('<hello>world!</hello>') < 0
            raise "failed to create XML document"
        end
        k = Xmlsig::Key.new
        if k.loadFromFile('t/res/rsakey.pem','pem','') < 0
            raise "failed to load key"
        end
        s = Xmlsig::Signer.new(x,k)
        xp = Xmlsig::XPath.new
        xp.setXPath("/hello")
        s.signInPlace(xp)
        expected = <<-XML
<?xml version="1.0"?>
<hello>world!<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference URI="">
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>1yxTNbA2ACee4VdoRgA69iOj6kg=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>R0F67tolSG60Dx7NCsi6f//QboN1FqmQs6C73GiCztY+SLaoOIMohGEWL5dQfvJd
isRn/AVZe+09bBmJLru73b+floTTf+av6sw0j2NsqQroGAuNDwMVk0fJwv8shMoB
wOM35Gp6jHs13FayL7QCf4qw7K+OebQtPdCHos4PkDuvKmMK1F/YpDOsezjo1Wg+
9dKFaTmbeaaq7iY3NlSJaC+kyRUMnlY9jVJWsE/EDTD0XujwlOFhKV9heanPvd+z
dplValY7ioM+T21IW5UUVY0xy8wTXWeaXRWRDuFcoIIF3UX/aeVEmmLhjKuEgD8k
ee1QrIN9c+mr5+W3Je6QTg==</SignatureValue>
</Signature></hello>
        XML
        assert_equal(expected, x.toString, "check signed xml")
    end
end

