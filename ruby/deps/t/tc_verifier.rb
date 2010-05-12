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

class TC_Verifier < Test::Unit::TestCase
    # def setup
    # end

    # def teardown
    # end

    def test_basics
        x = Xmlsig::XmlDoc.new
        xml = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<sxip:envelope xmlns:foo="http://sxip.com/xml-dsig/test/foo#" xmlns:sxip="http://sxip.com/xml-dsig/test#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><sxip:header><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#xpointer(/sxip:envelope/sxip:body/foo:morestuff)"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>NuSUptSOayIh51kdIONXjFeYxMQ=</ds:DigestValue></ds:Reference><ds:Reference URI="#xpointer(/sxip:envelope/sxip:body/sxip:evenMoreSxipStuff)"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>oT0HFNUy26Iea8HBnXsz0+IzPU4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>V64bOOa8ve14Qg0LYETMrV+Eby3go3AAjPgMMwM1swegZKiFYUntin14M7o8v6/TlNMFPlBx
x7vajc6AgVGshLkkvsrzKWktNqcya1k1YGqswxNIPdFsscMRzileSc+Dx61JuXm9Yw2PPl+0
aSmaxeKlrWjo9NOHLdHcmskCTPzqk20glB5SIYIspCnktCnCo1cj6xksOXi6G+ueEk8AVWnR
p07UIPgjWftXtWTDLJNxuhWOHUkpyBcMhCZjbNALq7wIm/pebMPC3gHFWaA8jIz+IIuRzwwj
ik7w/bp7Y81PYQyQGgFXuTs45x+twx4u7BX/RTpfGthpU/Ph3j0EtA==</ds:SignatureValue><ds:KeyInfo><ds:KeyName>Public key of certificate</ds:KeyName><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>oGgoDlqu7bl/TsvRjQs7JnocBR6/Sf8YNSzEc84/4JKiWK/X/3/VALmp8IXazpXSkGbRMqQY
nz9NVirxB6tB7z5p6yCh1oNLglH/vNDLi314RtAy0AU799EcQOJa8ybJR4phLK6uy1IxcBrd
AO2TAh/5QfYTUDsgAmH+FxWOJbwRd76u4+8RCqOFnEbHiKUBA1/N5C6H78+o3fIjfEApSADy
pVegB9UY5rkzPVLCTgKcQb7SOp5WHVteD3IzP0HSB0YsP3Pie9bwVyAzfoh1iq5Enoqnx4eV
APjOAWDf9WqoiBfxmwjqAHTWclDBYw2TOg+e3Lb03rqsKr60imT2uQ==</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue><ds:X509Data><ds:X509Certificate>MIIDATCCAemgAwIBAgIGAQoqb98SMA0GCSqGSIb3DQEBCwUAMEExEzARBgoJkiaJk/IsZAEZ
EwNjb20xFDASBgoJkiaJk/IsZAEZEwRzeGlwMRQwEgYDVQQDEwtJc3N1ZXIgTmFtZTAeFw0w
NjAzMjQwNDA3NTVaFw0yMDAxMDEwODAwMDBaMEIxEzARBgoJkiaJk/IsZAEZEwNjb20xFDAS
BgoJkiaJk/IsZAEZEwRzeGlwMRUwEwYDVQQDEwxTdWJqZWN0IE5hbWUwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCgaCgOWq7tuX9Oy9GNCzsmehwFHr9J/xg1LMRzzj/gkqJY
r9f/f9UAuanwhdrOldKQZtEypBifP01WKvEHq0HvPmnrIKHWg0uCUf+80MuLfXhG0DLQBTv3
0RxA4lrzJslHimEsrq7LUjFwGt0A7ZMCH/lB9hNQOyACYf4XFY4lvBF3vq7j7xEKo4WcRseI
pQEDX83kLofvz6jd8iN8QClIAPKlV6AH1RjmuTM9UsJOApxBvtI6nlYdW14PcjM/QdIHRiw/
c+J71vBXIDN+iHWKrkSeiqfHh5UA+M4BYN/1aqiIF/GbCOoAdNZyUMFjDZM6D57ctvTeuqwq
vrSKZPa5AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAArJTw0B6ZXSqs0oxFkgu5UAws0xdi/8
fuQCYMcV1e1Y8VXYVrmJQv8oaft/iSueyc7QmhOgUpXbqB+ApYhS3Hrk2F5EQthEIFGTWG1K
uxQno0OriMvRTn880SNo5wnl/UeKkp6OwAYGrsVZnxZ1cij+5EVWB8eBXN5OZPbktc/tAuj9
gS3CaEtoO7KQKZjGugwSMBGZwhiECaSn9jb4MotovtZCo5Qp8FJyeYWTgw2S+/HDc5Ot4i2b
pa/U87KGxffQASJcj05ij7HgHnAznvFBuFamNQo2s2sdXTIEKQpJ9804oSGdrdq7VuAOMnXN
uswvjAEdbUfaEBzym0OMghY=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></sxip:header><sxip:body id="Body"><foo:morestuff>Here is more stuff!</foo:morestuff><foo:evenMoreStuff>Here is more stuff!</foo:evenMoreStuff><sxip:evenMoreSxipStuff>Here is more stuff!</sxip:evenMoreSxipStuff></sxip:body></sxip:envelope>
        XML
        if x.loadFromString(xml) == -1
            raise "failed to create XML document"
        end
        xp = Xmlsig::XPath.new()
        xp.addNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
        xp.setXPath('/descendant::ds:Signature[position()=1]')
        v = Xmlsig::Verifier.new(x,xp)
        rc = v.verify
        assert_equal(1,rc,"verify document with namespace using xpath")
    end

    def test_plain_key
        x = Xmlsig::XmlDoc.new
        xml = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/> 
    <Reference URI="#object">
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <DigestValue>7/XTsHaBSOnJ/jXD5v0zL6VKYsk=</DigestValue>
    </Reference>
  </SignedInfo>
  <SignatureValue>BMGn3ftGz476A4ZyCOTf1X2GZ/yMK/o5J3kTg8WSh+56cgLRCQiOrA==</SignatureValue>
  <KeyInfo>
      <KeyValue>
<DSAKeyValue>
<P>
mTNzLdDnUE8esvAOW+m5/GR+2xAuv/5XHRuGP216C1Lh0ofU2978HuCIZgu29ggW
d6nYkRAhpprnw0MvnwQynyvZMs51YyHbSHFIb3eefyg14+Y4/003LrhOQwaPkptA
iUHohW9w7dhqRxKgDbD9T3yYiWr066v02u0jZhMCX/0=
</P>
<Q>
vMMOrPdYTfgRjIwMxAGrvGqpxZM=
</Q>
<G>
kAzI1xXPJ1Qd9V/OKNWuKliEvAWpPcPrshOPajErPXhG2qT15c+oP/CxauG+96RV
qoArUoluexWjySPm6SAZNr+hHQrE/OnV0IIgsiRlUJqxLNNEI6wn6G6FOw6ymUay
RCLAha5VDyoeQ90XA2QdZ7EDXhmom+q6ZjGAsn4dtNk=
</G>
<Y>
bmInlV3nwDyJ/8vck3jOYj3bB2c6gXrvdKQlxNsUvxy5rVfGY7DY+N/5Q4v6S8Q3
Cy6+GgMWIKjnolIpFt8khUUmwV0SNDcgLwsrnEMrZ0kQlMybFBaWqbuTk0FC+ORK
giAQbEuMveocyjZPdHNAHJmDe87nn1nbmBlPpxLQwTg=
</Y>
</DSAKeyValue>
</KeyValue>
  </KeyInfo>
  <Object Id="object">some text</Object>
</Signature>
        XML
        if x.loadFromString(xml) == -1
            raise "failed to create XML document"
        end
        v = Xmlsig::Verifier.new(x)
        rc = v.verify
        assert_equal(1,rc,"verify document containing plain key")
    end
    
    def test_bad_input
        xml = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1" />
    <Reference URI="http://www.w3.org/TR/xml-stylesheet">
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
      <DigestValue>60NvZvtdTB+7UnlLp/H24p7h4bs=</DigestValue>
    </Reference>
  </SignedInfo>
  <SignatureValue>
    MUOjiqG0dbjvR6+qYYPL85nKSt2FeZGQBQkYudv48KyJhJLG1Bp+bA==
  </SignatureValue>
  <KeyInfo>
    <X509Data>
      <X509SubjectName>
        CN=Badb,OU=X/Secure,O=Baltimore Technologies Ltd.,ST=Dublin,C=IE
      </X509SubjectName>
    </X509Data>
  </KeyInfo>
</Signature>
        XML
        x = Xmlsig::XmlDoc.new
        x.loadFromString(xml)
        ks = Xmlsig::KeyStore.new
        ks.addTrustedCertFromFile('t/keys/ca.pem', 'pem')
        ks.addTrustedCertFromFile('t/keys/badb.pem', 'pem')
        ks.addKeyFromFile('t/keys/badb.pem', 'cert_pem', '')
        v = Xmlsig::Verifier.new(x)
        v.setKeyStore(ks)
        assert_equal(1,v.verify, "should work")
    end
end

