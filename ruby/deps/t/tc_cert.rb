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

class TC_Cert < Test::Unit::TestCase
    def test_cert_basics
        c = Xmlsig::X509Certificate.new
        if c.loadFromFile("t/keys/badb.pem", "cert_pem") < 0
            raise "failed to load cert"
        end
        assert_equal("CN=Badb,OU=X/Secure,O=Baltimore Technologies Ltd.,ST=Dublin,C=IE",
        c.getSubjectDN, "subject DN matches")
        assert_equal("CN=Another Transient CA,OU=X/Secure,O=Baltimore Technologies Ltd.,ST=Dublin,C=IE",
        c.getIssuerDN, "issuer DN matches")
        assert_equal(3, c.getVersion, "version matches")
        assert_equal(1, c.isValid, "cert is valid")
    end
end
