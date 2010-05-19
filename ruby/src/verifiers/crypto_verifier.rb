#!/usr/bin/env ruby

# (C) Copyright 2010 Tractis, Inc.
# Developed by Dave Garcia
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
class CryptoVerifier
	def verify(signature_document, context)
		x = Xmlsig::XmlDoc.new		
		#attached signature verification		
		if x.loadFromString(signature_document) == -1
	            raise "failed to create XML document"
        	end

		xp = Xmlsig::XPath.new()
	        xp.addNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
	        xp.setXPath('/descendant::ds:Signature[position()=1]')
	        v = Xmlsig::Verifier.new(x,xp)
		context[:signature] = v
		context[:document] = x
		v.skipCertCheck(1)

	        rc = v.verify

		return rc == 1
	end
end
