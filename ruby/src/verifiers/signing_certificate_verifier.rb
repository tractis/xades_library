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
require 'rexml/document'
require 'base64'
require 'openssl'

class SigningCertificateVerifier

	include PathBuilder
	include PathValidator

	def verify(signature, context)
		signature = context[:signature]
		document = context[:document]

		doc = REXML::Document.new(document.toString)		
		certificates = REXML::XPath.match(doc,"//ds:X509Certificate/text()")
		
		#Find the one matching with signing certificate
		
		signing_certificate = get_signing_certificate(doc,certificates)

		result = build_path([], {:partial => [], :built => []}, signing_certificate, ca_certificates)
		raise "Cannot build path" if result[:built].nil?

		validate_path(result[:built])
	end


	def get_signing_certificate(document, certificates)
		signing_certificate = get_signing_certificate_data(document)
		certificates.each do |certificate_body|
			parsed_cert = parse_cert(certificate_body.to_s)
			#Todo add more checks not only digest
			return parsed_cert if check_digest(parsed_cert, signing_certificate)
		end
	end

	def digest(content)
		Base64.encode64(OpenSSL::Digest::SHA1.digest(content)).gsub("\n","")
	end

	def check_digest(certificate,signing_certificate)
		expected = signing_certificate[:digest]
		found = digest(certificate.to_der)
		
		expected == found
	end

	def get_signing_certificate_data(document)
		cert_digest = REXML::XPath.first(document,"//xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue/text()")

		{:digest => cert_digest}
	end

	def ca_certificates
		[cert("camerfirma-chambers-of-commerce-root.cer"), cert("camerfirma-certificados-camerales.cer"),cert("tractis-root.cer")]
	end

	def cert(name)
		OpenSSL::X509::Certificate.new(File.read("/usr/local/data/oisf/cacerts/" + name))
	end

	def parse_cert(body)
		OpenSSL::X509::Certificate.new(Base64.decode64(body))				
	end

end
