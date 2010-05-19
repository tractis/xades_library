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

module XadesSigner
	def create_signature(key, documents,certificate,signed_attributes)
		#signing certificate
		signing_certificate = Xmlsig::X509Certificate.new
		signing_certificate_file = dump_to_temp("cert",@certificate.to_pem)

		body = signature_body(documents, certificate, signed_attributes)
		
		signer = Xmlsig::Signer.new(body, key)
		signer.addCertFromFile(signing_certificate_file.path,"pem")
		
		begin
			signer.sign
		rescue => e
			puts "Cannot perform signature, cause #{e}"
			throw e
		end
	end

	private

	def signature_body(documents, certificate, signed_attributes)
		body = Xmlsig::XmlDoc.new
		       xml = <<-XML
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id='Signature'>
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>#{properties_reference}#{document_references(documents)}</ds:SignedInfo>
<ds:SignatureValue/>
<ds:KeyInfo>
<ds:X509Data><ds:X509Certificate/></ds:X509Data>
</ds:KeyInfo>
<ds:Object>#{qualifiying_properties(certificate, signed_attributes)}</ds:Object>
#{document_objects(documents)}</ds:Signature>
        XML
		body.loadFromString(xml.to_s)
		body
	end

	def properties_reference
		xml = <<-REF
<ds:Reference URI="#SignedProperties" Type='http://uri.etsi.org/01903#SignedProperties'>
<ds:Transforms>
<ds:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
<ds:DigestValue/>
</ds:Reference>
		REF
		xml
	end

	def document_references(documents)
			refs = []
			documents.each_pair do |identifier,document| 
				refs << <<-REFERENCE 
<ds:Reference URI="##{identifier}">
<ds:Transforms>
<ds:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
<ds:DigestValue/>
</ds:Reference>
				REFERENCE
			end
			refs.join('')
	end

	def document_objects(documents)
		docs = []		
		documents.each_pair do |identifier,document| 
			docs << <<-DOCUMENT
<ds:Object Id="#{identifier}">#{document}</ds:Object>
				DOCUMENT
		end
		docs.join('')
	end

	def digest(content)
		Base64.encode64(OpenSSL::Digest::SHA1.digest(content)).gsub("\n","")
	end

	def qualifiying_properties(signing_certificate, signed_attributes)
		signing_time = Time.new.utc.iso8601 #Time MUST be in zulu form and timezone must be utc
		cert_digest = digest(signing_certificate.to_der)
		cert_issuer = signing_certificate.issuer.to_s(OpenSSL::X509::Name::RFC2253)
		cert_serial = signing_certificate.serial

		#Signed attributes provided by user
		city = signed_attributes[:city] #City
		country = signed_attributes[:country] #Country
		#Commitment could be provided if not a default one will be used
		commitment_identifier = signed_attributes[:commitment].nil? ? "http://github.com/tractis/xades_library/commitments#signContract" : signed_attributes[:commitment]
		
		<<-QP 
<xades:QualifyingProperties xmlns:xades='http://uri.etsi.org/01903/v1.3.2#' Target='#Signature'>
<xades:SignedProperties Id='SignedProperties'>
<xades:SignedSignatureProperties>
<xades:SigningTime>#{signing_time}</xades:SigningTime>
<xades:SigningCertificate>
<xades:Cert>
<xades:CertDigest>
<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'/>
<ds:DigestValue>#{cert_digest}</ds:DigestValue>
</xades:CertDigest>
<xades:IssuerSerial>
<ds:X509IssuerName>#{cert_issuer}</ds:X509IssuerName>
<ds:X509SerialNumber>#{cert_serial}</ds:X509SerialNumber>
</xades:IssuerSerial>
</xades:Cert>
</xades:SigningCertificate>
<xades:SignatureProductionPlace>
<xades:City>#{city}</xades:City>
<xades:CountryName>#{country}</xades:CountryName>
</xades:SignatureProductionPlace>
</xades:SignedSignatureProperties>
<xades:SignedDataObjectProperties>
<xades:CommitmentTypeIndication>
<xades:CommitmentTypeId>
<xades:Identifier>#{commitment_identifier}</xades:Identifier>
</xades:CommitmentTypeId>
<xades:AllSignedDataObjects/>
</xades:CommitmentTypeIndication></xades:SignedDataObjectProperties>
</xades:SignedProperties>
<xades:UnsignedProperties></xades:UnsignedProperties>
</xades:QualifyingProperties>
		QP
	end
end
