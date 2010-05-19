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

require 'xmlsig'
require 'openssl'
require 'tempfile'
require 'base64'


class XadesSignature

	include XadesSigner
	include XadesVerifier

	def init_verify(options)
		init_docs(options)
		raise "Signature must be provided as :signature" if options[:signature].nil?
		@signature = options[:signature]
	end

	def initialize(mode, options)
		if mode == :sign 
			init_sign(options)
		elsif mode == :verify
			init_verify(options)
		else
			raise "Unsupported mode provided, only supported :sign and verify"
		end
	end

	def init_sign(options)
		#We add a reference for every document to be signed
		init_docs(options)
		@signed_attributes = validate_signed_attributes(options[:signed_attributes])
	end

	def init_docs(options)
		#If many docs are provided and topology is attached signature will be enveloping documents
		#Todo, add enveloped signature
		@documents = options[:documents]
	end

	def set_pkcs12_keystore(keystore, credentials)
		store = OpenSSL::PKCS12::PKCS12.new(File.read(keystore),credentials)
		@certificate = store.certificate
		@key = store.key
	end

	def sign
		#signing_key 	
		key = Xmlsig::Key.new
		key.loadFromFile(dump_to_temp("key",@key.to_s).path,'pem','')

		signature = create_signature(key, @documents, @certificate, @signed_attributes)
		#We return the string representation of the signature		
		signature.toString()
	end

	def verify
		verify_signature(@signature)
	end

	private 

	def dump_to_temp(prefix, content)
		temp_file = Tempfile.new(prefix)
		temp_file << content
		temp_file.flush 
		
		temp_file
	end
	

	def prepare_evenloped(enveloping_options)
		raise "Enveloped signatures are not supported yet"
	end

	def validate_signed_attributes(attributes)
		raise "Signed attributes cannot be blank" if attributes.nil? or attributes.empty?
		#Attributes must include city and country where the signature have been produced 
		[:city,:country].each do |att|
			raise "Attribute #{att} must be specified as signed attribute" unless (attributes.keys.include?(att) and not attributes[att].nil?)
		end 
		attributes
	end
end

require 'time'

class Time
    def full_date_and_time
      strftime('%Y-%m-%d %H:%M:%S %Z')
    end

    def iso8601
      strftime('%Y-%m-%dT%H:%M:%SZ') # the final "Z" means "Zulu time" which is ok since we're now doing all times in UTC
    end
end
	

