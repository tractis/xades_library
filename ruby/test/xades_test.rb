class XadesTest < Test::Unit

	def test_create_simple_signature
		signature_body = @signature.sign()
		#The signature must be valid, just wait for the validator to be created!
	end

	def test_no_location_fails
		assert_raise do 
			having_default_features_with_no_city
			@signature.sign()
		end
	end


	private

	def having_default_features
		@signature = XadesSignature.new({default_signed_attributes, default_signed_documents})
		initialize_default_pkcs12_store
	end

	def having_default_features_with_no_city
		@signature = XadesSignature.new({default_signed_attributes_no_city, default_signed_documents})
		initialize_default_pkcs12_store
	end

	def initialize_default_pkcs12_store
		@signature.set_pkcs12_keystore("/home/dave/demo.p12","1111")	
	end

	def default_signed_documents
		{:enveloped_documents => { "Contract1" => "<a/>", "Contract2" => "<b/>", "Contract3" => "<c/>"}
	end

	def default_signed_attributes_no_city
		atts = default_signed_attributes
		atts.delete(:city)
		atts
	end

	def default_signed_attributes
		{:signed_attributes => {:city => "Barcelona", :country => "SP"} }
	end
end
