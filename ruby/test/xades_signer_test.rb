require 'test/unit'

class XadesSignerTest < Test::Unit::TestCase

	def test_create_simple_signature
		having_default_features
		signature_body = @signature.sign()
		#The signature must be valid, just wait for the validator to be created!
	end

	def test_no_location_fails
		assert_raise(RuntimeError) do 
			having_default_features_with_no_city
			@signature.sign()
		end
	end

	def test_provided_attributes_are_present_on_signature

	end

	private

	def having_default_features
		@signature = XadesSignature.new(:sign,default_signed_attributes.merge(default_signed_documents))
		initialize_default_pkcs12_store
	end

	def having_default_features_with_no_city
		@signature = XadesSignature.new(:sign,default_signed_attributes_no_city.merge(default_signed_documents))
		initialize_default_pkcs12_store
	end

	def initialize_default_pkcs12_store
		@signature.set_pkcs12_keystore(File.dirname(__FILE__) + "/fixtures/demo.p12","1111")	
	end

	def default_signed_documents
		{:documents => { "Contract1" => "<a xmlns='http://a.b.com'/>", "Contract2" => "<b/>", "Contract3" => "<c/>"}}
	end

	def default_signed_attributes_no_city
		atts = default_signed_attributes
		atts[:signed_attributes].delete(:city)
		atts
	end

	def default_signed_attributes
		{:signed_attributes => {:city => "Barcelona", :country => "SP"} }
	end
end
