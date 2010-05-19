require 'test/unit'

class XadesVerifierTest < Test::Unit::TestCase

	def test_verify_attached_signature
		options = attached_signature
		signature = XadesSignature.new(:verify,options)	
		assert signature.verify
	end

	def test_verify_altered_signature_detected

	end

	def attached_signature
		{:signature => fixture("attached_signature.xml")}
	end

	def attached_signature_doc_altered
		{:signature => fixture("attached_signature_doc_altered.xml")}
	end
	

	def fixture(name)
		File.read(File.dirname(__FILE__) + "/fixtures/" + name)
	end
end

