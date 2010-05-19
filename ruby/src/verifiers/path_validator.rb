require 'net/http'
require 'uri'

module PathValidator

	def validate_path(paths)
		puts "Found #{paths.length} paths , validating"
		paths.first.each do |certificate|
			validate_status(certificate)
		end	
	end

	def validate_status(certificate)
		revocation_info_url = find_revocation_info(certificate)
		crl = recover_crl(revocation_info_url)
		status_revoked = is_revoked(crl,certificate)
		!status_revoked
	end

	def find_revocation_info(certificate)
		certificate.extensions.to_a.each do |extension|
			oid = extension.oid
			if (oid == "crlDistributionPoints")
				return extension.value
			end
		end
		raise "Revocation info extension not found"	
	end

	def is_revoked(crl,certificate)
		crl.revoked.each do |entry|
			return true if entry.serial == certificate.serial
		end
		return false
	end

	def recover_crl(url)
		new_url = URI.parse(url.split('URI:')[1])
  	        req = Net::HTTP::Get.new(new_url.path)
                res = Net::HTTP.new(new_url.host, new_url.port).start {|http| http.request(req) }
    		return OpenSSL::X509::CRL.new(res.body)				
	end

end
