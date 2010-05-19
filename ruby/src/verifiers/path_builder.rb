module PathBuilder

	#Simple path building alg making chaining by name
	def build_path(already_built, paths, current,candidates)
		#Check if we arrived to a Trust anchor
		if current.subject.to_s == current.issuer.to_s 
			paths[:built] << already_built + [current]
		else
			candidates.each do |candidate|
				if link?(current, candidate)
						build_path(already_built + [current] ,paths,candidate, candidates) 	
				end
				paths[:partial] << already_built
			end	

		end
		paths
	end

	def link?(certificate,issuer)
		#TODO check key linking
		certificate.issuer.to_s == issuer.subject.to_s
	end

end
