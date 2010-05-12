
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

.PHONY: sign verify verify-self java-verify build clean

RUBY=ruby
RM=rm
SIGN_OUTPUT=../out_1.xml ../out_2.xml ../out_3.xml

all: sign verify verify-self java-verify

verify: verify.rb build
	$(RUBY) $<

java-verify: $(SIGN_OUTPUT) build
	make -C ../res/tsik/java verify

sign: $(SIGN_OUTPUT) build

$(SIGN_OUTPUT): sign.rb 
	$(RUBY) $<

verify-self: verify_own.rb $(SIGN_OUTPUT) build
	$(RUBY) $<

build:
	make -C ../../ -f Makefile.ruby build

clean:
	@-make -C ../res/tsik/java clean
	@-$(RM) $(SIGN_OUTPUT)

