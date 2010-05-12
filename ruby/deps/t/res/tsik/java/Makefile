
# Copyright 2006 Verisign, Incorporated
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

JAVAC=javac -classpath tsik.jar:.
JAVA=java -classpath tsik.jar:.
CLASSES=Common.class Sign.class Verify.class
IN_DIR=../in
OUT_DIR=../../..
KEYS_DIR=../keys
.PHONY: sign verify verify1 verify2 verify3 verify-self

all: verify

$(CLASSES):  %.class: %.java
	$(JAVAC) $<

# verify output from XMLSig library
verify: verify1 verify2 verify3

verify1: $(CLASSES) $(OUT_DIR)/out_1.xml $(KEYS_DIR)/Alice.cer
	$(JAVA) Verify $(OUT_DIR)/out_1.xml $(KEYS_DIR)/Alice.cer

verify2: $(CLASSES) $(OUT_DIR)/out_2.xml
	$(JAVA) Verify $(OUT_DIR)/out_2.xml

verify3: $(CLASSES) $(OUT_DIR)/out_3.xml
	$(JAVA) Verify $(OUT_DIR)/out_3.xml

# sign if you need to re-gen the files in ../in/
# the cert_only_out.xml is an out.xml with the expanded
# public key removed
sign: $(IN_DIR)/out.xml

$(IN_DIR)/out.xml: $(CLASSES) $(KEYS_DIR)/priv.xml $(KEYS_DIR)/cert.x509 in.xml
	$(JAVA) Sign $(KEYS_DIR)/priv.xml $(KEYS_DIR)/cert.x509 in.xml $(IN_DIR)/out.xml

# verifies our own output
verify-self: $(IN_DIR)/out.xml
	$(JAVA) Verify $(IN_DIR)/out.xml
	$(JAVA) Verify $(IN_DIR)/cert_only_out.xml

clean:
	@-$(RM) $(CLASSES)
