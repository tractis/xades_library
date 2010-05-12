
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

CFLAGS   =  -fPIC -O0 -g -pipe -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fasynchronous-unwind-tables -Wall  -fPIC  $(shell xmlsec1-config --crypto=openssl --cflags) -DUNIX_SOCKETS
CPPFLAGS = -I. 
CXXFLAGS = $(CFLAGS) 
LDSHARED = $(CC) -shared $(shell xmlsec1-config --crypto=openssl --libs)
RM = rm -f

LIBS = -ldl -lcrypt -lm -lc
SRCS = Signer.cpp Verifier.cpp Key.cpp XmlDoc.cpp DSig.cpp XPath.cpp KeyStore.cpp X509Certificate.cpp Exceptions.cpp XmlElement.cpp TrustVerifier.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = _xmlsig
DLLIB = $(TARGET).so

CLEANLIBS     = $(TARGET).so $(TARGET).il? $(TARGET).tds $(TARGET).map
CLEANOBJS     = *.o *.a *.s[ol] *.pdb *.exp *.bak *.d

LIBEXT=$(shell perl -MConfig -e 'print $$Config{lib_ext}, "\n"')
TARGETLIB=xmlsig$(LIBEXT)

.PHONY: all clean reallyclean docs

all: $(TARGETLIB)

$(TARGETLIB): $(OBJS)
	rm -f $(TARGETLIB)
	ar -q $(TARGETLIB) $(OBJS)

-include $(OBJS:.o=.d)

clean:
	@-$(RM) $(CLEANLIBS) $(CLEANOBJS) $(CLEANFILES)

reallyclean: clean
	@-$(RM) $(TARGETLIB)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $*.cpp -o $*.o
	$(CXX) -MM $(CXXFLAGS) $(CPPFLAGS) $*.cpp > $*.d

