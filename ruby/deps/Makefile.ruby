
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

EXTNAME=xmlsig
DLEXT=$(shell perl -MConfig -e 'print $$Config{dlext}, "\n"')
LIBEXT=$(shell perl -MConfig -e 'print $$Config{lib_ext}, "\n"')
EXTDLL=$(EXTNAME).$(DLEXT)
EXTWRAPPER=$(EXTNAME)_wrap.cpp
EXTMAKEFILE=Makefile
VERSION=$(shell perl -e 'open(F,"../VERSION") or print "0.0.0" and exit;$$_=readline(F);chomp;print')
TMPDIR:=build-$(shell echo $$$$)
TBDIR=$(EXTNAME)-$(VERSION)-ruby
TBFILE=$(TBDIR).tar.gz

RM=rm -f
LN=ln
CP=cp
FIND=find
SWIG=swig
RUBY=ruby

SETUP = src swig README VERSION LICENSE scripts

all: sdist bdist

.PHONY: all build sdist bdist install clean reallyclean test uninstall wrapper

test: build
	$(RUBY) runtests.rb

src:
	@-$(LN) -s ../src src

swig:
	@-$(LN) -s ../swig swig

scripts:
	@-$(LN) -s ../scripts scripts

README: ../README
	$(CP) ../README .

VERSION: ../VERSION
	$(CP) ../VERSION .

LICENSE: ../LICENSE
	$(CP) ../LICENSE .

$(EXTWRAPPER): src swig swig/xmlsig.i
	$(SWIG) -c++ -ruby -o $(EXTWRAPPER) swig/xmlsig.i

wrapper: $(EXTWRAPPER) 

$(EXTMAKEFILE): extconf.rb
	$(RUBY) extconf.rb 

$(EXTDLL): wrapper $(EXTMAKEFILE)
	$(MAKE)

PRUNE=-name .svn -o -name build-\* -o -name \*~ -o -name .DS_Store -o \
	-name $(EXTNAME)-\*.tar.gz -o -name Makefile -o -name \*.o \
	-o -name swig -o -name Makefile.ruby 
sdist: $(SETUP) clean $(EXTWRAPPER)
	$(RM) $(TBFILE)
	mkdir -vp $(TMPDIR)/$(TBDIR)
	$(FIND) . -mindepth 1 \( \( \( $(PRUNE) \) -a -prune \) -o \( -type d -a -print \) \) | sed 's,^./,,'| xargs -I {} mkdir -v $(TMPDIR)/$(TBDIR)/{} 
	mkdir -v $(TMPDIR)/$(TBDIR)/src
	mkdir -v $(TMPDIR)/$(TBDIR)/scripts
	$(FIND) -L . \( \( $(PRUNE) \) -a -prune \) -o \( \( -type f \) -a -print \)| sed 's,^./,,'| xargs -I {} cp -v {} $(TMPDIR)/$(TBDIR)/{} 
	cp -v README VERSION LICENSE $(TMPDIR)/$(TBDIR)/
	cd $(TMPDIR) && tar czf $(TBFILE) $(TBDIR) && cp $(TBFILE) ..
	$(RM) -r $(TMPDIR)

build: $(EXTDLL)

bdist: build

install:
	$(MAKE) install

uninstall:

clean:
	@-bash -c 'if test -f Makefile; then make clean; fi'
	@-$(RM) $(EXTMAKEFILE) $(EXTWRAPPER) *.cpp *.h
	@-$(RM) -r build-*

reallyclean: clean
	@-$(RM) $(SETUP)
