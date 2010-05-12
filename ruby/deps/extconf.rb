#!/usr/bin/env ruby

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

require 'fileutils'
require 'mkmf'

if /mswin32|cygwin|mingw|bccwin/ =~ RUBY_PLATFORM
    basedir = "../libext/win32-deps"
    if !test(?d, basedir + "/include")
        basedir = "../"
    end
    incdir = basedir + "/include"
    libdir = basedir + "/lib"
    lib_list = [ "libxmlsec.lib", "libxslt.lib", "libxml2.lib", "zlib.lib", "libxmlsec-openssl.lib", "libeay32.lib", "ssleay32.lib" ]

    $CFLAGS << " /EHsc /DWIN32 /D_STATIC_CPPLIB=1 /D__XMLSEC_FUNCTION__=__FUNCTION__ /DXMLSEC_NO_XKMS=1 /DXMLSEC_CRYPTO=\\\"openssl\\\" /DXMLSEC_OPENSSL_097=1 /DXMLSEC_CRYPTO_OPENSSL=1 /DNDEBUG /I#{incdir}"
    $LIBS << " msvcprt.lib " + (lib_list.collect { |x| libdir + "/" + x }).join(" ")
else 
    $CFLAGS << " $(shell xmlsec1-config --crypto=openssl --cflags) -DUNIX_SOCKETS -DNDEBUG"
    $LIBS << " -lstdc++"
    CONFIG['LDSHARED'] << " $(shell xmlsec1-config --crypto=openssl --libs)"
    # fix to force C++ linker 
    CONFIG['LDSHARED'].sub!(/^g?cc/, "g++") 
end
$objs = []
for f in Dir[File.join('src', "*.{#{SRC_EXT.join(%q{,})}}")]
  $objs.push(File.basename(f, ".*") << "." << $OBJEXT)
end
$objs.push('xmlsig_wrap.' << $OBJEXT)
create_makefile('xmlsig', 'src')
