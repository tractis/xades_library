(C) Copyright 2006 VeriSign, Inc. 
Developed by Sxip Identity

This is the Ruby xmlsig library wrapper source.

There are two possible source distributions to build from.  The first
includes source for all supported scripting languages, and is run
using makefiles.  The second is a Ruby-only source distribution
built using a standard "extconf.rb" Ruby script.  If there is no file
named "Makefile.ruby" in the same directory as this README file, you
are working from the Ruby-only source distribution.


PREREQUISITES

The prerequisites from the main README file should be installed.
The Ruby language bindings also require additional support packages.


Linux (Red Hat)

The following additional packages are required (as tested version in
brackets):

- ruby (1.8.4-1.fc4)
- ruby-devel (1.8.4-1.fc4)


Windows XP

Install the WIN32 version (1.8.4 as tested) of Ruby from:
  http://rubyinstaller.rubyforge.org/

You will have to replace libeay32.dll in the ruby/bin directory with
the newer one as outlined in the main README.


FreeBSD

Install from the ports tree:

- lang/ruby (1.8.4_5,1)


OS X

Ruby 1.8 must be installed.  The "fink" package management tool
(http://fink.sourceforge.net/) may be used for this; install the
following packages:

- ruby (1.8.1-1)
- ruby18 (1.8.1-1)
- ruby18-dev (1.8.1-1)
- ruby18-shlibs (1.8.1-1)


BUILDING

Ensure that the prerequisites above are met.  Run 
"make -f Makefile.ruby" in the ruby directory to build the module.
This will rebuild the static C++ library if it does not exist, create
the wrapper source using swig and compile it.

If you are building from the Ruby-only source distribution, run the 
following commands:

  ruby extconf.rb
  make

The generated makefile is in the GNU makefile format, on some
platforms you may need to substitute "gmake" for "make".  On Windows,
use the "nmake" make utility.


INSTALLING

Run "make -f Makefile.ruby install" in the python directory.  If
installing from the Ruby-only source distribution, run:

  make install


TESTING

Run the following command to exercise the Ruby interface:

  ruby runtests.rb


TODO
