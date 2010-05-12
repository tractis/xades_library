#!/usr/bin/env bash
ruby extconf.rb
make
ruby runtests.rb
