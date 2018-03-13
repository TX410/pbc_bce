#!/usr/bin/env python

APPNAME = 'bce'

top = '.'
out = 'build'

def options(opt):
  opt.load(['compiler_c', 'compiler_cxx'])

def configure(conf):
  conf.load(['compiler_c', 'compiler_cxx'])

def build(bld):
  bld.read_shlib('pbc', paths=['/usr/local/lib'])
  bld.read_shlib('gmp', paths=['/usr/lib/x86_64-linux-gnu'])
  bld.program(source='testbce.c src/bce.c', target='test', use='pbc gmp', includes="src")

