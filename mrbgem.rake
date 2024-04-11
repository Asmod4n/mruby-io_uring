MRuby::Gem::Specification.new('mruby-io-uring') do |spec|
  spec.license = 'Apache-2.0'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'io_uring for mruby'
  spec.add_dependency 'mruby-io'
  spec.add_dependency 'mruby-socket'

  unless spec.search_package('liburing')
    raise "mruby-io-uring: cannot find liburing development headers and libraries, please install it."
  end
end
