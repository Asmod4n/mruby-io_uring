require_relative 'version.rb'

MRuby::Gem::Specification.new('mruby-io-uring') do |spec|
  spec.license = 'Apache-2.0'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'io_uring for mruby'
  spec.version = IO_URING_VERSION
  spec.add_dependency 'mruby-io'
  spec.add_dependency 'mruby-socket'
  spec.add_dependency 'mruby-errno'
  # liburing lives in mruby-slipstreamio: carried there as a submodule
  # and built with the seam underneath, so the SAME binary answers from
  # the kernel where io_uring is allowed and from slipstream's engine
  # where it is not - decided at runtime, per process. That gem exports
  # the installed liburing headers and links the archive; this gem just
  # writes #include <liburing.h> and asks slipstream_syscall_uses_engine
  # which side answered, for URING_AVAILABLE (:native or :shim).
  spec.add_dependency 'mruby-slipstreamio', github: 'Asmod4n/slipstreamIO', branch: 'backend-split'

  spec.cxx.flags << '-std=c++17'
end
