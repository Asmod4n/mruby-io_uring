# Read by mrbgem.rake under host CRuby (via rake) for spec.version. Not
# compiled into the target mruby binary at all -- IO::Uring::VERSION is
# defined natively in src/mrb_io_uring.cpp instead, right alongside the
# rest of the class, so it's automatically covered by the same
# URING_AVAILABLE gating as everything else there. Bump both together.
IO_URING_VERSION = '0.10.0'
