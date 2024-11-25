require_relative 'mrblib/version.rb'

MRuby::Gem::Specification.new('mruby-io-uring') do |spec|
  spec.license = 'Apache-2.0'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'io_uring for mruby'
  spec.version = IO::Uring::VERSION
  spec.add_dependency 'mruby-io'
  spec.add_dependency 'mruby-socket'
  spec.add_dependency 'mruby-errno'
  spec.add_dependency 'mruby-signal'
  unless File.exists? "#{spec.build_dir}/build/lib/liburing.a"
    command = "mkdir -p #{spec.build_dir}/build && cd #{spec.dir}/deps/liburing/ && ./configure "
    if spec.build.debug_enabled?
      command << "--enable-sanitizer"
    end
    command << " --prefix=\"#{spec.build_dir}/build\" --cc=\"#{spec.cc.command}\" --cxx=\"#{spec.cxx.command}\" && make -j$(nproc) && make install && make clean"
    sh command
  end
  ENV['PKG_CONFIG_PATH'] = "#{spec.build_dir}/build/lib/pkgconfig:" + (ENV['PKG_CONFIG_PATH'] || '')
  spec.cc.flags += [`pkg-config --cflags liburing`.strip]
  spec.cxx.flags += [`pkg-config --cflags liburing`.strip]
  spec.linker.flags_after_libraries += ["#{spec.build_dir}/build/lib/liburing.a"]
end
