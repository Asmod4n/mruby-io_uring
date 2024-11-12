MRuby::Gem::Specification.new('mruby-io-uring') do |spec|
  spec.license = 'Apache-2.0'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'io_uring for mruby'
  spec.add_dependency 'mruby-socket'
  spec.add_test_dependency 'mruby-phr'

  unless File.exists? "#{spec.build_dir}/build/lib/liburing.a"
    sh "mkdir -p #{spec.build_dir}/build && cd #{spec.dir}/deps/liburing/ && ./configure --prefix=\"#{spec.build_dir}/build\" --cc=\"#{spec.cc.command}\" --cxx=\"#{spec.cxx.command}\" && make -j$(nproc) && make install"
  end
  ENV['PKG_CONFIG_PATH'] = "#{spec.build_dir}/build/lib/pkgconfig:" + (ENV['PKG_CONFIG_PATH'] || '')
  spec.cc.flags += [`pkg-config --cflags liburing`.strip]
  spec.cxx.flags += [`pkg-config --cflags liburing`.strip]
  spec.linker.flags_before_libraries += ["#{spec.build_dir}/build/lib/liburing.a"]
end
