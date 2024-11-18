assert('File io') do
    ring = IO::Uring.new
    ring.prep_openat2('file.txt', File.open(File.expand_path(File.dirname(__FILE__))))

    ring.wait do |operation|
        ring.prep_read(operation.file)
    end

    ring.wait do |operation|
        assert_equal(operation.buf, File.read(File.expand_path(File.dirname(__FILE__)) + '/file.txt', operation.buf))
    end
end
