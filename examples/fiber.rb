fibers = {}

ring = IO::Uring.new
ring.prep_openat2('fiber.rb', File.open(File.expand_path(File.dirname(__FILE__))))

while true
    ring.wait do |operation|
        #puts operation.inspect
        case operation.type
        when :openat2
            ring.prep_read_fixed(operation.file)
            ring.prep_openat2('basic_http.rb', File.open(File.expand_path(File.dirname(__FILE__))))
        when :read_fixed
            ring.prep_close(operation.file)
        end
    end
end