ring = IO::Uring.new
ring.prep_openat2('file.txt', File.open(File.expand_path(File.dirname(__FILE__))))

read_bytes = 0
i = 0
start = Chrono::Steady.now

while i < 1000000
    ring.wait do |operation|
        #raise operation.errno if operation.errno
        #puts operation.inspect
        case operation.type
        when :openat2
            ring.prep_read_fixed(operation.file, 131072, 0)
        when :read_fixed, :read
            ring.prep_read_fixed(operation.file, 131072, 0)
            read_bytes += operation.buf.bytesize
        end
    end
    i+=1
end

puts "Read #{read_bytes} bytes in #{Chrono::Steady.now - start} Seconds"