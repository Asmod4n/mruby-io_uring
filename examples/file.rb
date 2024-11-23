ring = IO::Uring.new
ring.prep_openat2('file.txt', File.open(File.expand_path(File.dirname(__FILE__))))
filesize = File.size(File.expand_path(File.dirname(__FILE__)) + '/file.txt')

i = 0
current_pos = 0
read_bytes = 0
start = Chrono::Steady.now

while i < 1000000
    ring.wait do |operation|
        raise operation.errno if operation.errno
        case operation.type
        when :openat2
            ring.prep_read_fixed(operation.file, 131072, current_pos)
        when :read_fixed, :read
            if current_pos < filesize
                current_pos += operation.res
            else
                current_pos = 0
            end
            ring.prep_read_fixed(operation.file, 131072, current_pos)
            read_bytes += operation.res
        end
    end
    i+=1
end

puts "Read #{read_bytes} bytes in #{Chrono::Steady.now - start} Seconds"