ring = IO::Uring.new
ring.prep_openat2('file.txt', File.open(File.expand_path(File.dirname(__FILE__))))
filesize = File.size(File.expand_path(File.dirname(__FILE__)) + '/file.txt')

def measure_performance(ring, buffer_size, filesize)
  i = 0
  current_pos = 0
  read_bytes = 0
  start = Chrono::Steady.now

  while i < 100000
    ring.wait do |operation|
      if operation.errno
        puts operation.inspect
        raise operation.errno 
      end
      case operation.type
      when :openat2
        ring.prep_read_fixed(operation.file, buffer_size, current_pos)
      when :read_fixed
        if current_pos < filesize
          current_pos += operation.res
        else
          current_pos = 0
        end
        ring.prep_read_fixed(operation.file, buffer_size, current_pos)
        read_bytes += operation.res
      end
      i += 1
    end
  end

  elapsed_time = Chrono::Steady.now - start
  ops_per_second = 100000 / elapsed_time
  gbps = (read_bytes / elapsed_time) / (1024**3)

  return ops_per_second, gbps, read_bytes, elapsed_time
end

best_buffer_size = 4096
best_ops_per_second, best_gbps, best_read_bytes, best_elapsed_time = measure_performance(ring, best_buffer_size, filesize)

buffer_size = 8192 # Starting with 8 KB
increment = 4096 # Increase buffer size in steps of 8 KB

while buffer_size <= 1048576 # Max buffer size 1 MB
  ops_per_second, gbps, read_bytes, elapsed_time = measure_performance(ring, buffer_size, filesize)

  if ops_per_second > best_ops_per_second || gbps > best_gbps
    best_buffer_size = buffer_size
    best_ops_per_second = ops_per_second
    best_gbps = gbps
    best_read_bytes = read_bytes
    best_elapsed_time = elapsed_time
  else
    break
  end

  buffer_size += increment
end

puts "Optimal buffer size: #{best_buffer_size} bytes"
puts "Read #{best_read_bytes} bytes in #{best_elapsed_time.round(6)} seconds"
puts "Performance: #{best_gbps.round(6)} GBps, #{best_ops_per_second.round(2)} ops/sec"
