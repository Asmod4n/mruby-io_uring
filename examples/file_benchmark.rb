# Measure the time before the benchmark starts
setup_start_time = Chrono::Steady.now

def measure_performance(ring, fd, filesize)
  i = 0
  current_pos = 0
  read_bytes = 0

  # Calculate the number of recv operations needed to read the whole file
  num_operations = (filesize.to_f / ring.fixed_buffer_size).ceil

  start = Chrono::Steady.now
  while (Chrono::Steady.now - start) < 1
    # Issue the prep_read_fixed function calls
    ring.prep_read_fixed(fd, current_pos)
    current_pos += ring.fixed_buffer_size
    (num_operations - 1).times do
      ring.prep_read_fixed(fd, current_pos, IO::Uring::Operation::SQE_IO_LINK)
      current_pos += ring.fixed_buffer_size
    end

    # Run ring.wait with the number of completion queue events to wait for
    ring.wait(num_operations, 1) do |operation|
      if operation.errno
        puts operation.inspect
        raise operation.errno 
      end
      case operation.type
      when :read_fixed
        read_bytes += operation.res
      else
        raise "unkown operation: #{operation.inspect}"
      end
      i += 1
    end
  
    current_pos = 0
  end

  elapsed_time = Chrono::Steady.now - start
  ops_per_second = i / elapsed_time
  gbps = (read_bytes / elapsed_time) / (1000000000)

  return { ops_per_second: ops_per_second, gbps: gbps, read_bytes: read_bytes, elapsed_time: elapsed_time }
end

ring = IO::Uring.new
ring.prep_openat2('file.txt', File.open(File.expand_path(File.dirname(__FILE__))))
filesize = File.size(File.expand_path(File.dirname(__FILE__)) + '/file.txt')
fd = nil
ring.wait(1, 1) do |operation|
  fd = operation.file
end

setup_time = Chrono::Steady.now - setup_start_time

benchmark_start = Chrono::Steady.now

result = measure_performance(ring, fd, filesize)

benchmark_time = Chrono::Steady.now - benchmark_start

output_calculation_start = Chrono::Steady.now

puts "Fixed Buffer Size   : #{ring.fixed_buffer_size}"
puts "Performance         : #{result[:gbps].round(2)} GBps, #{result[:ops_per_second].round(2)} ops/sec"
puts "Benchmark setup time: #{setup_time.round(6)} seconds"
puts "Benchmark run   time: #{benchmark_time.round(6)} seconds"
puts "Output time         : #{(Chrono::Steady.now - output_calculation_start).round(6)} seconds"