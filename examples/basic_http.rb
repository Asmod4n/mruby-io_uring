body = "hallo\n"
headers = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\n\r\n"
response = "#{headers}#{body}"
uring = IO::Uring.new
server = TCPServer.new(0)
server.listen(4096)
puts server.local_address.ip_port
uring.prep_multishot_accept(server)

phr = Phr.new

while true
  uring.wait do |operation|
    if operation.errno
      puts operation.inspect
      raise operation.errno 
    end
    puts "Flags: #{operation.flags}"
    case operation.type
    when :multishot_accept
      puts "Remote Address: #{operation.to_io.remote_address.inspect}"
      puts "Socket        : #{operation.res}"
      uring.prep_recv(operation.res)
    when :recv
      next if operation.res == 0 # remote has disconnected
      ret = phr.parse_request(operation.buf)
      case ret
      when :incomplete, :parser_error
        uring.prep_close(operation.sock)
        phr.reset
        next
      when Integer
        puts "HTTP Method   : #{phr.method}"
        puts "HTTP Version  : 1.#{phr.minor_version}"
        puts "HTTP Path     : #{phr.path}"
        puts "HTTP Headers  : #{phr.headers.inspect}"
        puts "HTTP Body     : #{operation.buf.byteslice(ret..-1).inspect}"
      end
      phr.reset
      uring.prep_send(operation.sock, response)
    when :send
      uring.prep_close(operation.sock)
    end
  end
end
