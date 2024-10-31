body = "hallo\n"
headers = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\n\r\n"
response = "#{headers}#{body}"
uring = IO::Uring.new
server = TCPServer.new(12345)
server.listen(4096)
uring.prep_multishot_accept(server)

phr = Phr.new

while true
  uring.wait do |operation|
    raise operation.errno if operation.errno
    puts "Flags: #{operation.flags}"
    case operation.type
    when :multishot_accept
      puts "Remote Address: #{operation.to_tcpsocket.remote_address.inspect}"
      puts "Socket        : #{operation.res}"
      uring.prep_recv(operation.res)
    when :recv
      next if operation.res == 0 # remote has disconnected
      ret = phr.parse_request(operation.buf)
      case ret
      when :incomplete, :parser_error
        uring.prep_close(operation.socket)
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
      uring.prep_send(operation.socket, response)
    when :send
      uring.prep_close(operation.socket)
    end
  end
end
