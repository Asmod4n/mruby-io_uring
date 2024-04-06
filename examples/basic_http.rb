body = "hallo\n"
headers = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\n\r\n"
response = "#{headers}#{body}"
uring = IO::Uring.new
server = TCPServer.new(12345)
server._setnonblock(true)
server.listen(4096)
uring.accept(server)

phr = Phr.new

while true
  uring.wait do |userdata|
    raise userdata.errno if userdata.errno
    case userdata.type
    when :accept
      puts "Addrlist    : #{userdata.addrlist.inspect}"
      puts "Socket      : #{userdata.res}"
      uring.recv(userdata.res).accept(server)
    when :recv
      next if userdata.res == 0
      ret = phr.parse_request(userdata.buf)
      case ret
      when :incomplete, :parser_error
        uring.close(userdatta.sock)
        phr.reset
        next
      when Integer
        puts "HTTP Method : #{phr.method}"
        puts "HTTP Version: 1.#{phr.minor_version}"
        puts "HTTP Path   : #{phr.path}"
        puts "HTTP Headers: #{phr.headers.inspect}"
        puts "HTTP Body   : #{userdata.buf.byteslice(ret..-1).inspect}"
      end
      phr.reset
      uring.send(userdata.sock, response)
    when :send
      uring.close(userdata.sock)
    end
  end
end
