body = "hallo\n"
headers = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\n\r\n"
response = "#{headers}#{body}"
uring = IO::Uring.new
server = TCPServer.new(12345)
server.listen(4096)
uring.prep_accept(server)

phr = Phr.new

while true
  uring.wait do |userdata|
    raise userdata.errno if userdata.errno
    case userdata.type
    when :accept
      puts "Remote Address: #{userdata.to_tcpsocket.remote_address.inspect}"
      puts "Socket        : #{userdata.res}"
      uring.prep_recv(userdata.res)
      uring.prep_accept(userdata.socket)
      #userdata.res  is the accepted socket
      #userdata.socket is the socket passed to prep_accept, aka the server socket.
    when :recv
      next if userdata.res == 0
      ret = phr.parse_request(userdata.buf)
      case ret
      when :incomplete, :parser_error
        uring.prep_close(userdata.socket)
        phr.reset
        next
      when Integer
        puts "HTTP Method   : #{phr.method}"
        puts "HTTP Version  : 1.#{phr.minor_version}"
        puts "HTTP Path     : #{phr.path}"
        puts "HTTP Headers  : #{phr.headers.inspect}"
        puts "HTTP Body     : #{userdata.buf.byteslice(ret..-1).inspect}"
      end
      phr.reset
      uring.prep_send(userdata.socket, response)
    when :send
      uring.prep_close(userdata.socket)
    end
  end
end
