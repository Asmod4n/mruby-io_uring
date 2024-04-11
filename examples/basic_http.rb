body = "hallo\n"
headers = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\n\r\n"
response = "#{headers}#{body}"
uring = IO::Uring.new
phr = Phr.new
server = TCPServer.new(12345)
server._setnonblock(true)
server.listen(4096)
uring.prep_accept(server)

while true
  uring.wait do |userdata|
    case userdata.type
    when :accept
#      puts "Remote Address: #{userdata.to_tcpsocket.remote_address.inspect}"
#      puts "Socket        : #{userdata.res}"
      uring.prep_recv(userdata.res).prep_accept(server)
    when :recv
      next if userdata.res == 0
      uring.prep_send(userdata.sock, response)
    end
  end
end
