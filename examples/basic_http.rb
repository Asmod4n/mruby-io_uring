server = TCPServer.new(12345)
server._setnonblock(true)
server.listen(4096)
uring = IO::Uring.new
uring.accept(server)

body = "hallo\n"
headers = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\n\r\n"
response = headers + body

while true
  userdata = uring.wait
  case userdata.type
  when :accept
    uring.recv(userdata.sock).accept(server)
  when :recv
    uring.send(userdata.sock, response)
  when :send
    uring.close(userdata.sock)
  end
end
