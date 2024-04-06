body = "hallo\n"
headers = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\n\r\n"
response = "#{headers}#{body}"
uring = IO::Uring.new
server = TCPServer.new(12345)
server.listen(4096)
uring.accept(server)

while true
  uring.wait do |userdata|
    case userdata.type
    when :accept
      uring.recv(userdata.res).accept(server)
    when :recv
      uring.send(userdata.sock, response)
    when :send
      uring.close(userdata.sock)
    end
  end
end
