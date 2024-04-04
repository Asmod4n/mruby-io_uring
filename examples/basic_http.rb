body = "hallo\n"
headers = ["HTTP/1.1 200 OK", "Content-Type: text/plain", "Connection: keep-alive" ,"Content-Length: #{body.bytesize}\r\n\r\n"].join("\r\n")
response = headers + body

server = TCPServer.new(12345)
server.listen(4096)
server._setnonblock(true)
uring = IO_Uring.new
uring.accept(server)

while true
  uring.wait do |type, userdata|
    case type
    when :socket
      socket, error = userdata
    when :accept
      socket, addrlist, error = userdata
      uring.accept(server)
      uring.recv(socket)
    when :recv
      socket, buff, error = userdata
      uring.send(socket, response)
    when :send
      socket, send, error = userdata
      uring.close(socket)
    when :close
      socket, error = userdata
    end
  end
end
