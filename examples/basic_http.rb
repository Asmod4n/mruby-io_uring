body = "hallo\n"
headers = ["HTTP/1.1 200 OK", "Content-Type: text/plain", "Connection: keep-alive" ,"Content-Length: #{body.bytesize}\r\n\r\n"].join("\r\n")
response = headers + body

server = TCPServer.new(12345)
server.listen(4096)
server._setnonblock(true)
uring = IO_Uring.new
uring.accept(server)

while true
  uring.wait do |type, socket, ret, error|
    raise error if error
    case type
    when :socket
    when :accept
      uring.recv(socket)
      uring.accept(server)
    when :recv
      uring.send(socket, response)
    when :send
      uring.close(socket)
    when :close
    end
  end
end
