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
      puts userdata
    when :accept
      uring.accept(server)
      uring.recv(userdata[0])
    when :recv
      uring.send(userdata[0], response)
    when :send
      uring.close(userdata[0])
    when :close
    end
  end
end
