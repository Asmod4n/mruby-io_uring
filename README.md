# mruby-io_uring

io_uring for mruby

Requirements
============
This requires at least Linux 5.6

Supported functions
===================

At the moment the following functions are implemented.
```c
io_uring_queue_init
io_uring_prep_socket
io_uring_prep_accept
io_uring_prep_recv
io_uring_prep_send
io_uring_prep_close
io_uring_wait_cqe
```

Here is an example on how to use them
-------------------------------------
```ruby
body = "hallo\n"
headers = ["HTTP/1.1 200 OK", "Content-Type: text/plain", "Connection: keep-alive" ,"Content-Length: #{body.bytesize}\r\n\r\n"].join("\r\n")
response = headers + body

server = TCPServer.new(12345)
server.listen(4096)
server._setnonblock(true)
uring = IO_Uring.new # this sets up one io_uring
uring.accept(server) # this sends a command to create a accept socket
socket = nil

while true
  uring.wait do |type, userdata| # this function tells you when a command has finished and gives you back its reply.
    case type
    when :socket # this gets set when a socket command has completed, the userdata is filled with the socket descriptor of the client
      socket = userdata
    when :accept # this gets set when a accept command has completed
      uring.accept(server)
      uring.recv(userdata[0]) # the first part of each userdata array is a socket descriptor
      # the second part of the userdata array holds the info of the connected client, aka IPv4 or v6, it's port and it's ip Address.
    when :recv # the second part of the userdata array is filled with the client message
      uring.send(userdata[0], response)
    when :send
      uring.close(userdata[0])
    when :close
    end
  end
end

```