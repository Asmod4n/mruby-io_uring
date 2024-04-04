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

while true
  uring.wait do |type, userdata| # this function tells you when a command has finished and gives you back its reply.
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

```

Error Handling
==============

System type errors, aka, when a io_uring fuction directly returns an arror are raised according to the errno specification.
uring.wait handles errors a little bit like go, the last field of the userdata array can be an error, or doesnt exist.
The error handling is up to the library user for maximal flexibility and speed, when error is set it is an exception object with a special field named .sock so you know which socket caused an error.

Benchmark
=========

Tested on Windows 11 inside a wsl 2 VM. Ryzen 7 5800x, 32gb DDR 3200 Ram.
```pre
hey -z 3s -cpus 3 http://127.0.0.1:12345

Summary:
  Total:        3.0014 secs
  Slowest:      0.0052 secs
  Fastest:      0.0000 secs
  Average:      0.0009 secs
  Requests/sec: 57303.0477

  Total data:   1031946 bytes
  Size/request: 6 bytes

Response time histogram:
  0.000 [1]     |
  0.001 [10756] |■■■
  0.001 [136651]        |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.002 [20481] |■■■■■■
  0.002 [3105]  |■
  0.003 [728]   |
  0.003 [194]   |
  0.004 [48]    |
  0.004 [21]    |
  0.005 [3]     |
  0.005 [3]     |


Latency distribution:
  10% in 0.0006 secs
  25% in 0.0007 secs
  50% in 0.0008 secs
  75% in 0.0010 secs
  90% in 0.0012 secs
  95% in 0.0014 secs
  99% in 0.0019 secs

Details (average, fastest, slowest):
  DNS+dialup:   0.0000 secs, 0.0000 secs, 0.0052 secs
  DNS-lookup:   0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:    0.0001 secs, 0.0000 secs, 0.0022 secs
  resp wait:    0.0006 secs, 0.0000 secs, 0.0020 secs
  resp read:    0.0001 secs, 0.0000 secs, 0.0018 secs

Status code distribution:
  [200] 171991 responses
```pre