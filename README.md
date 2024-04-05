# mruby-io_uring

io_uring for mruby (WIP)

Requirements
============
This requires at least Linux 5.6

Supported functions
===================

At the moment the following functions are implemented.
```c
io_uring_queue_init
io_uring_get_sqe
io_uring_submit
io_uring_prep_socket
io_uring_prep_accept
io_uring_prep_recv
io_uring_prep_splice
io_uring_prep_send
io_uring_prep_shutdown
io_uring_prep_close
io_uring_wait_cqe
```

Here is an example on how to use them
-------------------------------------
```ruby
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

```

Benchmark
=========

Tested on Windows 11 inside a wsl 2 VM. Ryzen 7 5800x, 32gb DDR 3200 Ram.
```pre
hey -z 3s -cpus 3 http://127.0.0.1:12345

Summary:
  Total:        3.0012 secs
  Slowest:      0.0052 secs
  Fastest:      0.0000 secs
  Average:      0.0008 secs
  Requests/sec: 59363.8046

  Total data:   1068978 bytes
  Size/request: 6 bytes

Response time histogram:
  0.000 [1]     |
  0.001 [29029] |■■■■■■■■■■
  0.001 [114737]        |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.002 [28962] |■■■■■■■■■■
  0.002 [4150]  |■
  0.003 [924]   |
  0.003 [251]   |
  0.004 [82]    |
  0.004 [18]    |
  0.005 [5]     |
  0.005 [4]     |


Latency distribution:
  10% in 0.0005 secs
  25% in 0.0006 secs
  50% in 0.0008 secs
  75% in 0.0010 secs
  90% in 0.0012 secs
  95% in 0.0014 secs
  99% in 0.0020 secs

Details (average, fastest, slowest):
  DNS+dialup:   0.0000 secs, 0.0000 secs, 0.0052 secs
  DNS-lookup:   0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:    0.0001 secs, 0.0000 secs, 0.0021 secs
  resp wait:    0.0005 secs, 0.0000 secs, 0.0021 secs
  resp read:    0.0001 secs, 0.0000 secs, 0.0021 secs

Status code distribution:
  [200] 178163 responses
```