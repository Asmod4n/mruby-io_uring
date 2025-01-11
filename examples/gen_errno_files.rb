require 'fileutils'

# Directory to store the error files
output_dir = 'error_files'
FileUtils.mkdir_p(output_dir)

# Function to map errno to HTTP status codes
def map_errno_to_http(err)
  case err
  when Errno::EACCES::Errno, Errno::EPERM::Errno, Errno::EROFS::Errno
    '403 Forbidden'
  when Errno::EADDRINUSE::Errno, Errno::EALREADY::Errno, Errno::EEXIST::Errno, Errno::EINPROGRESS::Errno
    '409 Conflict'
  when Errno::EADDRNOTAVAIL::Errno, Errno::EAFNOSUPPORT::Errno, Errno::EDESTADDRREQ::Errno, Errno::EINVAL::Errno,
       Errno::EISCONN::Errno, Errno::ENOTDIR::Errno, Errno::ENOTSOCK::Errno, Errno::EPROTONOSUPPORT::Errno,
       Errno::ESOCKTNOSUPPORT::Errno, Errno::EOPNOTSUPP::Errno, Errno::EPFNOSUPPORT::Errno
    '400 Bad Request'
  when Errno::EAGAIN::Errno, Errno::ENOMEM::Errno
    '503 Service Unavailable'
  when Errno::ECONNABORTED::Errno, Errno::ECONNREFUSED::Errno, Errno::ECONNRESET::Errno,
       Errno::EHOSTDOWN::Errno, Errno::EHOSTUNREACH::Errno, Errno::ENETDOWN::Errno,
       Errno::ENETRESET::Errno, Errno::ENETUNREACH::Errno
    '502 Bad Gateway'
  when Errno::ETIMEDOUT::Errno
    '504 Gateway Timeout'
  when Errno::EMFILE::Errno
    '429 Too Many Requests'
  when Errno::ENAMETOOLONG::Errno
    '414 URI Too Long'
  when Errno::ENOSPC::Errno
    '507 Insufficient Storage'
  when Errno::ENOENT::Errno
    '404 Not Found'
  when Errno::EFBIG::Errno
    '413 Payload Too Large'
  else
    '500 Internal Server Error'
  end
end

# Generate a file for each unique HTTP status code dynamically
Errno.constants.each do |const|
  if Errno.const_get(const).is_a?(Class) && Errno.const_get(const).ancestors.include?(SystemCallError)
    err = Errno.const_get(const).new.errno
    status_line = map_errno_to_http(err)
    generic_message = "An error occurred. Please try again later."

    file_path = File.join(output_dir, "#{err}.txt")
    File.open(file_path, 'w') do |file|
      file.write "HTTP/1.1 #{status_line}\r\n"
      file.write "Content-Type: text/plain\r\n"
      file.write "Content-Length: #{generic_message.bytesize}\r\n"
      file.write "Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate\r\n"
      file.write "Connection: close\r\n"
      file.write "Expires: 0\r\n"
      file.write "\r\n"
      file.write generic_message
    end
  end
end

puts "Error files generated in #{output_dir} directory."
