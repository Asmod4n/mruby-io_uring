class Statx
    attr_reader :mask, :blksize, :attributes, :nlink, :uid, :gid, :mode, :ino, :size, :blocks,
                :attributes_mask, :atime, :btime, :ctime, :mtime, :rdev, :dev, :mnt_id,
                :dio_mem_align, :dio_offset_align

    def convert_timestamps
        # Convert timestamps to Time objects
        @atime = Time.at(@atime_sec, @atime_nsec / 1_000)
        @btime = Time.at(@btime_sec, @btime_nsec / 1_000)
        @ctime = Time.at(@ctime_sec, @ctime_nsec / 1_000)
        @mtime = Time.at(@mtime_sec, @mtime_nsec / 1_000)
        
        # Combine major and minor numbers
        @rdev = major_minor(@rdev_major, @rdev_minor)
        @dev = major_minor(@dev_major, @dev_minor)
    end

    private

    def major_minor(major, minor)
        (major << 8) | minor
    end
end