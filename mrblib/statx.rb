class Statx
  attr_reader :mask, :blksize, :attributes, :nlink, :uid, :gid, :mode, :ino, :size, :blocks,
              :attributes_mask, :attr_compressed, :attr_immutable, :attr_append, :attr_nodump,
              :attr_encrypted, :attr_automount, :attr_mount_root, :attr_verity, :attr_dax,
              :atime, :btime, :ctime, :mtime, :rdev, :rdev_major, :rdev_minor, :dev_major,
              :dev_minor, :mnt_id, :dio_mem_align, :dio_offset_align, :subvol,
              :atomic_write_unit_min, :atomic_write_unit_max, :atomic_write_segments_max
end
