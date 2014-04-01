make;
umount -t u2fs null;
rmmod u2fs;
insmod fs/u2fs/u2fs.ko;
mount -t u2fs -o ldir=/left/dir,rdir=/right/dir null /mnt/u2fs;
