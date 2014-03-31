make;
umount -t u2fs /tmp/lower/;
rmmod u2fs;
insmod fs/u2fs/u2fs.ko;
mount -t u2fs /tmp/lower/ /tmp/upper/;
