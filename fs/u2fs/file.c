/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "u2fs.h"
#define FILLDIR_SIZE 100

#ifdef CONFIG_U2_DUP_ELIMINATION
#define DUP_ELIM true
#else
#define DUP_ELIM false
#endif
static ssize_t u2fs_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	int err = -ENOENT, i;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry, *lower_dentry;
	UDBG;
	for (i = 0; i < 2; i++) {
		lower_dentry = u2fs_get_lower_dentry(dentry, i);
		if (!lower_dentry || !lower_dentry->d_inode)
			continue;
		lower_file = u2fs_lower_file(file, i);
		err = vfs_read(lower_file, buf, count, ppos);
		break;
	}
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);

	return err;
}

static ssize_t u2fs_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	int err = -ENOENT;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry, *lower_dentry;

	//u2fs_read_lock(dentry->d_sb, U2FS_SMUTEX_PARENT);
	//u2fs_lock_dentry(dentry, U2FS_DMUTEX_CHILD);

	//err = u2fs_file_revalidate(file, parent, true);
	//if (unlikely(err))
	//	goto out;
	UDBG;
	lower_dentry = u2fs_get_lower_dentry(dentry, 0);
	if (!lower_dentry || !lower_dentry->d_inode)
		return err;
	lower_file = u2fs_lower_file(file, 0);
	err = vfs_write(lower_file, buf, count, ppos);

	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
		fsstack_copy_attr_times(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
		U2FS_F(file)->wrote_to_file = true; /* for delayed copyup */
		//	u2fs_check_file(file);
	}

	//u2fs_unlock_dentry(dentry);
	//u2fs_read_unlock(dentry->d_sb);
	return err;
}

/* Taken from u2fs. based on generic filldir in fs/readir.c */
static int u2fs_filldir(void *dirent, const char *oname, int namelen,
		loff_t offset, u64 ino, unsigned int d_type)
{
	struct u2fs_getdents_buf *buf = dirent;
	//struct filldir_node *found = NULL;
	int err = 0;
	int is_whiteout;
	char *name = (char *) oname;
	struct filldir_node *found = NULL;
	//buf->filldir_called++;


	is_whiteout = is_whiteout_name(&name, &namelen);


	/* if 'name' isn't a whiteout, filldir it. */
	if (!is_whiteout) {
		/* Find Deleted Entry */
		if (buf->is_right)
			found = find_filldir_node(name, namelen, buf->heads, buf->heads_size);
		if (found)
			goto out;
		//off_t pos = rdstate2offset(buf->rdstate);

		/* Check how to send pos ? */
		err = buf->filldir(buf->dirent, name, namelen, offset,
				ino, d_type);
		//buf->rdstate->offset++;
		//verify_rdstate_offset(buf->rdstate);
	}


#if 0
	/*
	 * If we did fill it, stuff it in our hash, otherwise return an
	 * error.
	 */
	if (err) {
		buf->filldir_error = err;
		goto out;
	}

	buf->entries_written++;
#endif
	if (!err && ((DUP_ELIM || is_whiteout) && !buf->is_right))
		err = add_filldir_node(name, namelen,
				is_whiteout, buf->heads, buf->heads_size);
#if 0
	if (err)
		buf->filldir_error = err;

#endif

out:
	return err;
}

static int u2fs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct list_head filldir_heads[FILLDIR_SIZE];
	int index;
	int err = 0;


	struct u2fs_getdents_buf buf;
	init_filldir_heads(filldir_heads, FILLDIR_SIZE);
	printk("Read Dir Called\n");

	buf.dirent = dirent;
	buf.filldir = filldir;
	buf.heads = filldir_heads;
	buf.heads_size = FILLDIR_SIZE;

	for (index = 0; index < 2; index++) {
		buf.is_right = (index == 1);
		printk("lowerFile %d\n",index);
		lower_file = u2fs_lower_file(file, index);
		if (!lower_file)
			continue;
		err = vfs_readdir(lower_file, u2fs_filldir, &buf);
		file->f_pos = lower_file->f_pos;
		if (err >= 0)		/* copy the atime */
			fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
		else break;
	}
	if (!err)
		file->f_pos = DIREOF;
	free_filldir_heads(filldir_heads, FILLDIR_SIZE);
	return err;
}

static long u2fs_unlocked_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = u2fs_lower_file(file, 0);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

out:
	return err;
}

#ifdef CONFIG_COMPAT
static long u2fs_compat_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = u2fs_lower_file(file, 0);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int u2fs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = u2fs_lower_file(file, 0);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "u2fs: lower file system does not "
				"support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!U2FS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "u2fs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
		err = do_munmap(current->mm, vma->vm_start,
				vma->vm_end - vma->vm_start);
		if (err) {
			printk(KERN_ERR "u2fs: do_munmap failed %d\n", err);
			goto out;
		}
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &u2fs_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;

	file->f_mapping->a_ops = &u2fs_aops; /* set our aops */
	if (!U2FS_F(file)->lower_vm_ops) /* save for our ->fault */
		U2FS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int __open_dir(struct inode *inode, struct file *file,
		struct dentry *parent)
{
	struct dentry *lower_dentry;
	struct file *lower_file;
	struct vfsmount *lower_mnt;
	struct dentry *dentry = file->f_path.dentry;
	int index;
	for (index = 0; index < 2; index++) {
		lower_dentry =
			u2fs_get_lower_dentry(dentry, index);
		if (!lower_dentry || !lower_dentry->d_inode)
			continue;

		dget(lower_dentry);
		lower_mnt = u2fs_mntget(dentry, index);
		if (!lower_mnt)
			lower_mnt = u2fs_mntget(parent, index);
		lower_file = dentry_open(lower_dentry, lower_mnt, file->f_flags,
				current_cred());
		UDBG;
		if (IS_ERR(lower_file))
			return PTR_ERR(lower_file);

		u2fs_set_lower_file(file, index, lower_file);
		if (!u2fs_get_lower_mnt(dentry, index))
			u2fs_set_lower_mnt(dentry, index, lower_mnt);

		/*
		 * The branchget goes after the open, because otherwise
		 * we would miss the reference on release.
		 */
		//branchget(inode->i_sb, index);
	}

	return 0;
}

/* u2fs_open helper function: open a file */
static int __open_file(struct inode *inode, struct file *file,
		struct dentry *parent)
{
	struct dentry *lower_dentry;
	struct file *lower_file;
	int lower_flags;
	struct dentry *dentry = file->f_path.dentry;
	struct vfsmount *lower_mnt;
	int bIndex = 0;

	printk("Open File: %s\n", dentry->d_name.name);
	lower_dentry = u2fs_get_lower_dentry(dentry, 0);
	if (!lower_dentry || !lower_dentry->d_inode) {
		lower_dentry = u2fs_get_lower_dentry(dentry, 1);
		bIndex = 1;
	}
	lower_flags = file->f_flags;


	/*
	 * check for the permission for lower file.  If the error is
	 * COPYUP_ERR, copyup the file.
	 */
	if (lower_dentry->d_inode && bIndex) {
		/*
		 * if the open will change the file, copy it up otherwise
		 * defer it.
		 */
		printk("in if\n");
		if ((lower_flags & O_TRUNC) || (lower_flags & O_APPEND)) {
			int size = i_size_read(lower_dentry->d_inode);
			int err = -EROFS;
			UDBG;
			err = copyup_file(parent->d_inode, file, size);
			UDBG;
			if (err)
				return err;
			lower_dentry = u2fs_get_lower_dentry(dentry, 0);
			bIndex = 0;

		} else {
			lower_flags &= ~(OPEN_WRITE_FLAGS);
		}
	}

	dget(lower_dentry);

	/*
	 * dentry_open will decrement mnt refcnt if err.
	 * otherwise fput() will do an mntput() for us upon file close.
	 */
	lower_mnt = u2fs_mntget(dentry, bIndex);
	lower_file = dentry_open(lower_dentry, lower_mnt, lower_flags,
			current_cred());
	if (IS_ERR(lower_file))
		return PTR_ERR(lower_file);

	u2fs_set_lower_file(file, bIndex, lower_file);
	//branchget(inode->i_sb, bstart);

	return 0;
}

int u2fs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *parent;
	//	int valid = 0;

	//u2fs_read_lock(inode->i_sb, U2FS_SMUTEX_PARENT);
	parent = u2fs_lock_parent(dentry);
	//u2fs_lock_dentry(dentry, U2FS_DMUTEX_CHILD);

	/* don't open unhashed/deleted files */
	if (d_deleted(dentry)) {
		err = -ENOENT;
		goto out_nofree;
	}

	/* XXX: should I change 'false' below to the 'willwrite' flag? */
	/*	valid = __u2fs_d_revalidate(dentry, parent, false);
		if (unlikely(!valid)) {
		err = -ESTALE;
		goto out_nofree;
		}
	 */
	file->private_data =
		kzalloc(sizeof(struct u2fs_file_info), GFP_KERNEL);
	if (unlikely(!U2FS_F(file))) {
		err = -ENOMEM;
		goto out_nofree;
	}

	/*
	 * open all directories and make the u2fs file struct point to
	 * these lower file structs
	 */
	if (S_ISDIR(inode->i_mode))
		err = __open_dir(inode, file, parent); /* open a dir */
	else
		err = __open_file(inode, file, parent);	/* open a file */

	/* freeing the allocated resources, and fput the opened files */
	if (err) {
		u2fs_put_all_lower_files(file);
		kfree(U2FS_F(file));
	}
out_nofree:
	if (!err) {
		//u2fs_postcopyup_setmnt(dentry);
		fsstack_copy_attr_all(inode, u2fs_lower_inode(inode));
		//u2fs_check_file(file);
		//u2fs_check_inode(inode);
	}
	//u2fs_unlock_dentry(dentry);
	u2fs_unlock_parent(dentry, parent);
	//u2fs_read_unlock(inode->i_sb);
	return err;
}

static int u2fs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = u2fs_lower_file(file, 0);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush)
		err = lower_file->f_op->flush(lower_file, id);

	return err;
}

/* release all lower object references & free the file info structure */
static int u2fs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;
	struct dentry *lower_dentry;
	struct dentry *dentry = file->f_path.dentry;
	int index;
	for (index = 0; index < 2; index++) {

		lower_file = u2fs_lower_file(file, index);
		if (lower_file) {
			u2fs_set_lower_file(file, index, NULL);
			fput(lower_file);
		}

		lower_dentry =
			u2fs_get_lower_dentry(dentry, index);
		if (!lower_dentry)
			continue;
		printk("Dentry put %p\n", lower_dentry);
		//TODO: Check for all references
		if (d_deleted(lower_dentry)) {
			dput(lower_dentry);
			u2fs_set_lower_dentry(dentry, index, NULL);
		}
	}
	if (dentry) {
		//	dput(dentry);
		printk("Dentry Address %p\n", dentry);
		printk("Dentry Count %d\n", dentry->d_count);
	}

	kfree(U2FS_F(file));
	return 0;
}

static int u2fs_fsync(struct file *file, loff_t start, loff_t end,
		int datasync)
{
	int err, i;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry, *lower_dentry;

	UDBG;
	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	err = -ENOENT;
	for (i = 0; i < 2; i++) {
		lower_dentry = u2fs_get_lower_dentry(dentry, i);
		if (!lower_dentry || !lower_dentry->d_inode)
			continue;
		lower_file = u2fs_lower_file(file, i);
		err = vfs_fsync_range(lower_file, start, end, datasync);
		break;
	}
out:
	return err;
}

static int u2fs_fasync(int fd, struct file *file, int flag)
{
	int err = 0, i;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry, *lower_dentry;
	err = -ENOENT;
	UDBG;
	for (i = 0; i < 2; i++) {
		lower_dentry = u2fs_get_lower_dentry(dentry, i);
		if (!lower_dentry || !lower_dentry->d_inode)
			continue;
		lower_file = u2fs_lower_file(file, i);
		err = 0;
		if (lower_file->f_op && lower_file->f_op->fasync)
			err = lower_file->f_op->fasync(fd, lower_file, flag);
		break;
	}


	return err;
}

const struct file_operations u2fs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= u2fs_read,
	.write		= u2fs_write,
	.unlocked_ioctl	= u2fs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= u2fs_compat_ioctl,
#endif
	.mmap		= u2fs_mmap,
	.open		= u2fs_open,
	.flush		= u2fs_flush,
	.release	= u2fs_file_release,
	.fsync		= u2fs_fsync,
	.fasync		= u2fs_fasync,
};

/* trimmed directory options */
const struct file_operations u2fs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= u2fs_readdir,
	.unlocked_ioctl	= u2fs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= u2fs_compat_ioctl,
#endif
	.open		= u2fs_open,
	.release	= u2fs_file_release,
	.flush		= u2fs_flush,
	.fsync		= u2fs_fsync,
	.fasync		= u2fs_fasync,
};
