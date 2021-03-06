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

static int u2fs_create(struct inode *dir, struct dentry *dentry,
		int mode, struct nameidata *nd)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path *left_path, saved_path;

	left_path = u2fs_get_path(dentry, 0);
	lower_dentry = left_path->dentry;

	err = mnt_want_write(left_path->mnt);
	if (err)
		goto out;
	if (has_valid_parent(lower_dentry))
		err = check_unlink_whiteout(dentry, lower_dentry);
	if (err > 0)    /* ignore if whiteout found and removed */
		err = 0;
	if (err && err != -EROFS)
		goto out_mnt;
	/*
	 * If we get here, then check if copyup needed.  If lower_dentry is
	 * NULL, create the entire dentry directory structure in branch 0.
	 */
	if (!has_valid_parent(lower_dentry)) {
		lower_dentry = create_parents(dir, dentry,
				dentry->d_name.name);
		if (IS_ERR(lower_dentry)) {
			err = PTR_ERR(lower_dentry);
			goto out_mnt;
		}
	}

	lower_parent_dentry = u2fs_lock_parent(lower_dentry);

	pathcpy(&saved_path, &nd->path);
	pathcpy(&nd->path, left_path);
	err = vfs_create(lower_parent_dentry->d_inode, lower_dentry, mode, nd);
	pathcpy(&nd->path, &saved_path);
	if (err)
		goto out_unlock;

	err = u2fs_interpose(dentry, dir->i_sb);
	if (err)
		goto out_unlock;
	fsstack_copy_attr_times(dir, u2fs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out_unlock:
	u2fs_unlock_parent(lower_dentry, lower_parent_dentry);
out_mnt:
	mnt_drop_write(left_path->mnt);
out:
	return err;
}

/* copy a/m/ctime from the lower branch with the newest times */
void u2fs_copy_attr_times(struct inode *upper)
{
	struct inode *lower;

	if (!upper)
		return;
	lower = u2fs_lower_inode(upper);
	if (!lower)
		return; /* not all lower dir objects may exist */
	if (unlikely(timespec_compare(&upper->i_mtime,
					&lower->i_mtime) < 0))
		upper->i_mtime = lower->i_mtime;
	if (unlikely(timespec_compare(&upper->i_ctime,
					&lower->i_ctime) < 0))
		upper->i_ctime = lower->i_ctime;
	if (unlikely(timespec_compare(&upper->i_atime,
					&lower->i_atime) < 0))
		upper->i_atime = lower->i_atime;
}


static int u2fs_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;

	file_size_save = i_size_read(old_dentry->d_inode);

	lower_old_dentry = u2fs_get_lower_dentry(old_dentry, 0);
	lower_new_dentry = u2fs_get_lower_dentry(new_dentry, 0);

	if (!has_valid_parent(lower_new_dentry)) {
		err = -EPERM;
		return err;
	}

	if (!lower_old_dentry || !lower_old_dentry->d_inode)
		lower_old_dentry = u2fs_get_lower_dentry(old_dentry, 1);


	lower_dir_dentry = lock_parent(lower_new_dentry);


	err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
			lower_new_dentry);
	if (err || !lower_new_dentry->d_inode)
		goto out;

	err = u2fs_interpose(new_dentry, dir->i_sb);

	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_new_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_new_dentry->d_inode);
	set_nlink(old_dentry->d_inode,
			u2fs_lower_inode(old_dentry->d_inode)->i_nlink);
	i_size_write(new_dentry->d_inode, file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	return err;
}

static int u2fs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry = NULL, *parent, *dent_temp;
	struct dentry *lower_dir_dentry;
	struct vfsmount *mnt = NULL, *mnt_temp;
	int err, index = 1;
	bool is_right_valid = false, is_left_valid = false;
	parent = dget_parent(dentry);
	do {
		dent_temp = u2fs_get_lower_dentry(dentry, index);
		mnt_temp = u2fs_get_lower_mnt(dentry, index);
		if (dent_temp && dent_temp->d_inode) {
			if (index)
				is_right_valid = true;
			else
				is_left_valid = true;
			lower_dentry = dent_temp;
			mnt = mnt_temp;
		}
		index--;
	} while (index >= 0);
	UDBG;
	if (!lower_dentry || !lower_dentry->d_inode) {
		err = -ENOENT;
		goto out_return;
	}

	UDBG;
	dget(lower_dentry);
	lower_dir_dentry = u2fs_get_lower_dentry(parent, is_left_valid ? 0 : 1);

	UDBG;
	err = mnt_want_write(mnt);
	if (err)
		goto out_unlock;
	/*Delete File in left brach*/
	UDBG;
	if (is_left_valid) {
		if (!S_ISDIR(lower_dentry->d_inode->i_mode))
			err = vfs_unlink(lower_dir_dentry->d_inode, \
					lower_dentry);
		else
			err = vfs_rmdir(lower_dir_dentry->d_inode,
					lower_dentry);

	}

	UDBG;
	if (err)
		goto out;
	if (is_right_valid)
		err = create_whiteout(dentry);
	if (!err)
		inode_dec_link_count(dentry->d_inode);
	set_nlink(dentry->d_inode,
		  u2fs_lower_inode(dentry->d_inode)->i_nlink);

	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
	UDBG;
out:
	mnt_drop_write(mnt);
	UDBG;
out_unlock:
	UDBG;
	dput(lower_dentry);
	UDBG;
out_return:
	dput(parent);
	UDBG;
	return err;
}



static int u2fs_symlink(struct inode *dir, struct dentry *dentry,
		const char *symname)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	umode_t mode;

	lower_dentry = u2fs_get_lower_dentry(dentry, 0);

	if (has_valid_parent(lower_dentry))
		err = check_unlink_whiteout(dentry, lower_dentry);
	if (err > 0)    /* ignore if whiteout found and removed */
		err = 0;
	if (err && err != -EROFS)
		goto out;

	/*
	 * If we get here, then check if copyup needed.  If lower_dentry is
	 * NULL, create the entire dentry directory structure in branch 0.
	 */
	if (!has_valid_parent(lower_dentry)) {
		lower_dentry = create_parents(dir, dentry,
				dentry->d_name.name);
		if (IS_ERR(lower_dentry)) {
			err = PTR_ERR(lower_dentry);
			goto out;
		}
	}


	lower_parent_dentry = lock_parent(lower_dentry);
	if (IS_ERR(lower_parent_dentry)) {
		err = PTR_ERR(lower_parent_dentry);
		goto out_unlock;
	}

	mode = S_IALLUGO;
	err = vfs_symlink(lower_parent_dentry->d_inode, lower_dentry, symname);
	if (!err) {
		err = u2fs_interpose(dentry, dir->i_sb);
		if (!err) {
			u2fs_copy_attr_times(dir);
			fsstack_copy_inode_size(dir,
					lower_parent_dentry->d_inode);
		}
	}

out_unlock:
	unlock_dir(lower_parent_dentry);

	if (!err)
		u2fs_postcopyup_setmnt(dentry);
out:
	return err;
}


static int u2fs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path *left_path;

	left_path = u2fs_get_path(dentry, 0);
	lower_dentry = left_path->dentry;

	err = mnt_want_write(left_path->mnt);
	if (err)
		goto out;

	if (has_valid_parent(lower_dentry))
		err = check_unlink_whiteout(dentry, lower_dentry);
	if (err > 0)    /* ignore if whiteout found and removed */
		err = 0;
	if (err && err != -EROFS)
		goto out_mnt;
	/*
	 * If we get here, then check if copyup needed.  If lower_dentry is
	 * NULL, create the entire dentry directory structure in branch 0.
	 */
	if (!has_valid_parent(lower_dentry)) {
		lower_dentry = create_parents(dir, dentry,
				dentry->d_name.name);
		if (IS_ERR(lower_dentry)) {
			err = PTR_ERR(lower_dentry);
			goto out_mnt;
		}
	}

	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mkdir(lower_parent_dentry->d_inode, lower_dentry, mode);
	if (err)
		goto out_unlock;

	err = u2fs_interpose(dentry, dir->i_sb);
	if (err)
		goto out_unlock;

	fsstack_copy_attr_times(dir, u2fs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
	/* update number of links on parent directory */

	set_nlink(dir, u2fs_lower_inode(dir)->i_nlink);

out_unlock:
	unlock_dir(lower_parent_dentry);
out_mnt:
	mnt_drop_write(left_path->mnt);
out:
	return err;
}
#if 0
static int u2fs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path *left_path;

	left_path = u2fs_get_path(dentry, 0);
	lower_dentry = left_path->dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(left_path->mnt);
	if (err)
		goto out_unlock;
	err = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (dentry->d_inode)
		clear_nlink(dentry->d_inode);
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);

out:
	mnt_drop_write(left_path->mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	return err;
}
#endif

static int u2fs_mknod(struct inode *dir, struct dentry *dentry, int mode,
		dev_t dev)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path *left_path;

	left_path = u2fs_get_path(dentry, 0);
	lower_dentry = left_path->dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(left_path->mnt);
	if (err)
		goto out_unlock;
	err = vfs_mknod(lower_parent_dentry->d_inode, lower_dentry, mode, dev);
	if (err)
		goto out;

	err = u2fs_interpose(dentry, dir->i_sb);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, u2fs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out:
	mnt_drop_write(left_path->mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	return err;
}

/*
 * The locking rules in u2fs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int u2fs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path *lower_old_path, *lower_new_path;

	lower_old_path = u2fs_get_path(old_dentry, 0);
	lower_new_path = u2fs_get_path(new_dentry, 0);
	lower_old_dentry = lower_old_path->dentry;
	lower_new_dentry = lower_new_path->dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = mnt_want_write(lower_old_path->mnt);
	if (err)
		goto out;
	err = mnt_want_write(lower_new_path->mnt);
	if (err)
		goto out_drop_old_write;

	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			lower_new_dir_dentry->d_inode, lower_new_dentry);
	if (err)
		goto out_err;

	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				lower_old_dir_dentry->d_inode);
		fsstack_copy_inode_size(old_dir,
				lower_old_dir_dentry->d_inode);
	}

out_err:
	mnt_drop_write(lower_new_path->mnt);
out_drop_old_write:
	mnt_drop_write(lower_old_path->mnt);
out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	return err;
}
/* requires sb, dentry, and parent to already be locked */
static int __u2fs_readlink(struct dentry *dentry, char __user *buf,
		int bufsiz)
{
	int err;
	struct dentry *lower_dentry;

	lower_dentry = u2fs_get_lower_dentry(dentry, 0);
	if (!lower_dentry || !lower_dentry->d_inode)
		lower_dentry = u2fs_get_lower_dentry(dentry, 1);

	if (!lower_dentry->d_inode->i_op ||
			!lower_dentry->d_inode->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->readlink(lower_dentry,
			buf, bufsiz);
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
				lower_dentry->d_inode);

out:
	return err;
}

static int u2fs_readlink(struct dentry *dentry, char __user *buf,
		int bufsiz)
{
	int err;
	struct dentry *parent;

	parent = u2fs_lock_parent(dentry);

	err = __u2fs_readlink(dentry, buf, bufsiz);

	u2fs_unlock_parent(dentry, parent);

	return err;
}

static void *u2fs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;
	struct dentry *parent;

	parent = u2fs_lock_parent(dentry);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (unlikely(!buf)) {
		err = -ENOMEM;
		goto out;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = __u2fs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = NULL;
		goto out;
	}
	buf[err] = 0;
	nd_set_link(nd, buf);
	err = 0;

out:

	u2fs_unlock_parent(dentry, parent);

	return ERR_PTR(err);
}

/* this @nd *IS* still used */
static void u2fs_put_link(struct dentry *dentry, struct nameidata *nd,
		void *cookie)
{
	struct dentry *parent;
	char *buf;

	parent = u2fs_lock_parent(dentry);

	buf = nd_get_link(nd);
	if (!IS_ERR(buf))
		kfree(buf);
	u2fs_unlock_parent(dentry, parent);
}

static int u2fs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = u2fs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int u2fs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err = 0;
	struct dentry *lower_dentry, *parent;
	struct inode *inode;
	struct inode *lower_inode;
	struct iattr lower_ia;
	loff_t size;
	inode = dentry->d_inode;

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;


	lower_dentry = u2fs_get_lower_dentry(dentry, 0);

	if (ia->ia_valid & ATTR_SIZE)
		size = ia->ia_size;
	else
		size = i_size_read(inode);

	parent = u2fs_lock_parent(dentry);

	err = copyup_dentry(parent->d_inode,
			dentry,
			dentry->d_name.name,
			dentry->d_name.len,
			NULL, size);

	u2fs_unlock_parent(dentry, parent);
	if (err)
		goto out;

	lower_dentry = u2fs_get_lower_dentry(dentry, 0);

	lower_inode = lower_dentry->d_inode;

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = u2fs_lower_file(ia->ia_file, 0);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use lower_dentry->d_inode, because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = notify_change(lower_dentry, &lower_ia); /* note: lower_ia */
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
out_err:
	return err;
}

const struct inode_operations u2fs_symlink_iops = {
	.readlink	= u2fs_readlink,
	.permission	= u2fs_permission,
	.follow_link	= u2fs_follow_link,
	.setattr	= u2fs_setattr,
	.put_link	= u2fs_put_link,
};

const struct inode_operations u2fs_dir_iops = {
	.create		= u2fs_create,
	.lookup		= u2fs_lookup,
	.link		= u2fs_link,
	.unlink		= u2fs_unlink,
	.symlink	= u2fs_symlink,
	.mkdir		= u2fs_mkdir,
	.rmdir		= u2fs_unlink,
	.mknod		= u2fs_mknod,
	.rename		= u2fs_rename,
	.permission	= u2fs_permission,
	.setattr	= u2fs_setattr,
};

const struct inode_operations u2fs_main_iops = {
	.permission	= u2fs_permission,
	.setattr	= u2fs_setattr,
};
