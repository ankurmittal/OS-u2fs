/*
 * Copyright (c) 2003-2014 Erez Zadok
 * Copyright (c) 2003-2006 Charles P. Wright
 * Copyright (c) 2005-2007 Josef 'Jeff' Sipek
 * Copyright (c) 2005-2006 Junjiro Okajima
 * Copyright (c) 2005      Arun M. Krishnakumar
 * Copyright (c) 2004-2006 David P. Quigley
 * Copyright (c) 2003-2004 Mohammad Nayyer Zubair
 * Copyright (c) 2003      Puja Gupta
 * Copyright (c) 2003      Harikesavan Krishnan
 * Copyright (c) 2003-2014 Stony Brook University
 * Copyright (c) 2003-2014 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "u2fs.h"

/*
 * Determine the mode based on the copyup flags, and the existing dentry.
 *
 * Handle file systems which may not support certain options.  For example
 * jffs2 doesn't allow one to chmod a symlink.  So we ignore such harmless
 * errors, rather than propagating them up, which results in copyup errors
 * and errors returned back to users.
 */
static int copyup_permissions(struct super_block *sb,
			      struct dentry *old_lower_dentry,
			      struct dentry *new_lower_dentry)
{
	struct inode *i = old_lower_dentry->d_inode;
	struct iattr newattrs;
	int err;

	newattrs.ia_atime = i->i_atime;
	newattrs.ia_mtime = i->i_mtime;
	newattrs.ia_ctime = i->i_ctime;
	newattrs.ia_gid = i->i_gid;
	newattrs.ia_uid = i->i_uid;
	newattrs.ia_valid = ATTR_CTIME | ATTR_ATIME | ATTR_MTIME |
		ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_FORCE |
		ATTR_GID | ATTR_UID;
	mutex_lock(&new_lower_dentry->d_inode->i_mutex);
	err = notify_change(new_lower_dentry, &newattrs);
	if (err)
		goto out;

	/* now try to change the mode and ignore EOPNOTSUPP on symlinks */
	newattrs.ia_mode = i->i_mode;
	newattrs.ia_valid = ATTR_MODE | ATTR_FORCE;
	err = notify_change(new_lower_dentry, &newattrs);
	if (err == -EOPNOTSUPP &&
	    S_ISLNK(new_lower_dentry->d_inode->i_mode)) {
		printk(KERN_WARNING
		       "u2fs: changing \"%s\" symlink mode unsupported\n",
		       new_lower_dentry->d_name.name);
		err = 0;
	}

out:
	mutex_unlock(&new_lower_dentry->d_inode->i_mutex);
	return err;
}

/*
 * create the new device/file/directory - use copyup_permission to copyup
 * times, and mode
 *
 * if the object being copied up is a regular file, the file is only created,
 * the contents have to be copied up separately
 */
static int __copyup_ndentry(struct dentry *old_lower_dentry,
			    struct dentry *new_lower_dentry,
			    struct dentry *new_lower_parent_dentry,
			    char *symbuf)
{
	int err = 0;
	umode_t old_mode = old_lower_dentry->d_inode->i_mode;

	if (S_ISDIR(old_mode))
		err = vfs_mkdir(new_lower_parent_dentry->d_inode,
			new_lower_dentry, old_mode);
	else if (S_ISLNK(old_mode))
		err = vfs_symlink(new_lower_parent_dentry->d_inode,
				new_lower_dentry, symbuf);
	else if (S_ISBLK(old_mode) || S_ISCHR(old_mode) ||
			S_ISFIFO(old_mode) || S_ISSOCK(old_mode))
		err = vfs_mknod(new_lower_parent_dentry->d_inode,
				new_lower_dentry, old_mode,
				old_lower_dentry->d_inode->i_rdev);

	else if (S_ISREG(old_mode))
		err = vfs_create(new_lower_parent_dentry->d_inode,
				new_lower_dentry, old_mode, NULL);
	else {
		printk(KERN_CRIT "u2fs: unknown inode type %d\n",
				old_mode);
		BUG();
	}

	return err;
}

static int __copyup_reg_data(struct dentry *dentry,
		struct dentry *new_lower_dentry,
		struct dentry *old_lower_dentry,
		struct file **copyup_file, loff_t len)
{
	struct super_block *sb = dentry->d_sb;
	struct file *input_file;
	struct file *output_file;
	struct vfsmount *output_mnt;
	mm_segment_t old_fs;
	char *buf = NULL;
	ssize_t read_bytes, write_bytes;
	loff_t size;
	int err = 0;

	/* open old file */
	u2fs_mntget(dentry, 1);
	/* dentry_open calls dput and mntput if it returns an error */
	input_file = dentry_open(old_lower_dentry,
			u2fs_get_lower_mnt(dentry, 1),
			O_RDONLY | O_LARGEFILE, current_cred());
	if (IS_ERR(input_file)) {
		dput(old_lower_dentry);
		err = PTR_ERR(input_file);
		goto out;
	}
	if (unlikely(!input_file->f_op || !input_file->f_op->read)) {
		err = -EINVAL;
		goto out_close_in;
	}

	/* open new file */
	dget(new_lower_dentry);
	output_mnt = u2fs_mntget(sb->s_root, 0);

	output_file = dentry_open(new_lower_dentry, output_mnt,
			O_RDWR | O_LARGEFILE, current_cred());
	if (IS_ERR(output_file)) {
		err = PTR_ERR(output_file);
		goto out_close_in;
	}
	if (unlikely(!output_file->f_op || !output_file->f_op->write)) {
		err = -EINVAL;
		goto out_close_out;
	}

	/* allocating a buffer */
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (unlikely(!buf)) {
		err = -ENOMEM;
		goto out_close_out;
	}

	input_file->f_pos = 0;
	output_file->f_pos = 0;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	size = len;
	err = 0;
	do {
		if (len >= PAGE_SIZE)
			size = PAGE_SIZE;
		else if ((len < PAGE_SIZE) && (len > 0))
			size = len;

		len -= PAGE_SIZE;

		read_bytes =
			input_file->f_op->read(input_file,
					(char __user *)buf, size,
					&input_file->f_pos);
		if (read_bytes <= 0) {
			err = read_bytes;
			break;
		}

		lockdep_off();
		write_bytes =
			output_file->f_op->write(output_file,
					(char __user *)buf,
					read_bytes,
					&output_file->f_pos);
		lockdep_on();
		if ((write_bytes < 0) || (write_bytes < read_bytes)) {
			err = write_bytes;
			break;
		}
	} while ((read_bytes > 0) && (len > 0));

	set_fs(old_fs);

	kfree(buf);

	if (err)
		goto out_close_out;

	if (copyup_file) {
		*copyup_file = output_file;
		goto out_close_in;
	}

out_close_out:
	fput(output_file);

out_close_in:
	fput(input_file);

out:
	return err;
}

/*
 * dput the lower references for old and new dentry & clear a lower dentry
 * pointer
 */
static void __clear(struct dentry *dentry, struct dentry *old_lower_dentry,
		struct dentry *new_lower_dentry)
{
	/* get rid of the lower dentry and all its traces */
	UDBG;
	u2fs_set_lower_dentry(dentry, 0, NULL);
	dput(new_lower_dentry);
	dput(old_lower_dentry);
}

/*
 * Copy up a dentry to a file of specified name.
 *
 * @dir: used to pull the ->i_sb to access other branches
 * @dentry: the non-negative dentry whose lower_inode we should copy
 * @name: the name of the file to create
 * @namelen: length of @name
 * @copyup_file: the "struct file" to return (optional)
 * @len: how many bytes to copy-up?
 */
int copyup_dentry(struct inode *dir, struct dentry *dentry,
		const char *name, int namelen,
		struct file **copyup_file, loff_t len)
{
	struct dentry *new_lower_dentry;
	struct dentry *old_lower_dentry = NULL;
	struct super_block *sb;
	int err = 0;
	struct dentry *new_lower_parent_dentry = NULL;
	mm_segment_t oldfs;
	char *symbuf = NULL;


	sb = dir->i_sb;

	/* Create the directory structure above this dentry. */
	new_lower_dentry = create_parents(dir, dentry, name);
	if (IS_ERR(new_lower_dentry)) {
		err = PTR_ERR(new_lower_dentry);
		goto out;
	}

	old_lower_dentry = u2fs_get_lower_dentry(dentry, 1);
	/* we conditionally dput this old_lower_dentry at end of function */
	dget(old_lower_dentry);

	/* For symlinks, we must read the link before we lock the directory. */
	if (S_ISLNK(old_lower_dentry->d_inode->i_mode)) {

		symbuf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (unlikely(!symbuf)) {
			__clear(dentry, old_lower_dentry,
					new_lower_dentry);
			err = -ENOMEM;
			goto out_free;
		}

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		err = old_lower_dentry->d_inode->i_op->readlink(
				old_lower_dentry,
				(char __user *)symbuf,
				PATH_MAX);
		set_fs(oldfs);
		if (err < 0) {
			__clear(dentry, old_lower_dentry,
					new_lower_dentry);
			goto out_free;
		}
		symbuf[err] = '\0';
	}

	/* Now we lock the parent, and create the object in the new branch. */
	new_lower_parent_dentry = lock_parent(new_lower_dentry);

	/* create the new inode */
	err = __copyup_ndentry(old_lower_dentry, new_lower_dentry,
			new_lower_parent_dentry, symbuf);

	if (err) {
		__clear(dentry, old_lower_dentry,
				new_lower_dentry);
		goto out_unlock;
	}

	/* We actually copyup the file here. */
	if (S_ISREG(old_lower_dentry->d_inode->i_mode))
		err = __copyup_reg_data(dentry, new_lower_dentry,
				old_lower_dentry,
				copyup_file, len);
	if (err)
		goto out_unlink;

	/* Set permissions. */
	err = copyup_permissions(sb, old_lower_dentry, new_lower_dentry);
	if (err)
		goto out_unlink;

	/* do not allow files getting deleted to be re-interposed */
	/* Req?? if (!d_deleted(dentry))
	   u2fs_reinterpose(dentry);*/

	goto out_unlock;

out_unlink:
	/*
	 * copyup failed, because we possibly ran out of space or
	 * quota, or something else happened so let's unlink; we don't
	 * really care about the return value of vfs_unlink
	 */
	vfs_unlink(new_lower_parent_dentry->d_inode, new_lower_dentry);

	if (copyup_file)
		/* need to close the file */
		fput(*copyup_file);

	/*
	 * TODO: should we reset the error to something like -EIO?
	 *
	 * If we don't reset, the user may get some nonsensical errors, but
	 * on the other hand, if we reset to EIO, we guarantee that the user
	 * will get a "confusing" error message.
	 */

out_unlock:
	unlock_dir(new_lower_parent_dentry);

out_free:
	/*
	 * If old_lower_dentry was not a file, then we need to dput it.  If
	 * it was a file, then it was already dput indirectly by other
	 * functions we call above which operate on regular files.
	 */
	if (old_lower_dentry && old_lower_dentry->d_inode &&
			!S_ISREG(old_lower_dentry->d_inode->i_mode))
		dput(old_lower_dentry);
	kfree(symbuf);

	if (err) {
		UDBG;
		/*
		 * if directory creation succeeded, but inode copyup failed,
		 * then purge new dentries.
		 */
		__clear(dentry, NULL,
				new_lower_dentry);
		goto out;
	}
	if (!S_ISDIR(dentry->d_inode->i_mode)) {
		u2fs_postcopyup_release(dentry);
		if (!u2fs_lower_inode(dentry->d_inode)) {
			/*
			 * If we got here, then we copied up to an
			 * unlinked-open file, whose name is .u2fsXXXXX.
			 */
			struct inode *inode = new_lower_dentry->d_inode;
			atomic_inc(&inode->i_count);
			u2fs_set_lower_inode(dentry->d_inode, inode);
		}
	}
	u2fs_postcopyup_setmnt(dentry);
	/* sync inode times from copied-up inode to our inode */
	u2fs_copy_attr_times(dentry->d_inode);
out:
	return err;
}

/*
 * This function creates a copy of a file represented by 'file'
 * The copy will be named "name".
 */
int copyup_named_file(struct inode *dir, struct file *file, char *name,
		int bstart, int new_bindex, loff_t len)
{
	int err = 0;
	struct file *output_file = NULL;

	err = copyup_dentry(dir, file->f_path.dentry,
			name, strlen(name), &output_file, len);
	if (!err)
		u2fs_set_lower_file(file, 0, output_file);

	return err;
}

/*
 * This function creates a copy of a file represented by 'file'
 */
int copyup_file(struct inode *dir, struct file *file, loff_t len)
{
	int err = 0;
	struct file *output_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	err = copyup_dentry(dir, dentry, dentry->d_name.name,
			dentry->d_name.len, &output_file, len);
	if (!err)
		u2fs_set_lower_file(file, 0, output_file);

	return err;
}

/*
 * This function replicates the directory structure up-to given dentry
 */
struct dentry *create_parents(struct inode *dir, struct dentry *dentry,
		const char *name)
{
	int err;
	struct dentry *child_dentry;
	struct dentry *parent_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct dentry *lower_dentry = NULL;
	const char *childname;
	unsigned int childnamelen;
	int nr_dentry;
	int count = 0;
	struct dentry **path = NULL;
	struct super_block *sb;
	int bindex = 0;

	UDBG;



	lower_dentry = ERR_PTR(-ENOMEM);

	/* There is no sense allocating any less than the minimum. */
	nr_dentry = 1;
	path = kmalloc(nr_dentry * sizeof(struct dentry *), GFP_KERNEL);
	if (unlikely(!path))
		goto out;

	/* assume the negative dentry of u2fs as the parent dentry */
	parent_dentry = dentry;

	/*
	 * This loop finds the first parent that exists in the given branch.
	 * We start building the directory structure from there.  At the end
	 * of the loop, the following should hold:
	 *  - child_dentry is the first nonexistent child
	 *  - parent_dentry is the first existent parent
	 *  - path[0] is the = deepest child
	 *  - path[count] is the first child to create
	 */
	do {
		child_dentry = parent_dentry;

		/* find the parent directory dentry in u2fs */
		parent_dentry = dget_parent(child_dentry);

		/* find out the lower_parent_dentry in the given branch */
		lower_parent_dentry =
			u2fs_get_lower_dentry(parent_dentry, bindex);

		/* grow path table */
		if (count == nr_dentry) {
			void *p;

			nr_dentry *= 2;
			p = krealloc(path, nr_dentry * sizeof(struct dentry *),
					GFP_KERNEL);
			if (unlikely(!p)) {
				lower_dentry = ERR_PTR(-ENOMEM);
				goto out;
			}
			path = p;
		}

		/* store the child dentry */
		path[count++] = child_dentry;
	} while (!lower_parent_dentry || !lower_parent_dentry->d_inode);
	count--;

	sb = dentry->d_sb;

	/*
	 * This code goes between the begin/end labels and basically
	 * emulates a while(child_dentry != dentry), only cleaner and
	 * shorter than what would be a much longer while loop.
	 */
begin:
	/* get lower parent dir in the current branch */
	lower_parent_dentry = u2fs_get_lower_dentry(parent_dentry, bindex);
	dput(parent_dentry);

	/* init the values to lookup */
	childname = child_dentry->d_name.name;
	childnamelen = child_dentry->d_name.len;

	if (child_dentry != dentry) {
		/* lookup child in the underlying file system */
		lower_dentry = lookup_lck_len(childname, lower_parent_dentry,
				childnamelen);
		if (IS_ERR(lower_dentry))
			goto out;
	} else {
		/*
		 * Is the name a whiteout of the child name ?  lookup the
		 * whiteout child in the underlying file system
		 */
		lower_dentry = lookup_lck_len(name, lower_parent_dentry,
				strlen(name));
		if (IS_ERR(lower_dentry))
			goto out;

		/* Replace the current dentry (if any) with the new one */
		dput(u2fs_get_lower_dentry(dentry, bindex));
		u2fs_set_lower_dentry(dentry, bindex,
				lower_dentry);

		goto out;
	}

	if (lower_dentry->d_inode) {
		/*
		 * since this already exists we dput to avoid
		 * multiple references on the same dentry
		 */
		dput(lower_dentry);
	} else {

		/* it's a negative dentry, create a new dir */
		lower_parent_dentry = lock_parent(lower_dentry);

		err = vfs_mkdir(lower_parent_dentry->d_inode,
				lower_dentry, child_dentry->d_inode->i_mode);

		if (!err)
			err = copyup_permissions(dir->i_sb, child_dentry,
					lower_dentry);
		unlock_dir(lower_parent_dentry);
		if (err) {
			dput(lower_dentry);
			lower_dentry = ERR_PTR(err);
			goto out;
		}

	}

	u2fs_set_lower_dentry(child_dentry, bindex, lower_dentry);
	/*
	 * update times of this dentry, but also the parent, because if
	 * we changed, the parent may have changed too.
	 */
	fsstack_copy_attr_times(parent_dentry->d_inode,
			lower_parent_dentry->d_inode);
	u2fs_copy_attr_times(child_dentry->d_inode);

	parent_dentry = child_dentry;
	child_dentry = path[--count];
	goto begin;
out:
	/* cleanup any leftover locks from the do/while loop above */
	if (IS_ERR(lower_dentry))
		while (count)
			dput(path[count--]);
	kfree(path);
	return lower_dentry;
}

/*
 * Post-copyup helper to ensure we have valid mnts: set lower mnt of
 * dentry+parents to the first parent node that has an mnt.
 */
void u2fs_postcopyup_setmnt(struct dentry *dentry)
{
	struct dentry *parent, *hasone;

	if (u2fs_get_lower_mnt(dentry, 0))
		return;
	hasone = dentry->d_parent;
	/* this loop should stop at root dentry */
	while (!u2fs_get_lower_mnt(hasone, 0))
		hasone = hasone->d_parent;
	parent = dentry;
	while (!u2fs_get_lower_mnt(parent, 0)) {
		u2fs_set_lower_mnt(parent, 0,
				u2fs_mntget(hasone, 0));
		parent = parent->d_parent;
	}
}

/*
 * Post-copyup helper to release all non-directory source objects of a
 * copied-up file.  Regular files should have only one lower object.
 */
void u2fs_postcopyup_release(struct dentry *dentry)
{
	BUG_ON(S_ISDIR(dentry->d_inode->i_mode));

	iput(u2fs_lower_inode(dentry->d_inode));
	u2fs_set_lower_inode(dentry->d_inode, NULL);

}
