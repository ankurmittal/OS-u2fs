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

#ifndef _U2FS_H_
#define _U2FS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>

/* the file system name */
#define U2FS_NAME "u2fs"

/* u2fs root inode number */
#define U2FS_ROOT_INO     1

#define IS_COPYUP_ERR(err) ((err) == -EROFS)

#define DIREOF (0xfffff)

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)
/* u2fs_open, check if we need to copyup the file */
#define OPEN_WRITE_FLAGS (O_WRONLY | O_RDWR | O_APPEND)
#define IS_WRITE_FLAG(flag) ((flag) & OPEN_WRITE_FLAGS)

/* operations vectors defined in specific files */
extern const struct file_operations u2fs_main_fops;
extern const struct file_operations u2fs_dir_fops;
extern const struct inode_operations u2fs_main_iops;
extern const struct inode_operations u2fs_dir_iops;
extern const struct inode_operations u2fs_symlink_iops;
extern const struct super_operations u2fs_sops;
extern const struct dentry_operations u2fs_dops;
extern const struct address_space_operations u2fs_aops, u2fs_dummy_aops;
extern const struct vm_operations_struct u2fs_vm_ops;
extern struct dentry *lookup_whiteout(const char *name,
		struct dentry *lower_parent);
extern int u2fs_init_inode_cache(void);
extern void u2fs_destroy_inode_cache(void);
extern int u2fs_init_dentry_cache(void);
extern void u2fs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *u2fs_lookup(struct inode *dir, struct dentry *dentry,
		struct nameidata *nd);
extern struct inode *u2fs_iget(struct super_block *sb,
		struct inode *lower_inode);
extern int u2fs_interpose(struct dentry *dentry, struct super_block *sb);
extern int create_whiteout(struct dentry *dentry);
extern bool is_whiteout_name(char **namep, int *namelenp);

extern int u2fs_init_filldir_cache(void);
extern void u2fs_destroy_filldir_cache(void);

extern struct filldir_node *find_filldir_node(const char *name, int namelen,
		struct list_head *heads, int head_list_size);
extern int add_filldir_node(const char *name, int namelen, int whiteout,
		struct list_head *heads, int head_list_size);
extern void free_filldir_heads(struct list_head *heads, int head_list_size);
extern struct dentry *create_parents(struct inode *dir, struct dentry *dentry,
		const char *name);
extern void u2fs_copy_attr_times(struct inode *upper);
extern void u2fs_postcopyup_setmnt(struct dentry *dentry);
extern void u2fs_postcopyup_release(struct dentry *dentry);
extern int copyup_file(struct inode *dir, struct file *file, loff_t len);
extern int check_unlink_whiteout(struct dentry *dentry,
		struct dentry *lower_dentry);
extern void u2fs_set_max_namelen(long *namelen);
extern int copyup_dentry(struct inode *dir, struct dentry *dentry,
		const char *name, int namelen,
		struct file **copyup_file, loff_t len);

/* file private data */
struct u2fs_file_info {
	struct file *right_file;
	struct file *left_file;
	const struct vm_operations_struct *lower_vm_ops;
	bool wrote_to_file;
};

/* u2fs inode data in memory */
struct u2fs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
};

/* u2fs dentry data in memory */
struct u2fs_dentry_info {
	spinlock_t lock;	/* protects left_path */
	struct path left_path;
	struct path right_path;
};

/* u2fs super-block data in memory */
struct u2fs_sb_info {
	char *dev_name;
	struct super_block *left_sb;
	struct super_block *right_sb;
};

struct u2fs_getdents_buf {
	void *dirent;
	filldir_t filldir;
	bool is_right;
	struct list_head *heads;
	int heads_size;

};

/*
 * structure for making the linked list of entries by readdir on left branch
 * to compare with entries on right branch
 */
struct filldir_node {
	struct list_head file_list;     /* list for directory entries */
	char *name;             /* name entry */
	int hash;               /* name hash */
	int namelen;            /* name len since name is not 0 terminated */

	/*
	 * we can check for duplicate whiteouts and files in the same branch
	 * in order to return -EIO.
	 */

	/* is this a whiteout entry? */
	int whiteout;

	/* Inline name, so we don't need to separately kmalloc small ones */
	char iname[DNAME_INLINE_LEN];
};

static inline void init_filldir_heads(struct list_head *heads,
int head_list_size)
{
	int i;
	for (i = 0; i < head_list_size; i++)
		INIT_LIST_HEAD(&heads[i]);
}

static inline bool has_valid_parent(struct dentry *dentry)
{
	if (!dentry || !dentry->d_parent || !dentry->d_parent->d_inode)
		return false;
	return true;
}
/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * u2fs_inode_info structure, U2FS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct u2fs_inode_info *U2FS_I(const struct inode *inode)
{
	return container_of(inode, struct u2fs_inode_info, vfs_inode);
}

/* dentry to private data */
#define U2FS_D(dent) ((struct u2fs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define U2FS_SB(super) ((struct u2fs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define U2FS_F(file) ((struct u2fs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *u2fs_lower_file(struct file *f, int is_right)
{
	if (is_right)
		return U2FS_F(f)->right_file;
	else
		return U2FS_F(f)->left_file;

}
static inline void u2fs_set_lower_file(struct file *f,
		int is_right, struct file *val)
{
	if (is_right)
		U2FS_F(f)->right_file = val;
	else
		U2FS_F(f)->left_file = val;

}

static inline void u2fs_put_all_lower_files(struct file *f)
{
	if (U2FS_F(f)->right_file) {
		fput(U2FS_F(f)->right_file);
		U2FS_F(f)->right_file = NULL;
	}

	if (U2FS_F(f)->left_file) {
		fput(U2FS_F(f)->left_file);
		U2FS_F(f)->left_file = NULL;
	}


}

/* inode to lower inode. */
static inline struct inode *u2fs_lower_inode(const struct inode *i)
{
	return U2FS_I(i)->lower_inode;
}

static inline void u2fs_set_lower_inode(struct inode *i, struct inode *val)
{
	U2FS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *u2fs_lower_super(
		const struct super_block *sb)
{
	return U2FS_SB(sb)->left_sb;
}

static inline void u2fs_set_right_super(struct super_block *sb,
		struct super_block *val)
{
	U2FS_SB(sb)->right_sb = val;
}

static inline void u2fs_set_left_super(struct super_block *sb,
		struct super_block *val)
{
	U2FS_SB(sb)->left_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline struct path *u2fs_get_path(const struct dentry *dent,
		int is_right)
{
	if (is_right)
		return &U2FS_D(dent)->right_path;
	else
		return  &U2FS_D(dent)->left_path;
}




static inline void u2fs_put_path(const struct dentry *denti, struct path *path)
{
	path_put(path);
	return;
}

static inline void u2fs_put_all_paths(const struct dentry *dent)
{
	path_put(&U2FS_D(dent)->right_path);
	path_put(&U2FS_D(dent)->left_path);
	return;
}


static inline void u2fs_set_right_path(const struct dentry *dent,
		struct path *right_path)
{
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&U2FS_D(dent)->right_path, right_path);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}

static inline struct dentry *u2fs_get_lower_dentry(struct dentry *dent,
		int is_right)
{
	if (is_right)
		return U2FS_D(dent)->right_path.dentry;
	else
		return U2FS_D(dent)->left_path.dentry;
}

static inline void u2fs_set_lower_dentry(struct dentry *dent, int is_right,
		struct dentry *val)
{
	if (is_right)
		U2FS_D(dent)->right_path.dentry = val;
	else
		U2FS_D(dent)->left_path.dentry = val;
}

static inline struct vfsmount *u2fs_get_lower_mnt(struct dentry *dent,
		int is_right)
{
	if (is_right)
		return U2FS_D(dent)->right_path.mnt;
	else
		return U2FS_D(dent)->left_path.mnt;
}

static inline void u2fs_set_lower_mnt(struct dentry *dent,
		int is_right, struct vfsmount *val)
{
	if (is_right)
		U2FS_D(dent)->right_path.mnt = val;
	else
		U2FS_D(dent)->left_path.mnt = val;
}

static inline struct vfsmount *u2fs_mntget(struct dentry *dentry,
		int is_right)
{
	struct vfsmount *mnt;

	mnt = mntget(u2fs_get_lower_mnt(dentry, is_right));

	return mnt;
}


static inline void u2fs_set_path(const struct dentry *dent,
		struct path *path, int is_right)
{
	spin_lock(&U2FS_D(dent)->lock);
	if (!is_right)
		pathcpy(&U2FS_D(dent)->left_path, path);
	else
		pathcpy(&U2FS_D(dent)->right_path, path);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}
static inline void u2fs_reset_all_path(const struct dentry *dent)
{
	spin_lock(&U2FS_D(dent)->lock);
	U2FS_D(dent)->left_path.dentry = NULL;
	U2FS_D(dent)->right_path.dentry = NULL;
	U2FS_D(dent)->left_path.mnt = NULL;
	U2FS_D(dent)->right_path.mnt = NULL;
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}
static inline void u2fs_put_reset_all_path(const struct dentry *dent)
{
	struct path path;
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&path, &U2FS_D(dent)->right_path);
	U2FS_D(dent)->right_path.dentry = NULL;
	U2FS_D(dent)->right_path.mnt = NULL;
	path_put(&path);
	pathcpy(&path, &U2FS_D(dent)->left_path);
	U2FS_D(dent)->left_path.dentry = NULL;
	U2FS_D(dent)->left_path.mnt = NULL;
	path_put(&path);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}

/* lock base inode mutex before calling lookup_one_len */
static inline struct dentry *lookup_lck_len(const char *name,
		struct dentry *base, int len)
{
	struct dentry *d;
	mutex_lock(&base->d_inode->i_mutex);
	d = lookup_one_len(name, base, len);
	mutex_unlock(&base->d_inode->i_mutex);
	return d;
}


static inline struct dentry *u2fs_lock_parent(struct dentry *d)
{
	struct dentry *p;

	BUG_ON(!d);
	p = dget_parent(d);
	if (p != d)
		mutex_lock_nested(&p->d_inode->i_mutex, I_MUTEX_PARENT);
	return p;
}
/* The root directory is unhashed, but isn't deleted. */
static inline int d_deleted(struct dentry *d)
{
	return d_unhashed(d) && (d != d->d_sb->s_root);
}


static inline void u2fs_unlock_parent(struct dentry *d, struct dentry *p)
{
	BUG_ON(!d);
	BUG_ON(!p);
	if (p != d)
		mutex_unlock(&p->d_inode->i_mutex);
	dput(p);
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}

#endif	/* not _U2FS_H_ */
