/*
 * Code Copied from u2fs.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "u2fs.h"

/* This file contains the routines for maintaining readdir state. */


/*
 * This is a struct kmem_cache for filldir nodes, because we allocate a lot
 * of them and they shouldn't waste memory.  If the node has a small name
 * (as defined by the dentry structure), then we use an inline name to
 * preserve kmalloc space.
 */
static struct kmem_cache *u2fs_filldir_cachep;

int u2fs_init_filldir_cache(void)
{
	u2fs_filldir_cachep =
		kmem_cache_create("u2fs_filldir",
				sizeof(struct filldir_node), 0,
				SLAB_RECLAIM_ACCOUNT, NULL);

	return u2fs_filldir_cachep ? 0 : -ENOMEM;
}

void u2fs_destroy_filldir_cache(void)
{
	if (u2fs_filldir_cachep)
		kmem_cache_destroy(u2fs_filldir_cachep);
}

static void free_filldir_node(struct filldir_node *node)
{
	if (node->namelen >= DNAME_INLINE_LEN)
		kfree(node->name);
	kmem_cache_free(u2fs_filldir_cachep, node);
}

void free_filldir_heads(struct list_head *heads, int head_list_size)
{
	struct filldir_node *tmp;
	int i;

	for (i = 0; i < head_list_size; i++) {
		struct list_head *head = &(heads[i]);
		struct list_head *pos, *n;

		/* traverse the list and deallocate space */
		list_for_each_safe(pos, n, head) {
			tmp = list_entry(pos, struct filldir_node, file_list);
			list_del(&tmp->file_list);
			free_filldir_node(tmp);
		}
	}

}


struct filldir_node *find_filldir_node(const char *name, int namelen,
		struct list_head *heads, int head_list_size)
{
	int index;
	unsigned int hash;
	struct list_head *head;
	struct list_head *pos;
	struct filldir_node *cursor = NULL;
	int found = 0;

	BUG_ON(namelen <= 0);

	hash = full_name_hash(name, namelen);
	index = hash % head_list_size;

	head = &(heads[index]);
	list_for_each(pos, head) {
		cursor = list_entry(pos, struct filldir_node, file_list);

		if (cursor->namelen == namelen && cursor->hash == hash &&
				!strncmp(cursor->name, name, namelen)) {
			/*
			 * a duplicate exists, and hence no need to create
			 * entry to the list
			 */
			found = 1;
			break;
		}
	}

	if (!found)
		cursor = NULL;

	return cursor;
}

int add_filldir_node(const char *name, int namelen, int whiteout,
			struct list_head *heads, int head_list_size)
{
	struct filldir_node *new;
	unsigned int hash;
	int index;
	int err = 0;
	struct list_head *head;

	BUG_ON(namelen <= 0);

	hash = full_name_hash(name, namelen);
	index = hash % head_list_size;
	head = &(heads[index]);

	new = kmem_cache_alloc(u2fs_filldir_cachep, GFP_KERNEL);
	if (unlikely(!new)) {
		err = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&new->file_list);
	new->namelen = namelen;
	new->hash = hash;
	new->whiteout = whiteout;

	if (namelen < DNAME_INLINE_LEN) {
		new->name = new->iname;
	} else {
		new->name = kmalloc(namelen + 1, GFP_KERNEL);
		if (unlikely(!new->name)) {
			kmem_cache_free(u2fs_filldir_cachep, new);
			new = NULL;
			goto out;
		}
	}

	memcpy(new->name, name, namelen);
	new->name[namelen] = '\0';


	list_add(&(new->file_list), head);
out:
	return err;
}
