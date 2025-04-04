// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ufs/namei.c
 *
 * Migration to usage of "page cache" on May 2006 by
 * Evgeniy Dushistov <dushistov@mail.ru> based on ext2 code base.
 *
 * Copyright (C) 1998
 * Daniel Pirkl <daniel.pirkl@email.cz>
 * Charles University, Faculty of Mathematics and Physics
 *
 *  from
 *
 *  linux/fs/ext2/namei.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/time.h>
#include <linux/fs.h>

#include "ufs_fs.h"
#include "ufs.h"
#include "util.h"

static inline int ufs_add_nondir(struct dentry *dentry, struct inode *inode)
{
	int err = ufs_add_link(dentry, inode);
	if (!err) {
		d_instantiate_new(dentry, inode);
		return 0;
	}
	inode_dec_link_count(inode);
	discard_new_inode(inode);
	return err;
}

static struct dentry *ufs_lookup(struct inode * dir, struct dentry *dentry, unsigned int flags)
{
	struct inode * inode = NULL;
	ino_t ino;
	
	if (dentry->d_name.len > UFS_MAXNAMLEN)
		return ERR_PTR(-ENAMETOOLONG);

	ino = ufs_inode_by_name(dir, &dentry->d_name);
	if (ino)
		inode = ufs_iget(dir->i_sb, ino);
	return d_splice_alias(inode, dentry);
}

/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate(). 
 */
static int ufs_create (struct mnt_idmap * idmap,
		struct inode * dir, struct dentry * dentry, umode_t mode,
		bool excl)
{
	struct inode *inode;

	inode = ufs_new_inode(dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &ufs_file_inode_operations;
	inode->i_fop = &ufs_file_operations;
	inode->i_mapping->a_ops = &ufs_aops;
	mark_inode_dirty(inode);
	return ufs_add_nondir(dentry, inode);
}

static int ufs_mknod(struct mnt_idmap *idmap, struct inode *dir,
		     struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct inode *inode;
	int err;

	if (!old_valid_dev(rdev))
		return -EINVAL;

	inode = ufs_new_inode(dir, mode);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		init_special_inode(inode, mode, rdev);
		ufs_set_inode_dev(inode->i_sb, UFS_I(inode), rdev);
		mark_inode_dirty(inode);
		err = ufs_add_nondir(dentry, inode);
	}
	return err;
}

static int ufs_symlink (struct mnt_idmap * idmap, struct inode * dir,
	struct dentry * dentry, const char * symname)
{
	struct super_block * sb = dir->i_sb;
	int err;
	unsigned l = strlen(symname)+1;
	struct inode * inode;

	if (l > sb->s_blocksize)
		return -ENAMETOOLONG;

	inode = ufs_new_inode(dir, S_IFLNK | S_IRWXUGO);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		return err;

	if (l > UFS_SB(sb)->s_uspi->s_maxsymlinklen) {
		/* slow symlink */
		inode->i_op = &page_symlink_inode_operations;
		inode_nohighmem(inode);
		inode->i_mapping->a_ops = &ufs_aops;
		err = page_symlink(inode, symname, l);
		if (err)
			goto out_fail;
	} else {
		/* fast symlink */
		inode->i_op = &simple_symlink_inode_operations;
		inode->i_link = (char *)UFS_I(inode)->i_u1.i_symlink;
		memcpy(inode->i_link, symname, l);
		inode->i_size = l-1;
	}
	mark_inode_dirty(inode);

	return ufs_add_nondir(dentry, inode);

out_fail:
	inode_dec_link_count(inode);
	discard_new_inode(inode);
	return err;
}

static int ufs_link (struct dentry * old_dentry, struct inode * dir,
	struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);
	int error;

	inode_set_ctime_current(inode);
	inode_inc_link_count(inode);
	ihold(inode);

	error = ufs_add_link(dentry, inode);
	if (error) {
		inode_dec_link_count(inode);
		iput(inode);
	} else
		d_instantiate(dentry, inode);
	return error;
}

static struct dentry *ufs_mkdir(struct mnt_idmap * idmap, struct inode * dir,
				struct dentry * dentry, umode_t mode)
{
	struct inode * inode;
	int err;

	inode_inc_link_count(dir);

	inode = ufs_new_inode(dir, S_IFDIR|mode);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_dir;

	inode->i_op = &ufs_dir_inode_operations;
	inode->i_fop = &ufs_dir_operations;
	inode->i_mapping->a_ops = &ufs_aops;

	inode_inc_link_count(inode);

	err = ufs_make_empty(inode, dir);
	if (err)
		goto out_fail;

	err = ufs_add_link(dentry, inode);
	if (err)
		goto out_fail;

	d_instantiate_new(dentry, inode);
	return NULL;

out_fail:
	inode_dec_link_count(inode);
	inode_dec_link_count(inode);
	discard_new_inode(inode);
out_dir:
	inode_dec_link_count(dir);
	return ERR_PTR(err);
}

static int ufs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode * inode = d_inode(dentry);
	struct ufs_dir_entry *de;
	struct folio *folio;
	int err;

	de = ufs_find_entry(dir, &dentry->d_name, &folio);
	if (!de)
		return -ENOENT;

	err = ufs_delete_entry(dir, de, folio);
	if (!err) {
		inode_set_ctime_to_ts(inode, inode_get_ctime(dir));
		inode_dec_link_count(inode);
	}
	folio_release_kmap(folio, de);
	return err;
}

static int ufs_rmdir (struct inode * dir, struct dentry *dentry)
{
	struct inode * inode = d_inode(dentry);
	int err= -ENOTEMPTY;

	if (ufs_empty_dir (inode)) {
		err = ufs_unlink(dir, dentry);
		if (!err) {
			inode->i_size = 0;
			inode_dec_link_count(inode);
			inode_dec_link_count(dir);
		}
	}
	return err;
}

static int ufs_rename(struct mnt_idmap *idmap, struct inode *old_dir,
		      struct dentry *old_dentry, struct inode *new_dir,
		      struct dentry *new_dentry, unsigned int flags)
{
	struct inode *old_inode = d_inode(old_dentry);
	struct inode *new_inode = d_inode(new_dentry);
	struct folio *dir_folio = NULL;
	struct ufs_dir_entry * dir_de = NULL;
	struct folio *old_folio;
	struct ufs_dir_entry *old_de;
	int err;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	old_de = ufs_find_entry(old_dir, &old_dentry->d_name, &old_folio);
	if (!old_de)
		return -ENOENT;

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		dir_de = ufs_dotdot(old_inode, &dir_folio);
		if (!dir_de)
			goto out_old;
	}

	if (new_inode) {
		struct folio *new_folio;
		struct ufs_dir_entry *new_de;

		err = -ENOTEMPTY;
		if (dir_de && !ufs_empty_dir(new_inode))
			goto out_dir;

		err = -ENOENT;
		new_de = ufs_find_entry(new_dir, &new_dentry->d_name, &new_folio);
		if (!new_de)
			goto out_dir;
		err = ufs_set_link(new_dir, new_de, new_folio, old_inode, 1);
		folio_release_kmap(new_folio, new_de);
		if (err)
			goto out_dir;
		inode_set_ctime_current(new_inode);
		if (dir_de)
			drop_nlink(new_inode);
		inode_dec_link_count(new_inode);
	} else {
		err = ufs_add_link(new_dentry, old_inode);
		if (err)
			goto out_dir;
		if (dir_de)
			inode_inc_link_count(new_dir);
	}

	/*
	 * Like most other Unix systems, set the ctime for inodes on a
 	 * rename.
	 */
	inode_set_ctime_current(old_inode);
	mark_inode_dirty(old_inode);

	err = ufs_delete_entry(old_dir, old_de, old_folio);
	if (!err && dir_de) {
		if (old_dir != new_dir)
			err = ufs_set_link(old_inode, dir_de, dir_folio,
					   new_dir, 0);
		inode_dec_link_count(old_dir);
	}
out_dir:
	if (dir_de)
		folio_release_kmap(dir_folio, dir_de);
out_old:
	folio_release_kmap(old_folio, old_de);
	return err;
}

const struct inode_operations ufs_dir_inode_operations = {
	.create		= ufs_create,
	.lookup		= ufs_lookup,
	.link		= ufs_link,
	.unlink		= ufs_unlink,
	.symlink	= ufs_symlink,
	.mkdir		= ufs_mkdir,
	.rmdir		= ufs_rmdir,
	.mknod		= ufs_mknod,
	.rename		= ufs_rename,
};
