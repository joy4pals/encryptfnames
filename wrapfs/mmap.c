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
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/writeback.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#include "wrapfs.h"

#ifdef WRAPFS_CRYPTO
static const char *default_algo = "ctr(aes)";
/*
 This function is used to encrypt or decrypt a page.
 src_page	: the given page with data
 dst_page	: the final page which is to be filled in
 key		: the encryption key
 key_len	: the length of the encryption key
 encrypt	: This is a flag whch determines whether the src_page needs
 to be encrypted or deprypted.
 1: encrypt
 0: decrypt

 returns 0 on success and appropriate negative error or failure
 */
int
decrypt_encrypt_page(struct page *src_page,
					 struct page *dst_page,
					 char *key,
					 int key_len,
					 int encrypt){
	int ret = 0;
	struct scatterlist src_sg, dst_sg;
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	sg_init_table(&src_sg, 1);
	sg_init_table(&dst_sg, 1);

	sg_set_page(&src_sg, src_page, PAGE_SIZE, 0);
	sg_set_page(&dst_sg, dst_page, PAGE_SIZE, 0);

	tfm = crypto_alloc_blkcipher(default_algo, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		printk(KERN_ERR "failed to load transform for %s: %ld\n",
			   default_algo,
		       PTR_ERR(tfm));
		ret = IS_ERR(tfm);
		goto out;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	ret = crypto_blkcipher_setkey(tfm, key, key_len);
	if (ret) {
		printk(KERN_ERR "setkey() failed flags=%x\n",
			   crypto_blkcipher_get_flags(tfm));
		goto out;
	}
	if (encrypt)
		ret = crypto_blkcipher_encrypt(
					&desc, &dst_sg, &src_sg, PAGE_SIZE);
	else
		ret = crypto_blkcipher_decrypt(
					&desc, &dst_sg, &src_sg, PAGE_SIZE);
	if (ret)
		printk(KERN_INFO "Some error occured while encrypting.\n");

out:
	crypto_free_blkcipher(tfm);
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(ret);
#endif
	return ret;
}
#endif
/**This function is taken from ecryptfs with necessary changes
 * wrapfs_read_lower
 * @data: The read data is stored here by this function
 * @offset: Byte offset in the lower file from which to read the data
 * @size: Number of bytes to read from @offset of the lower file and
 *        store into @data
 * @wrapfs_inode: The wrapfs inode
 *
 * Read @size bytes of data at byte offset @offset from the lower
 * inode into memory location @data.
 *
 * Returns bytes read on success; 0 on EOF; less than zero on error
 */
int wrapfs_read_lower(char *data, loff_t offset, size_t size,
				struct inode *wrapfs_inode, struct file *file)
{
	struct file *lower_file;
	mm_segment_t fs_save;
	ssize_t rc;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	lower_file = wrapfs_lower_file(file);
	if (!lower_file)
		return -EIO;
	if (!(lower_file->f_mode & FMODE_READ))
		lower_file->f_mode = lower_file->f_mode | FMODE_READ;
	fs_save = get_fs();
	set_fs(get_ds());
	rc = vfs_read(lower_file, data, size, &offset);
	set_fs(fs_save);
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(rc);
#endif
	return rc;
}

/**This function is taken from ecryptfs with necessary changes
 * wrapfs_read_lower_page_segment
 * @page_for_lower: The page into which data for wrapfs will be
 *                     written
 * @offset_in_page: Offset in @page_for_lower from which to start
 *                  writing
 * @size: The number of bytes to write into @page_for_lower
 * @wrapfs_inode: The wrapfs inode
 * @file	: This file pointer corresponding to the page
 * Determines the byte offset in the file for the given page and
 * offset within the page, maps the page, and makes the call to read
 * the contents of @page_for_lower from the lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
int wrapfs_read_lower_page_segment(struct page *page_for_lower,
						 pgoff_t page_index,
						 size_t offset_in_page,
						 size_t size,
						 struct inode *wrapfs_inode,
						 struct file *file)
{
	char *virt;
	loff_t offset;
	int rc = 0;
	struct page *dst_page = NULL;

	offset = ((((loff_t)page_index) << PAGE_CACHE_SHIFT) + offset_in_page);
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
#ifdef WRAPFS_CRYPTO
	if (strlen(WRAPFS_SB(page_for_lower->mapping->host->i_sb)->key) != 0) {
		dst_page = alloc_page(GFP_USER);
		if (!dst_page) {
			rc = -ENOMEM;
			printk(KERN_ERR "Error allocating memory for "
				   "page\n");
			goto out;
		}
		virt = kmap(dst_page);
		rc = wrapfs_read_lower(virt, offset, size, wrapfs_inode, file);
		rc = decrypt_encrypt_page(dst_page, page_for_lower,
			WRAPFS_SB(page_for_lower->mapping->host->i_sb)->key,
		sizeof(WRAPFS_SB(page_for_lower->mapping->host->i_sb)->key)-1,
			0);
	} else {
		printk(KERN_ERR "key Not Set\n");
		rc = -EPERM;
		goto out;
#endif
		virt = kmap(page_for_lower);
		rc = wrapfs_read_lower(virt, offset, size, wrapfs_inode, file);
#ifdef WRAPFS_CRYPTO
	}
#endif
	if (rc > 0)
		rc = 0;

	if (dst_page) {
		kunmap(dst_page);
		__free_page(dst_page);
	} else {
		kunmap(page_for_lower);
	}

	flush_dcache_page(page_for_lower);
#ifdef WRAPFS_CRYPTO
out:
#endif
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(rc);
#endif
	return rc;
}
/**This function is taken from ecryptfs with necessary changes
 * wrapfs_write_lower
 * @wrapfs_inode: The wrapfs inode
 * @data: Data to write
 * @offset: Byte offset in the lower file to which to write the data
 * @size: Number of bytes from @data to write at @offset in the lower
 *        file
 * @file: The corresponding file pointer
 * Write data to the lower file.
 *
 * Returns bytes written on success; less than zero on error
 */
int wrapfs_write_lower(struct inode *wrapfs_inode, char *data,
				loff_t offset, size_t size, struct file *file)
{
	struct file *lower_file = NULL;
	mm_segment_t fs_save;
	ssize_t rc;
	int append_enabled = 0;

	lower_file = wrapfs_lower_file(file);
	if (!lower_file) {
		printk(KERN_ERR "Could not find corresponsing lower file.");
		return -EIO;
	}
	fs_save = get_fs();
	set_fs(get_ds());

	if (lower_file->f_flags & O_APPEND) {
		append_enabled = 1;
		lower_file->f_flags &= ~(O_APPEND);
	}
	rc = vfs_write(lower_file, data, size, &offset);

	if (append_enabled) {
		append_enabled = 0;
		lower_file->f_flags |= O_APPEND;
	}
	set_fs(fs_save);
	mark_inode_dirty_sync(wrapfs_inode);
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(rc);
#endif
	return rc;
}
/**This function is taken from ecryptfs with necessary changes
 * wrapfs_write_lower_page_segment
 * @wrapfs_inode: The wrapfs inode
 * @page_for_lower: The page containing the data to be written to the
 *                  lower file
 * @offset_in_page: The offset in the @page_for_lower from which to
 *                  start writing the data
 * @size: The amount of data from @page_for_lower to write to the
 *        lower file
 * @file: The corresponding file pointer
 * Determines the byte offset in the file for the given page and
 * offset within the page, maps the page, and makes the call to write
 * the contents of @page_for_lower to the lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
int wrapfs_write_lower_page_segment(struct inode *wrapfs_inode,
						  struct page *page_for_lower,
						  size_t offset_in_page,
						  size_t size,
						  struct file *file)
{
	char *virt;
	loff_t offset;
	int rc;
	struct page *dst_page = NULL;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	offset = ((((loff_t)page_for_lower->index) << PAGE_CACHE_SHIFT)
			  + offset_in_page);
#ifdef WRAPFS_CRYPTO
	if (strlen(WRAPFS_SB(page_for_lower->mapping->host->i_sb)->key) != 0) {
		dst_page = alloc_page(GFP_USER);
		if (!dst_page) {
			rc = -ENOMEM;
			printk(KERN_ERR "Error allocating memory for "
				   "page\n");
			goto out;
		}
		rc = decrypt_encrypt_page(page_for_lower, dst_page,
			WRAPFS_SB(page_for_lower->mapping->host->i_sb)->key,
		sizeof(WRAPFS_SB(page_for_lower->mapping->host->i_sb)->key)-1,
			1);
		virt = kmap(dst_page);
	} else {
		printk(KERN_ERR "key Not Set\n");
		rc = -EPERM;
		goto out;
#endif
		virt = kmap(page_for_lower);
#ifdef WRAPFS_CRYPTO
	}
#endif
	rc = wrapfs_write_lower(wrapfs_inode, virt, offset, size, file);
	if (rc > 0)
		rc = 0;
	if (dst_page) {
		kunmap(dst_page);
		__free_page(dst_page);
	} else {
		kunmap(page_for_lower);
	}
#ifdef WRAPFS_CRYPTO
out:
#endif
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(rc);
#endif
	return rc;
}
/**This function is taken from ecryptfs with necessary changes
 * wrapfs_writepage
 * @page: Page that is locked before this call is made
 *
 * Returns zero on success; non-zero otherwise
 */
static int wrapfs_writepage(struct page *page, struct writeback_control *wbc)
{
	int rc = 0;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	/*
	 * Refuse to write the page out if we are called from reclaim context
	 * since our writepage() path may potentially allocate memory when
	 * calling into the lower fs vfs_write() which may in turn invoke
	 * us again.
	 */
	if (current->flags & PF_MEMALLOC) {
		redirty_page_for_writepage(wbc, page);
		rc = 0;
		goto out;
	}
	/*
	 here we need to write some code that copises the page to the lower.
	 */
	if (rc) {
		printk(KERN_WARNING "Error encrypting "
				"page (upper index [0x%.16lx])\n", page->index);
		ClearPageUptodate(page);
		goto out;
	}
	SetPageUptodate(page);
out:
	unlock_page(page);
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(rc);
#endif
	return rc;
}
/**This function is taken from ecryptfs with necessary changes
 * wrapfs_readpage
 * @file: A file
 * @page: Page from wrapfs inode mapping into which to stick the read data
 *
 * Read in a page, decrypting if necessary.
 *
 * Returns zero on success; non-zero on error.
 */
static int wrapfs_readpage(struct file *file, struct page *page)
{
	int ret = 0;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	ret = wrapfs_read_lower_page_segment(
					page, page->index, 0,
					PAGE_CACHE_SIZE, page->mapping->host,
					file);
	if (ret) {
		printk(KERN_ERR "Error decrypting page; "
						"ret = [%d]\n", ret);
		goto out;
	}
out:
	if (ret)
		ClearPageUptodate(page);
	else
		SetPageUptodate(page);
	printk(KERN_DEBUG "Unlocking page with index = [0x%.16lx]\n",
					page->index);
	unlock_page(page);
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(ret);
#endif
	return ret;
}
/**
 * This function is taken from ecryptfs with necessary changes
 * wrapfs_get_locked_page
 * Get one page from cache or lower f/s, return error otherwise.
 *
 * Returns locked and up-to-date page (if ok), with increased
 * refcnt.
 */
struct page *wrapfs_get_locked_page(struct inode *inode,
							loff_t index,
							struct file *file)
{
	struct page *page = NULL;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	page = read_mapping_page(inode->i_mapping, index, file);
	if (!IS_ERR(page))
		lock_page(page);
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		(IS_ERR(page)) ? DBGRET(-1) : DBGRET(0);
#endif
	return page;
}
/**
 * This function is taken from ecryptfs with necessary changes
 * wrapfs_write
 * @wrapfs_inode: The wrapfs file into which to write
 * @data: Virtual address where data to write is located
 * @offset: Offset in the wrapfs file at which to begin writing the
 *          data from @data
 * @size: The number of bytes to write from @data
 *
 * Write an arbitrary amount of data to an arbitrary location in the
 * wrapfs inode page cache. This is done on a page-by-page. This function
 * takes care of all the address translation to locations in the lower
 * filesystem; it also handles truncate events, writing out zeros
 * where necessary.
 *
 * Returns zero on success; non-zero otherwise
 */
int wrapfs_write(struct inode *wrapfs_inode, char *data, loff_t offset,
				   size_t size, struct file *file)
{
	struct page *wrapfs_page;
	char *wrapfs_page_virt;
	loff_t wrapfs_file_size = i_size_read(wrapfs_inode);
	loff_t data_offset = 0;
	loff_t curr_pos;
	int rc = 0;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	/*
	 * if we are writing beyond current size, then start pos
	 * at the current size - we'll fill in zeros from there.
	 */
	if (offset > wrapfs_file_size)
		curr_pos = wrapfs_file_size;
	else
		curr_pos = offset;
	while (curr_pos < (offset + size)) {
		pgoff_t wrapfs_page_idx = (curr_pos >> PAGE_CACHE_SHIFT);
		size_t start_offset_in_page = (curr_pos & ~PAGE_CACHE_MASK);
		size_t num_bytes = (PAGE_CACHE_SIZE - start_offset_in_page);
		size_t total_remaining_bytes = ((offset + size) - curr_pos);

		if (num_bytes > total_remaining_bytes)
			num_bytes = total_remaining_bytes;
		if (curr_pos < offset) {
			/* remaining zeros to write, up to destination offset */
			size_t total_remaining_zeros = (offset - curr_pos);

			if (num_bytes > total_remaining_zeros)
				num_bytes = total_remaining_zeros;
		}
		wrapfs_page = wrapfs_get_locked_page(wrapfs_inode,
							wrapfs_page_idx, file);
		if (IS_ERR(wrapfs_page)) {
			rc = PTR_ERR(wrapfs_page);
			printk(KERN_ERR "%s: Error getting page at "
			       "index [%ld] from wrapfs inode "
			       "mapping; rc = [%d]\n", __func__,
			       wrapfs_page_idx, rc);
			goto out;
		}
		wrapfs_page_virt = kmap_atomic(wrapfs_page, KM_USER0);
		/*
		 * pos: where we're now writing, offset: where the request was
		 * If current pos is before request, we are filling zeros
		 * If we are at or beyond request, we are writing the *data*
		 * If we're in a fresh page beyond eof, zero it in either case
		 */
		if (curr_pos < offset || !start_offset_in_page) {
			/* We are extending past the previous end of the file.
			 * Fill in zero values to the end of the page */
			memset(((char *)wrapfs_page_virt
					+ start_offset_in_page), 0,
				   PAGE_CACHE_SIZE - start_offset_in_page);
		}
		/* pos >= offset, we are now writing the data request */
		if (curr_pos >= offset) {
			memcpy(((char *)wrapfs_page_virt
					+ start_offset_in_page),
			       (data + data_offset), num_bytes);
			data_offset += num_bytes;
		}
		kunmap_atomic(wrapfs_page_virt, KM_USER0);
		flush_dcache_page(wrapfs_page);
		SetPageUptodate(wrapfs_page);
		unlock_page(wrapfs_page);
		rc = wrapfs_write_lower_page_segment(wrapfs_inode,
						wrapfs_page,
						start_offset_in_page,
						data_offset,
						file);
		page_cache_release(wrapfs_page);
		if (rc) {
			printk(KERN_ERR "%s: Error encrypting "
			       "page; rc = [%d]\n", __func__, rc);
			goto out;
		}
		curr_pos += num_bytes;
	}
	if ((offset + size) > wrapfs_file_size)
		i_size_write(wrapfs_inode, (offset + size));
out:
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(rc);
#endif
	return rc;
}

/**
 *This function is taken from ecryptfs with necessary changes
 * truncate_upper
 * @dentry: The wrapfs layer dentry
 * @ia: Address of the wrapfs inode's attributes
 * @lower_ia: Address of the lower inode's attributes
 *
 * Function to handle truncations modifying the size of the file. Note
 * that the file sizes are interpolated. When expanding, we are simply
 * writing strings of 0's out. When truncating, we truncate the upper
 * inode and update the lower_ia according to the page index
 * interpolations. If ATTR_SIZE is set in lower_ia->ia_valid upon return,
 * the caller must use lower_ia in a call to notify_change() to perform
 * the truncation of the lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int truncate_upper(struct dentry *dentry, struct iattr *ia,
				struct iattr *lower_ia, struct file *file)
{
	int rc = 0;
	struct inode *inode = dentry->d_inode;
	loff_t i_size = i_size_read(inode);
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	if (unlikely((ia->ia_size == i_size))) {
		lower_ia->ia_valid &= ~ATTR_SIZE;
		return 0;
	}
	/* Switch on growing or shrinking file */
	if (ia->ia_size > i_size) {
		char zero[] = { 0x00 };

		lower_ia->ia_valid &= ~ATTR_SIZE;
		/* Write a single 0 at the last position of the file;
		 * this triggers code that will fill in 0's throughout
		 * the intermediate portion of the previous end of the
		 * file and the new and of the file */
		rc = wrapfs_write(inode, zero,
				(ia->ia_size - 1), 1, file);
	} else { /* ia->ia_size < i_size_read(inode) */
		/* We're chopping off all the pages down to the page
		 * in which ia->ia_size is located. Fill in the end of
		 * that page from (ia->ia_size & ~PAGE_CACHE_MASK) to
		 * PAGE_CACHE_SIZE with zeros. */
		size_t num_zeros = (PAGE_CACHE_SIZE
				- (ia->ia_size & ~PAGE_CACHE_MASK));

		/*
		 * XXX(truncate) this should really happen at the begginning
		 * of ->setattr.  But the code is too messy to that as part
		 * of a larger patch.  This is also totally missing out
		 * on the inode_change_ok check at the beginning of
		 * ->setattr while would include this.
		 */
		rc = inode_newsize_ok(inode, ia->ia_size);
		if (rc)
			goto out;
		if (strlen(WRAPFS_SB(dentry->d_inode->i_sb)->key) == 0) {
			truncate_setsize(inode, ia->ia_size);
			lower_ia->ia_size = ia->ia_size;
			lower_ia->ia_valid |= ATTR_SIZE;
			goto out;
		}
		if (num_zeros) {
			char *zeros_virt;

			zeros_virt = kzalloc(num_zeros, GFP_KERNEL);
			if (!zeros_virt) {
				rc = -ENOMEM;
				goto out;
			}
			rc = wrapfs_write(inode, zeros_virt,
					ia->ia_size, num_zeros, file);
			kfree(zeros_virt);
			if (rc) {
				printk(KERN_ERR "Error attempting to zero out "
				       "the remainder of the end page on "
				       "reducing truncate; rc = [%d]\n", rc);
				goto out;
			}
		}
		truncate_setsize(inode, ia->ia_size);
	}
out:
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(rc);
#endif
	return rc;
}
/**
 *This function is taken from ecryptfs with necessary changes
 * wrapfs_truncate
 * @dentry: The wrapfs layer dentry
 * @new_length: The length to expand the file to
 *
 * Simple function that handles the truncation of an inode and
 * its corresponding lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
int wrapfs_truncate(struct dentry *dentry, loff_t new_length,
					struct file *file)
{
	struct iattr ia = { .ia_valid = ATTR_SIZE, .ia_size = new_length };
	struct iattr lower_ia = { .ia_valid = 0 };
	int rc;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	rc = truncate_upper(dentry, &ia, &lower_ia, file);
	if (!rc && lower_ia.ia_valid & ATTR_SIZE) {
		struct dentry *lower_dentry = wrapfs_dentry_to_lower(dentry);

		mutex_lock(&lower_dentry->d_inode->i_mutex);
		rc = notify_change(lower_dentry, &lower_ia);
		mutex_unlock(&lower_dentry->d_inode->i_mutex);
	}
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(rc);
#endif
	return rc;
}
/**
 *This function is taken from ecryptfs with necessary changes
 * wrapfs_write_begin
 * @file: The file pointer
 * @mapping: The wrapfs object
 * @pos: The file offset at which to start writing
 * @len: Length of the write
 * @flags: Various flags
 * @pagep: Pointer to return the page
 * @fsdata: Pointer to return fs data (unused)
 *
 * This function must zero any hole we create
 *
 * Returns zero on success; non-zero otherwise
 */

static int wrapfs_write_begin(struct file *file,
						struct address_space *mapping,
						loff_t pos, unsigned len,
						unsigned flags,
						struct page **pagep,
						void **fsdata)
{
	int ret = 0;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;
	loff_t prev_page_end_size;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;

	prev_page_end_size = ((loff_t)index << PAGE_CACHE_SHIFT);
	if (!PageUptodate(page)) {
		if (prev_page_end_size
			>= i_size_read(page->mapping->host)) {
			zero_user(page, 0, PAGE_CACHE_SIZE);
		} else {
			ret = wrapfs_read_lower_page_segment(
							 page, index, 0,
							 PAGE_CACHE_SIZE,
							 mapping->host,
							 file);
			if (ret) {
				printk(KERN_ERR "%s: Error decrypting "
					   "page at index [%ld]; "
					   "rc = [%d]\n",
					   __func__, page->index, ret);
				ClearPageUptodate(page);
				goto out;
			}
		}
		SetPageUptodate(page);
	}
	/* If creating a page or more of holes, zero them out via truncate.
	 * Note, this will increase i_size. */
	if (index != 0) {
		if (prev_page_end_size > i_size_read(page->mapping->host)) {
			ret = wrapfs_truncate(file->f_path.dentry,
							 prev_page_end_size,
							 file);
			if (ret) {
				printk(KERN_ERR "%s: Error on attempt to "
				       "truncate to (higher) offset [%lld];"
				       " ret = [%d]\n", __func__,
				       prev_page_end_size, ret);
				goto out;
			}
		}
	}
	/* Writing to a new page, and creating a small hole from start
	 * of page?  Zero it out. */
	if ((i_size_read(mapping->host) == prev_page_end_size)
		&& (pos != 0)) {
		printk(KERN_INFO "Creating a small hole from start\n");
		zero_user(page, 0, PAGE_CACHE_SIZE);
	}
out:
	if (unlikely(ret)) {
		unlock_page(page);
		page_cache_release(page);
		*pagep = NULL;
	}
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(ret);
#endif
	return ret;
}
/**
 * This function is taken from ecryptfs with necessary changes
 * wrapfs_write_end
 * @file: The file object
 * @mapping: The addr space mapping object
 * @pos: The file position
 * @len: The length of the data (unused)
 * @copied: The amount of data copied
 * @page: The page
 * @fsdata: The fsdata (unused)
 *
 * This is where we encrypt the data and pass the encrypted data to
 * the lower filesystem.
 */
static int wrapfs_write_end(struct file *file,
						struct address_space *mapping,
						loff_t pos, unsigned len,
						unsigned copied,
						struct page *page, void *fsdata)
{
	int ret = 0;
	/*pgoff_t index = pos >> PAGE_CACHE_SHIFT;*/
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	unsigned to = from + copied;
	struct inode *wrapfs_inode = mapping->host;
	int need_unlock_page = 1;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	ret = wrapfs_write_lower_page_segment(
							wrapfs_inode,
							page, 0,
							to, file);

	if (!ret) {
		ret = copied;
		fsstack_copy_inode_size(wrapfs_inode,
					wrapfs_lower_inode(wrapfs_inode));
	} else{
		goto out;
	}
	set_page_dirty(page);
	unlock_page(page);
	need_unlock_page = 0;
	if (pos + copied > i_size_read(wrapfs_inode)) {
		i_size_write(wrapfs_inode, pos + copied);
		printk(KERN_DEBUG "Expanded file size to "
						"[0x%.16llx]\n",
			(unsigned long long)i_size_read(wrapfs_inode));
		balance_dirty_pages_ratelimited(mapping);
	}
	ret = copied;
out:
	if (need_unlock_page)
		unlock_page(page);
	page_cache_release(page);
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(ret);
#endif
	return ret;
}
static sector_t wrapfs_bmap(struct address_space *mapping, sector_t block)
{
	int ret = 0;
	struct inode *inode;
	struct inode *lower_inode;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	inode = (struct inode *)mapping->host;
	lower_inode = wrapfs_lower_inode(inode);
	if (lower_inode->i_mapping->a_ops->bmap)
		ret = lower_inode->i_mapping->a_ops->bmap(
							lower_inode->i_mapping,
							block);
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(ret);
#endif
	return ret;
}
static int wrapfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	struct file *file, *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
	struct vm_area_struct lower_vma;
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		UDBG;
#endif
	memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
	file = lower_vma.vm_file;
	lower_vm_ops = WRAPFS_F(file)->lower_vm_ops;
	BUG_ON(!lower_vm_ops);

	lower_file = wrapfs_lower_file(file);
	/*
	 * XXX: vm_ops->fault may be called in parallel.  Because we have to
	 * resort to temporarily changing the vma->vm_file to point to the
	 * lower file, a concurrent invocation of wrapfs_fault could see a
	 * different value.  In this workaround, we keep a different copy of
	 * the vma structure in our stack, so we never expose a different
	 * value of the vma->vm_file called to us, even temporarily.  A
	 * better fix would be to change the calling semantics of ->fault to
	 * take an explicit file pointer.
	 */
	lower_vma.vm_file = lower_file;
	err = lower_vm_ops->fault(&lower_vma, vmf);
#ifdef EXTRA_CREDIT
	if (debug_opt & A_DOPS || debug_opt & ALL_DOPS)
		DBGRET(err);
#endif
	return err;
}

/*
 * XXX: the default address_space_ops for wrapfs is empty.  We cannot set
 * our inode->i_mapping->a_ops to NULL because too many code paths expect
 * the a_ops vector to be non-NULL.
 */
const struct address_space_operations wrapfs_aops = {
	.writepage = wrapfs_writepage,
	.readpage = wrapfs_readpage,
	.write_begin = wrapfs_write_begin,
	.write_end = wrapfs_write_end,
	.bmap = wrapfs_bmap,
};

const struct vm_operations_struct wrapfs_vm_ops = {
	.fault		= wrapfs_fault,
};
