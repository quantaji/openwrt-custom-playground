// SPDX-License-Identifier: GPL-2.0-only
/* Isolated read-only snapshot of the two reserved NSS image/heap windows.
 * Root must verify actual firmware access end before setting access_ended.
 * This never follows pointers outside reserved DDR or touches freed DMA logs.
 */
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define SNAPSHOT_BASE 0x40000000ULL
#define SNAPSHOT_SIZE 0x01000000UL

static bool access_ended;
module_param(access_ended, bool, 0400);
MODULE_PARM_DESC(access_ended, "Required assertion of verified NSS access end");
static void __iomem *snapshot_window;
static struct dentry *snapshot_directory;

static ssize_t snapshot_read(struct file *file, char __user *buffer,
                             size_t count, loff_t *position)
{
	void *page;
	size_t length;

	if (*position < 0)
		return -EINVAL;
	if (*position >= SNAPSHOT_SIZE || !count)
		return 0;
	length = min_t(size_t, count, PAGE_SIZE);
	length = min_t(size_t, length, SNAPSHOT_SIZE - *position);
	page = kmalloc(length, GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	memcpy_fromio(page, snapshot_window + *position, length);
	if (copy_to_user(buffer, page, length)) {
		kfree(page);
		return -EFAULT;
	}
	kfree(page);
	*position += length;
	return length;
}

static loff_t snapshot_seek(struct file *file, loff_t offset, int whence)
{
	return fixed_size_llseek(file, offset, whence, SNAPSHOT_SIZE);
}

static const struct file_operations snapshot_operations = {
	.owner = THIS_MODULE,
	.read = snapshot_read,
	.llseek = snapshot_seek,
};

static int __init snapshot_init(void)
{
	struct dentry *data;
	int error;

	if (!access_ended)
		return -EPERM;
	snapshot_window = ioremap(SNAPSHOT_BASE, SNAPSHOT_SIZE);
	if (!snapshot_window)
		return -ENOMEM;
	snapshot_directory = debugfs_create_dir("qdx_nss_snapshot", NULL);
	if (IS_ERR(snapshot_directory)) {
		error = PTR_ERR(snapshot_directory);
		goto unmap;
	}
	data = debugfs_create_file("data", 0400, snapshot_directory, NULL,
				  &snapshot_operations);
	if (IS_ERR(data)) {
		error = PTR_ERR(data);
		debugfs_remove_recursive(snapshot_directory);
		goto unmap;
	}
	return 0;
unmap:
	iounmap(snapshot_window);
	return error;
}

static void __exit snapshot_exit(void)
{
	debugfs_remove_recursive(snapshot_directory);
	iounmap(snapshot_window);
}

module_init(snapshot_init);
module_exit(snapshot_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Read-only reserved NSS DDR diagnostic after access end");
