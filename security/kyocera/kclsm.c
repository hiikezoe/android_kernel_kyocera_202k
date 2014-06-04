/* security/kyocera/kclsm.c  (kclsm LSM module)
 * This software is contributed or developed by KYOCERA Corporation.
 * (C) 2012 KYOCERA Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
#include <linux/security.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include "kclsm.h"
#include "kclsm_sysfs.h"

#define KCLSM_KBFM_DISABLE 0
#define KCLSM_KBFM_ENABLE  1
static int kclsm_kbfm = KCLSM_KBFM_DISABLE;
static int __init kclsm_kbfm_setup(char *buf)
{
	if (strcmp(buf, "kcfactory") == 0)
		kclsm_kbfm = KCLSM_KBFM_ENABLE;
	return 0;
}
early_param("androidboot.mode", kclsm_kbfm_setup);

#define KCLSM_BOOTMODE_NORMAL 0
#define KCLSM_BOOTMODE_UPDATE 1
static int kclsm_bootmode = KCLSM_BOOTMODE_NORMAL;
static int __init kclsm_bootmode_setup(char *buf)
{
	if (strcmp(buf, "f-ksg") == 0)
		kclsm_bootmode = KCLSM_BOOTMODE_UPDATE;
	return 0;
}
early_param("kcdroidboot.mode", kclsm_bootmode_setup);

#ifdef CONFIG_SECURITY_KCLSM_PTRACE
static int kclsm_ptrace_access_check(struct task_struct *child,
				     unsigned int mode)
{
	if (current_uid() != 0)
		return KCLSM_RETURN(0);

	if (current->pid == debuggerd_pid())
		return KCLSM_RETURN(0);

	if (mode & PTRACE_MODE_READ)
		return KCLSM_RETURN(0);

	pr_warn("no permission in %s pid=%d pname=%s child=%s mode=%d\n",
		__FUNCTION__, current->pid, current->comm, child->comm, mode);
	return KCLSM_RETURN(-EPERM);
}

static int kclsm_ptrace_traceme(struct task_struct *parent)
{
	if (current_uid() != 0)
		return KCLSM_RETURN(0);

	pr_warn("no permission in %s pid=%d pname=%s parent=%s\n",
		__FUNCTION__, current->pid, current->comm, parent->comm);
	return KCLSM_RETURN(-EPERM);
}
#endif

#ifdef CONFIG_SECURITY_KCLSM_INSMOD
static int kclsm_kernel_setup_load_info(char *kmod_name)
{
	int i;

	for (i=0; kclsm_module_checklist[i]!=NULL; i++)
		if (strcmp(kclsm_module_checklist[i], kmod_name) == 0)
			return KCLSM_RETURN(0);

	pr_warn("no permission in %s pid=%d pname=%s module=%s\n",
		__FUNCTION__, current->pid, current->comm, kmod_name);

	return KCLSM_RETURN(-EPERM);
}
#endif

#ifdef CONFIG_SECURITY_KCLSM_MOUNT
static int kclsm_sb_mount(char *dev_name, struct path *path,
			    char *type, unsigned long flags, void *data)
{
	int i, ret = 0;
	char *ptr, *realpath = NULL;

	ptr = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;

	realpath = d_path(path, ptr, PATH_MAX);

	if (strncmp(realpath, KCLSM_SYSTEM_MOUNT_POINT,
		    strlen(KCLSM_SYSTEM_MOUNT_POINT)) != 0)
		goto out;

	if (strcmp(realpath, KCLSM_SYSTEM_MOUNT_POINT) != 0) {
		if (current->pid == 1)
			goto out;
		else
			goto err;
	}

	if (flags & MS_REMOUNT)
		goto err;

	for (i=0; kclsm_mount_checklist[i] != NULL; i++)
		if (strcmp(dev_name, kclsm_mount_checklist[i]) == 0)
			goto out;

err:
	pr_warn("no permission in %s pid=%d pname=%s realpath=%s dev_name=%s\n",
		__FUNCTION__, current->pid, current->comm, realpath, dev_name);
	ret = -EPERM;
out:
	kfree(ptr);
	return KCLSM_RETURN(ret);
}
#endif

#ifdef CONFIG_SECURITY_KCLSM_UMOUNT
static int kclsm_sb_umount(struct vfsmount *mnt, int flags)
{
	int ret = 0;
	struct path umount_path;
	char *ptr, *realpath = NULL;

	if (kclsm_bootmode == KCLSM_BOOTMODE_UPDATE ||
	    kclsm_kbfm == KCLSM_KBFM_ENABLE)
		return 0;

	ptr = kmalloc(PATH_MAX, GFP_KERNEL);
	if(!ptr)
		return -ENOMEM;

	umount_path.mnt = mnt;
	umount_path.dentry = mnt->mnt_root;

	realpath = d_path(&umount_path, ptr, PATH_MAX);

	if (strcmp(realpath, KCLSM_SYSTEM_MOUNT_POINT) != 0 &&
	    strcmp(realpath, KCLSM_SYSTEM_PROPERTY) != 0 )
		goto out;

	if (strcmp(realpath, KCLSM_SYSTEM_PROPERTY) == 0)
		if (fs_mgr_pid() == current->pid)
			goto out;

	pr_warn("no permission in %s pid=%d pname=%s realpath=%s\n",
		__FUNCTION__, current->pid, current->comm, realpath);
	ret = -EPERM;
out:
	kfree(ptr);
	return KCLSM_RETURN(ret);
}
#endif

#ifdef CONFIG_SECURITY_KCLSM_PIVOTROOT
static int kclsm_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	pr_warn("no permission in %s pid=%d pname=%s\n",
		__FUNCTION__, current->pid, current->comm);
	return KCLSM_RETURN(-EPERM);
}
#endif

#ifdef CONFIG_SECURITY_KCLSM_CHROOT
static int kclsm_path_chroot(struct path *path)
{
	pr_warn("no permission in %s pid=%d pname=%s\n",
		__FUNCTION__, current->pid, current->comm);
	return KCLSM_RETURN(-EPERM);
}
#endif

#ifdef CONFIG_SECURITY_KCLSM_MKNOD
static int kclsm_path_mknod(struct path *dir, struct dentry *dentry,
			    umode_t mode, unsigned int dev)
{
	char *ptr, *realpath = NULL;

	/* allow to create non-block and non-char file */
	if (!S_ISBLK(mode) && !S_ISCHR(mode))
		return 0;

	if (current->pid == 1 ||
	    current->pid == ueventd_pid() || current->pid == vold_pid() ||
	    current->group_leader->pid == vold_pid())
		return 0;

	ptr = kmalloc(PATH_MAX, GFP_KERNEL);
	if(!ptr)
		return -ENOMEM;

	realpath = d_path(dir, ptr, PATH_MAX);

	pr_warn("no permission in %s pid=%d pname=%s realpath=%s",
		__FUNCTION__, current->pid, current->comm, realpath);
	kfree(ptr);

	return KCLSM_RETURN(-EPERM);
}
#endif

#ifdef CONFIG_SECURITY_KCLSM_OPEN

int kclsm_dentry_open(struct file *file, const struct cred *cred)
{
	int ret = 0;
	char *ptr, *realpath = NULL;

	if (kclsm_bootmode == KCLSM_BOOTMODE_UPDATE ||
	    kclsm_kbfm == KCLSM_KBFM_ENABLE)
		return 0;

	ptr = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;

	realpath = d_path(&file->f_path, ptr, PATH_MAX);
	if (strncmp(realpath, KCLSM_SYSTEM_PROPERTY,
		     strlen(KCLSM_SYSTEM_PROPERTY)) == 0 ||
	    strcmp(realpath, KCLSM_SYSTEM_FILE_PSRO) == 0 ||
	    strcmp(realpath, KCLSM_SYSTEM_FILE_PSRW) == 0) {
		if (current->pid == 1 || current->pid == lkspad_pid()
		    || current->group_leader->pid == lkspad_pid())
			goto out;
	} else if (strcmp(realpath, "/dev/mem") == 0) {
		if (current->pid == rmt_storage_pid()) 
			goto out;
	} else {
		goto out;
	}

	ret = -EPERM;
	pr_warn("no permission in %s pid=%d pname=%s realpath=%s",
		__FUNCTION__, current->pid, current->comm, realpath);
out:
	kfree(ptr);
	return KCLSM_RETURN(ret);
}
#endif

static struct security_operations kclsm_security_ops = {
	.name = "kclsm",
#ifdef CONFIG_SECURITY_KCLSM_PTRACE
	.ptrace_access_check = kclsm_ptrace_access_check,
	.ptrace_traceme = kclsm_ptrace_traceme,
#endif
#ifdef CONFIG_SECURITY_KCLSM_INSMOD
	.kernel_setup_load_info  = kclsm_kernel_setup_load_info,
#endif
#ifdef CONFIG_SECURITY_KCLSM_MOUNT
	.sb_mount = kclsm_sb_mount,
#endif
#ifdef CONFIG_SECURITY_KCLSM_UMOUNT
	.sb_umount  = kclsm_sb_umount,
#endif
#ifdef CONFIG_SECURITY_KCLSM_PIVOTROOT
	.sb_pivotroot = kclsm_sb_pivotroot,
#endif
#ifdef CONFIG_SECURITY_KCLSM_CHROOT
	.path_chroot = kclsm_path_chroot,
#endif
#ifdef CONFIG_SECURITY_KCLSM_MKNOD
	.path_mknod = kclsm_path_mknod,
#endif
#ifdef CONFIG_SECURITY_KCLSM_OPEN
	.dentry_open = kclsm_dentry_open,
#endif
};

static int __init kclsm_init(void)
{
	int ret;

	ret = register_security(&kclsm_security_ops);
	if (ret) {
		pr_err("Unable to register kclsm\n");
		return ret;
	}

	pr_info("kclsm initialized\n");

	return 0;
}
security_initcall(kclsm_init);
