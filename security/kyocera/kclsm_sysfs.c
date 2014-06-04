/* security/kyocera/kclsm_sysfs.c  (kclsm LSM module sysfs interface)
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
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include "kclsm_sysfs.h"

#define KCLSM_SYSFS_CREATE(ifname, name) \
	static int name; \
	static ssize_t name##_store(struct kobject *kobj, \
				       struct kobj_attribute *attr, \
				       const char *buf, size_t count ) \
	{ \
		if (current->pid != 1) \
			return count; \
		sscanf(buf, "%du", &name); \
		return count; \
	} \
	static ssize_t name##_show(struct kobject *kobj, \
				    struct kobj_attribute *attr, char *buf) \
	{ \
		return sprintf(buf, "%d\n", name); \
	} \
	static struct kobj_attribute kclsm_##name##_attr = \
		__ATTR(ifname, S_IWUSR | S_IRUSR, name##_show, name##_store); \
	int name##_pid(void) \
	{ \
		return name; \
	} \
	static int dump_##name##_info(char *buf, int need_pid) \
	{ \
		if (need_pid) \
			return sprintf(buf, "%s:%d\n", #ifname, name); \
		else \
			return sprintf(buf, "%s\n", #ifname); \
	}


KCLSM_SYSFS_CREATE(debuggerd, debuggerd);
KCLSM_SYSFS_CREATE(ueventd, ueventd);
KCLSM_SYSFS_CREATE(vold, vold);
KCLSM_SYSFS_CREATE(rmt_storage, rmt_storage);
KCLSM_SYSFS_CREATE(wifi_diag, wifi_diag);
KCLSM_SYSFS_CREATE(lkspad, lkspad);
KCLSM_SYSFS_CREATE(fs_mgr, fs_mgr);

KCLSM_SYSFS_CREATE(kflcd, kflcd);
KCLSM_SYSFS_CREATE(kflcdiag, kflcdiag);
KCLSM_SYSFS_CREATE(ts_daemon, ts_daemon);
KCLSM_SYSFS_CREATE(ts_diag, ts_diag);
KCLSM_SYSFS_CREATE(sdcardioserver, sdcardioserver);
KCLSM_SYSFS_CREATE(usb_init, usb_init);
KCLSM_SYSFS_CREATE(disp_ctrl, disp_ctrl);
KCLSM_SYSFS_CREATE(kdiag_common, kdiag_common);
KCLSM_SYSFS_CREATE(bfss_diag, bfss_diag);
KCLSM_SYSFS_CREATE(extlibd, extlibd);

static ssize_t dump_list_info(char *buf, int need_pid)
{
	char *needle = buf;

	if (!need_pid) {
		needle += dump_debuggerd_info(needle, need_pid);
		needle += dump_ueventd_info(needle, need_pid);
		needle += dump_vold_info(needle, need_pid);
		needle += dump_rmt_storage_info(needle, need_pid);
		needle += dump_wifi_diag_info(needle, need_pid);
		needle += dump_lkspad_info(needle, need_pid);
		needle += dump_fs_mgr_info(needle, need_pid);
	}
	needle += dump_kflcd_info(needle, need_pid);
	needle += dump_kflcdiag_info(needle, need_pid);
	needle += dump_ts_daemon_info(needle, need_pid);
	needle += dump_ts_diag_info(needle, need_pid);
	needle += dump_sdcardioserver_info(needle, need_pid);
	needle += dump_usb_init_info(needle, need_pid);
	needle += dump_disp_ctrl_info(needle, need_pid);
	needle += dump_kdiag_common_info(needle, need_pid);
	needle += dump_bfss_diag_info(needle, need_pid);
	needle += dump_extlibd_info(needle, need_pid);

	return (needle - buf);
}
static ssize_t process_list_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	if (current->pid != 1)
		return 0;

	return dump_list_info(buf, 0);
}
static ssize_t lkspad_client_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	if (current->pid != lkspad
	    && current->group_leader->pid != lkspad)
		return 0;

	return dump_list_info(buf, 1);
}

static struct kobj_attribute kclsm_process_list_attr =
	__ATTR(process_list, S_IRUSR, process_list_show, NULL);
static struct kobj_attribute kclsm_lkspad_client_attr =
	__ATTR(lkspad_client, S_IRUSR, lkspad_client_show, NULL);

static struct attribute *kclsm_attrs[] = {
	/* attributes for processes start */
	&kclsm_debuggerd_attr.attr,
	&kclsm_ueventd_attr.attr,
	&kclsm_vold_attr.attr,
	&kclsm_rmt_storage_attr.attr,
	&kclsm_wifi_diag_attr.attr,
	&kclsm_lkspad_attr.attr,
	&kclsm_fs_mgr_attr.attr,
	&kclsm_kflcd_attr.attr,
	&kclsm_kflcdiag_attr.attr,
	&kclsm_ts_daemon_attr.attr,
	&kclsm_ts_diag_attr.attr,
	&kclsm_sdcardioserver_attr.attr,
	&kclsm_usb_init_attr.attr,
	&kclsm_disp_ctrl_attr.attr,
	&kclsm_kdiag_common_attr.attr,
	&kclsm_bfss_diag_attr.attr,
	&kclsm_extlibd_attr.attr,
	/* attributes for special I/F start */
	&kclsm_process_list_attr.attr,
	&kclsm_lkspad_client_attr.attr,
	NULL,
};

static struct attribute_group kclsm_attr_group = {
	.attrs = kclsm_attrs,
};

static struct kobject *kclsm_kobj;
static int __init kclsm_sysfs_init(void)
{
	int retval;

	kclsm_kobj = kobject_create_and_add("kclsm", kernel_kobj);
	if (!kclsm_kobj)
		goto out_failed;

	retval = sysfs_create_group(kclsm_kobj, &kclsm_attr_group);
	if (retval != 0)
		goto out_kclsm_kobj;

	pr_info("kclsm_sysfs initialized\n");
	return retval;

out_kclsm_kobj:
	kobject_put(kclsm_kobj);
out_failed:
	pr_info("kclsm_sysfs init failed\n");
	return -ENOMEM;
}

static void __exit kclsm_sysfs_exit(void)
{
	kobject_put(kclsm_kobj);
}
module_init(kclsm_sysfs_init);
module_exit(kclsm_sysfs_exit);
MODULE_LICENSE("GPL");
