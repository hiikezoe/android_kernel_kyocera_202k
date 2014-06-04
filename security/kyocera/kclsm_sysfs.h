/* security/kyocera/kclsm_sysfs.h  (kclsm LSM module sysfs interface)
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
#ifndef __KCLSM_SYSFS_H__
#define __KCLSM_SYSFS_H__

int debuggerd_pid(void);
int ueventd_pid(void);
int vold_pid(void);
int rmt_storage_pid(void);
int lkspad_pid(void);
int wifi_diag_pid(void);
int fs_mgr_pid(void);
#endif
