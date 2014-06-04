/* security/kyocera/kclsm.h
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
#ifndef __KCLSM_H__
#define __KCLSM_H__

#ifdef KCLSM_DEBUG
#define KCLSM_RETURN(ret) (0)
#else
#define KCLSM_RETURN(ret) (ret)
#endif

#define KCLSM_SYSTEM_MOUNT_POINT "/system"
#define KCLSM_SYSTEM_PROPERTY "/pstore"
#define KCLSM_SYSTEM_FILE_PSRO "/system/vendor/etc/ps_ro.dat"
#define KCLSM_SYSTEM_FILE_PSRW "/system/vendor/etc/ps_rw.dat"

#ifdef CONFIG_SECURITY_KCLSM_INSMOD
static const char *kclsm_module_checklist[] = {
	"felica",
	"wlan",
	"prima_wlan",
	NULL,
};
#endif
#ifdef CONFIG_SECURITY_KCLSM_MOUNT
static const char *kclsm_mount_checklist[] = {
	"/dev/block/platform/msm_sdcc.1/by-name/system",
	NULL
};
#endif

#endif
