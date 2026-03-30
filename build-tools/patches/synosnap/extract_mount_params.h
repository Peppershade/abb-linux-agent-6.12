// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Synology Inc.
 */

#ifndef EXTRACT_MOUNT_PARAMS_H_
#define EXTRACT_MOUNT_PARAMS_H_
#include "kernel-config.h"
#include <linux/ptrace.h>

#include "includes.h"

#ifdef HAVE_UAPI_MOUNT_H
#include <uapi/linux/mount.h>
#endif

#ifdef USE_NEW_MOUNT_API
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/fs_context.h>
#include <linux/fs_struct.h>
#include <linux/ns_common.h>

struct mnt_namespace;
struct mount;
struct mount_attr;
int mount_setattr_hook_extract_params(struct pt_regs *regs, int *dfd, char **path, unsigned int *flags, struct mount_attr **uattr, size_t *usize);
int move_mount_hook_extract_params(struct pt_regs *regs, int *from_dfd , char **from_dir, int *to_dfd, char **to_dir, unsigned int *flags);
int fsconfig_hook_extract_params(struct pt_regs *regs, int *fd , unsigned int *cmd, char **key, void **value, int *aux);
#else
int mount_hook_extract_params(struct pt_regs *regs, char **dev_name, char **dir_name, unsigned long *flags);

#endif
int umount_hook_extract_params(struct pt_regs *regs, char **dev_name, unsigned long *flags);

#endif /* EXTRACT_MOUNT_PARAMS_H_ */