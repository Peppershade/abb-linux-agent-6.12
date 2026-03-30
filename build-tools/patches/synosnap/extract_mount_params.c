// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Synology Inc.
 */

#include "extract_mount_params.h"

#ifdef USE_NEW_MOUNT_API
int move_mount_hook_extract_params(struct pt_regs *regs, int *from_dfd , char **from_dir, int *to_dfd, char **to_dir, unsigned int *flags)
{
	if (!regs || !from_dfd || !from_dir || !to_dfd || !to_dir || !flags) return -EINVAL;

#if defined(CONFIG_ARM64)
	*from_dfd = (int) regs->regs[0];
	*from_dir = (char *) regs->regs[1];
	*to_dfd = (int) regs->regs[2];
	*to_dir = (char *) regs->regs[3];
	*flags = regs->regs[4];
#elif defined(CONFIG_X86_64)

    *from_dfd = (int) regs->di;
	*from_dir = (char *) regs->si;
	*to_dfd = (int) regs->dx;
	*to_dir = (char *) regs->r10;
	*flags = regs->r8;
#endif
	return 0;
}


int mount_setattr_hook_extract_params(struct pt_regs *regs, int *dfd, char **path, unsigned int *flags, struct mount_attr **uattr, size_t *usize)
{
	if (!regs || !dfd || !path || !flags || !uattr || !usize) return -EINVAL;

#if defined(CONFIG_ARM64)
	*dfd = (int) regs->regs[0];
	*path = (char *) regs->regs[1];
	*flags =  regs->regs[2];
	*uattr = (struct mount_attr *) regs->regs[3];
	*usize = (size_t) regs->regs[4];
#elif defined(CONFIG_X86_64)

    *dfd = (int) regs->di;
	*path = (char *) regs->si;
	*flags = regs->dx;
	*uattr = (struct mount_attr *) regs->r10;
	*usize = (size_t) regs->r8;
#endif
	return 0;
}


int fsconfig_hook_extract_params(struct pt_regs *regs, int *fd , unsigned int *cmd, char **key, void **value, int *aux)
{
	if (!regs || !fd || !cmd || !key || !value || !aux) return -EINVAL;

#if defined(CONFIG_ARM64)
	*fd = (int) regs->regs[0];
	*cmd =  regs->regs[1];
	*key = (char *) regs->regs[2];
	*value =  (void *) regs->regs[3];
	*aux = (int) regs->regs[4];
#elif defined(CONFIG_X86_64)
	*fd = (int) regs->di;
	*cmd = regs->si;
	*key = (char *) regs->dx;
	*value =  (void *) regs->r10;
	*aux = (int) regs->r8;
#endif
	return 0;
}
#else
int mount_hook_extract_params(struct pt_regs *regs, char **dev_name, char **dir_name, unsigned long *flags)
{
	if (!regs || !dev_name || !dir_name || !flags) return -EINVAL;

#if defined(CONFIG_ARM64)
	*dev_name = (char *) regs->regs[0];
	*dir_name = (char *) regs->regs[1];
	*flags = regs->regs[3];
#elif defined(CONFIG_X86_64)
	*dev_name = (char *) regs->di;
	*dir_name = (char *) regs->si;
	*flags = regs->r10;
#endif
	return 0;
}

#endif //USE_NEW_MOUNT_API


int umount_hook_extract_params(struct pt_regs *regs, char **dev_name, unsigned long *flags)
{
	if (!regs || !dev_name || !flags) return -EINVAL;

#if defined(CONFIG_ARM64)
	*dev_name = (char *) regs->regs[0];
	*flags = regs->regs[1];
#elif defined(CONFIG_X86_64)
	*dev_name = (char *) regs->di;
	*flags = regs->si;
#endif
	return 0;
}