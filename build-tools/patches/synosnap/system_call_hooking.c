// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "system_call_hooking.h"
#include "blkdev.h"
#include "cow_manager.h"
#include "filesystem.h"
#include "includes.h"
#include "ioctl_handlers.h"
#include "logging.h"
#include "paging_helper.h"
#include "snap_device.h"
#include "task_helper.h"
#include "tracer.h"
#include "tracer_helper.h"
#include "bdev_state_handler.h"
#include "extract_mount_params.h"

#ifdef HAVE_UAPI_MOUNT_H
#include <uapi/linux/mount.h>
#endif




#ifndef UMOUNT_NOFOLLOW
#define UMOUNT_NOFOLLOW 0
#endif

#ifdef USE_NEW_MOUNT_API
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/fs_context.h>
#include <linux/fs_struct.h>
#include <linux/ns_common.h>
#endif

#if !SYS_MOUNT_ADDR
#if __X64_SYS_MOUNT_ADDR || __ARM64_SYS_MOUNT_ADDR
#define USE_ARCH_MOUNT_FUNCS
#else
#warning "No mount function found"
#endif
#endif

#ifdef USE_ARCH_MOUNT_FUNCS
#ifdef USE_NEW_MOUNT_API
// kernel >= 6.6
static asmlinkage long (*orig_move_mount)(struct pt_regs *regs);
static asmlinkage long (*orig_mount_setattr)(struct pt_regs *regs);
static asmlinkage long (*orig_fsconfig)(struct pt_regs *regs);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)
// kernel >= 6.12: major mnt_namespace restructure
struct mnt_namespace {
	struct ns_common	ns;
	struct mount *		root;
	struct rb_node		mnt_ns_tree_node;
	struct list_head	mnt_ns_list;
	spinlock_t		ns_lock;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t	poll;
	u64			event;
	unsigned int		nr_mounts; /* # of mounts in the namespace */
	unsigned int		pending_mounts;
	struct rb_root		mounts; /* Protected by namespace_sem */
	refcount_t		passive;
} __randomize_layout;
#else
struct mnt_namespace {
	struct ns_common	ns;
	struct mount *	root;
#ifndef HAVE_BDEV_FREEZE
// kernel < 6.8
	struct list_head	list;
	spinlock_t		ns_lock;
	unsigned int		mounts; /* # of mounts in the namespace */
#else
// kernel 6.8-6.11
#ifdef HAVE_BDEV_FILE_OPEN_BY_PATH
// kernel 6.9-6.11: mnt_ns_tree_node added before mounts
	struct rb_node		mnt_ns_tree_node;
#endif
	struct rb_root		mounts; /* Protected by namespace_sem */
	unsigned int		nr_mounts; /* # of mounts in the namespace */
#endif
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	u64 event;
	unsigned int		pending_mounts;
} __randomize_layout;
#endif

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
#ifndef HAVE_BDEV_FREEZE
// kernel < 6.8
	struct list_head mnt_list;
#else
// kernel >= 6.8
	union {
		struct rb_node mnt_node;	/* Under ns->mounts */
		struct list_head mnt_list;
	};
#endif
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	struct mountpoint *mnt_mp;	/* where is it mounted */
	union {
		struct hlist_node mnt_mp_list;	/* list mounts with the same mountpoint */
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting; /* list entry for umount propagation */
#ifdef CONFIG_FSNOTIFY
	struct fsnotify_mark_connector __rcu *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
} __randomize_layout;

#else
static asmlinkage long (*orig_mount)(struct pt_regs *regs);
#endif //USE_NEW_MOUNT_API
static asmlinkage long (*orig_umount)(struct pt_regs *regs);
#else
#ifndef USE_NEW_MOUNT_API
static asmlinkage long (*orig_mount)(char __user *, char __user *, char __user *, unsigned long, void __user *);
#endif //USE_NEW_MOUNT_API
static asmlinkage long (*orig_umount)(char __user *name, int flags);
#endif

#ifdef HAVE_SYS_OLDUMOUNT
static asmlinkage long (*orig_oldumount)(char __user *);
#endif


#define set_syscall(sys_nr, orig_call_save, new_call)                          \
        orig_call_save = system_call_table[sys_nr];                            \
        system_call_table[sys_nr] = new_call;

#define restore_syscall(sys_nr, orig_call_save)                                \
        system_call_table[sys_nr] = orig_call_save;

void **system_call_table = NULL;

#ifndef USE_NEW_MOUNT_API
// kernel < 6.6
#ifdef USE_ARCH_MOUNT_FUNCS
static asmlinkage long mount_hook(struct pt_regs *regs){
#else
static asmlinkage long mount_hook(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data){
#endif
	int ret;
	int ret_dev;
	int ret_dir;
	long sys_ret;
	unsigned int idx;
	char *buff_dev_name = NULL;
	char *buff_dir_name = NULL;
	unsigned long real_flags;

#ifdef USE_ARCH_MOUNT_FUNCS
	unsigned long flags;
	char *dir_name;
	char *dev_name;

	ret = mount_hook_extract_params(regs, &dev_name, &dir_name, &flags);
	if (ret) {
		// should never happen
		LOG_ERROR(ret, "couldn't extract mount params");
		return ret;
	}
#endif

	real_flags = flags;

	buff_dev_name = kmalloc(PATH_MAX, GFP_ATOMIC);
	buff_dir_name = kmalloc(PATH_MAX, GFP_ATOMIC);
	if(!buff_dev_name || !buff_dir_name) {
		if(buff_dev_name)
			kfree(buff_dev_name);
		if(buff_dir_name)
			kfree(buff_dir_name);
		return -ENOMEM;
	}

	ret_dev = copy_from_user(buff_dev_name, dev_name, PATH_MAX);
	ret_dir = copy_from_user(buff_dir_name, dir_name, PATH_MAX);

	if(ret_dev || ret_dir)
		LOG_DEBUG("detected block device Get mount params error!");
	else
		LOG_DEBUG("detected block device mount: %s -> %s : 0x%lx", buff_dev_name,
			buff_dir_name, real_flags);



	//get rid of the magic value if its present
	if((real_flags & MS_MGC_MSK) == MS_MGC_VAL) real_flags &= ~MS_MGC_MSK;

	if((real_flags & MS_RDONLY) && (real_flags & MS_REMOUNT)){
		ret = handle_bdev_mount_nowrite_user(dir_name, 0, &idx);

#ifdef USE_ARCH_MOUNT_FUNCS
		sys_ret = orig_mount(regs);
#else
		sys_ret = orig_mount(dev_name, dir_name, type, flags, data);
#endif

		post_umount_check(ret, sys_ret, idx, dir_name, 1);
	}

	else if(real_flags & (MS_BIND | MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE | MS_MOVE) || ((real_flags & MS_RDONLY) && !(real_flags & MS_REMOUNT))){
		//bind, shared, move, or new read-only mounts it do not affect the state of the driver
#ifdef USE_ARCH_MOUNT_FUNCS
		sys_ret = orig_mount(regs);
#else
		sys_ret = orig_mount(dev_name, dir_name, type, flags, data);
#endif
	}else{
		//new read-write mount
		ret = setup_traced(buff_dev_name);
		if(ret) {
			LOG_ERROR(ret, "failed to setup traced");
		}
#ifdef USE_ARCH_MOUNT_FUNCS
		sys_ret = orig_mount(regs);
#else
		sys_ret = orig_mount(dev_name, dir_name, type, flags, data);
#endif
		if(!sys_ret) handle_bdev_mounted_writable_user(dir_name, &idx);
	}

	kfree(buff_dev_name);
	kfree(buff_dir_name);

	LOG_DEBUG("mount returned: %ld", sys_ret);

	return sys_ret;
}
#else 
// kernel >= 6.6

#ifndef HAVE_BDEV_FREEZE
// kernel <= 6.8
static bool may_mount(void)
{
	return ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN);
}
#endif

static asmlinkage long move_mount_hook(struct pt_regs *regs){
	int ret;
	int ret_from;
	int ret_to;
	long sys_ret;
	unsigned int idx;
	char *buff_to_dir_name = NULL;
	char *buff_from_dir_name = NULL;
	unsigned int real_flags;
	struct path from_path;
	unsigned int lflags;

	int from_dfd;
	char *from_dir;
	int to_dfd;
	char *to_dir;
	unsigned int flags;
	

	ret = move_mount_hook_extract_params(regs, &from_dfd, &from_dir, &to_dfd, &to_dir, &flags);
	if (ret) {
		// should never happen
		LOG_ERROR(ret, "couldn't extract move mount params");
		return ret;
	}
	LOG_DEBUG("detected block device move mount hooked: 0x%x", flags);
	real_flags = flags;

#ifndef HAVE_BDEV_FREEZE
	if (!may_mount()) return -EPERM;
#endif

	if (real_flags & ~MOVE_MOUNT__MASK) return -EINVAL;

	if ((real_flags & (MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP)) == (MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP))
		return -EINVAL;

	
	lflags = 0;
	if (real_flags & MOVE_MOUNT_F_SYMLINKS)	lflags |= LOOKUP_FOLLOW;
	if (real_flags & MOVE_MOUNT_F_AUTOMOUNTS)	lflags |= LOOKUP_AUTOMOUNT;
	if (real_flags & MOVE_MOUNT_F_EMPTY_PATH)	lflags |= LOOKUP_EMPTY;

	buff_from_dir_name = kmalloc(PATH_MAX, GFP_ATOMIC);
	buff_to_dir_name = kmalloc(PATH_MAX, GFP_ATOMIC);
	if (!buff_from_dir_name || !buff_to_dir_name) {
		if(buff_from_dir_name) kfree(buff_from_dir_name);
		if(buff_to_dir_name) kfree(buff_to_dir_name);
		return -ENOMEM;
	}
	ret_to = copy_from_user(buff_to_dir_name, to_dir, PATH_MAX);
	ret_from = copy_from_user(buff_from_dir_name, from_dir, PATH_MAX);
	if(ret_to || ret_from) LOG_DEBUG("detected block device Get mount params error!");
	else LOG_DEBUG("from dir %s to dir %s", buff_from_dir_name, buff_to_dir_name);

	// move mount from dir is not empty means it's not a new mount
	if (*buff_from_dir_name != '\0') {
		kfree(buff_to_dir_name);
		kfree(buff_from_dir_name);
		goto call_orig;
	} 


	kfree(buff_to_dir_name);
	kfree(buff_from_dir_name);

	ret = user_path_at(from_dfd, from_dir, lflags, &from_path);

	// make sure we can get the path & its block device normally
	if(ret < 0 || !from_path.mnt || !from_path.mnt->mnt_sb || !from_path.mnt->mnt_sb->s_bdev) goto free_path;
	
	struct block_device *bdev = from_path.mnt->mnt_sb->s_bdev;
	LOG_DEBUG("from_path->dentry: %s, from_path->mnt->mnt_root: %s", from_path.dentry->d_name.name, from_path.mnt->mnt_root->d_name.name);

	//  handling the case like: mount --bind foo foo, where foo is a directory (not a block device)
	if (from_path.mnt->mnt_root->d_name.name[0] != '/') {
		LOG_DEBUG("from_path.mnt->mnt_root->d_name.name[0] != '/'");
		goto free_path;
	}

	// handling the new read only mount
	LOG_DEBUG("s_flags & SB_RDONLY : %lu", from_path.mnt->mnt_sb->s_flags & SB_RDONLY);
	if (sb_rdonly(from_path.mnt->mnt_sb)){
		LOG_DEBUG("from_path.mnt->mnt_sb is read only");
		goto free_path;
	}

	char *dev_name = kmalloc(PATH_MAX, GFP_ATOMIC);
	if(!dev_name) {
		LOG_ERROR(-ENOMEM, "failed to allocate memory for dev_name");
		goto free_path;
	}

	LOG_DEBUG("bdevname %pg", bdev);
	snprintf(dev_name, PATH_MAX, "/dev/%pg", bdev);
	// bdev_name will be like sdb1, we want to make it look like /dev/sdb1
	LOG_DEBUG("dev_name %s", dev_name);

	// new read-write mount
	ret = setup_traced(dev_name);
	if(ret) {
		LOG_ERROR(ret, "failed to setup traced");
	}

	sys_ret = orig_move_mount(regs);
	if(!sys_ret) handle_bdev_mounted_writable_user(to_dir, &idx);

	path_put(&from_path);
	kfree(dev_name);

	LOG_DEBUG("EXIT move_mount_hook");
	return sys_ret;



free_path:
	path_put(&from_path);

call_orig:
	sys_ret = orig_move_mount(regs);
	return sys_ret;
}


static asmlinkage long mount_setattr_hook(struct pt_regs *regs){
	int ret;
	long sys_ret;
	unsigned int idx;
	unsigned int real_flags;
	struct mount_attr attr;
	struct path target;
	unsigned int lookup_flags = LOOKUP_AUTOMOUNT | LOOKUP_FOLLOW;
	char *dir_name = NULL;
	int len_res;

	int dfd;
	char *path;
	unsigned int flags;
	struct mount_attr *uattr;
	size_t usize;
	
	ret = mount_setattr_hook_extract_params(regs, &dfd, &path, &flags, &uattr, &usize);
	if (ret) {
		// should never happen
		LOG_ERROR(ret, "couldn't extract mount setattr params");
		return ret;
	}
	real_flags = flags;
	LOG_DEBUG("detected block device mount setattr hooks , flags : 0x%x", flags);
	if (real_flags == 0) goto call_orig;

	if (real_flags & ~(AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)) return -EINVAL;

	if (unlikely(usize > PAGE_SIZE)) return -E2BIG;

	if (unlikely(usize < MOUNT_ATTR_SIZE_VER0)) return -EINVAL;

#ifndef HAVE_BDEV_FREEZE
	if (!may_mount()) return -EPERM;
#endif

	ret = copy_struct_from_user(&attr, sizeof(attr), uattr, usize);
	if (ret){
		LOG_ERROR(ret, "error in copying mount attr from user");
		return ret;
	}

	/* Don't bother walking through the mounts if this is a nop. */
	if (attr.attr_set == 0 && attr.attr_clr == 0 && attr.propagation == 0) return 0;


	// not remount && read only
	LOG_DEBUG("attr.attr_set = %llu, attr.attr_clr = %llu, attr.propagation = %llu", attr.attr_set, attr.attr_clr, attr.propagation);

	// set propagation flags (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE) will not effect driver status
	if(attr.propagation && (attr.propagation & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))) {
		LOG_DEBUG("propagation get one of (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)");
		goto call_orig;
	}

	// new read only mount just ignroe it
	if (attr.attr_set == MOUNT_ATTR_RDONLY && attr.attr_clr == 0) {
		LOG_DEBUG("its a new read only mount just ignroe it");
		goto call_orig;
	}

	if (real_flags & AT_NO_AUTOMOUNT) lookup_flags &= ~LOOKUP_AUTOMOUNT;
	if (real_flags & AT_SYMLINK_NOFOLLOW) lookup_flags &= ~LOOKUP_FOLLOW;
	if (real_flags & AT_EMPTY_PATH) lookup_flags |= LOOKUP_EMPTY;

	ret = user_path_at(dfd, path, lookup_flags, &target);
	if (ret < 0) {
		LOG_DEBUG("error finding path in mount_setattr_hook");
		goto free_path;
	}

	ret = path_get_absolute_pathname(&target, &dir_name, &len_res);
	if (ret){
		LOG_ERROR(ret, "error converting target to absolute pathname");
		goto free_path;
	} 
	LOG_DEBUG("dir_name = %s", dir_name);
	LOG_DEBUG("path->dentry: %s, path->mnt->mnt_root: %s", target.dentry->d_name.name, target.mnt->mnt_root->d_name.name);

	if (attr.attr_clr != 0 && attr.attr_set == MOUNT_ATTR_RDONLY){
		// remount with readonly
		LOG_DEBUG("this is a read only remount !!!");
	} else {
		// no propagation, no remount with readonly --> remount with rw, we should treat it as mount
		LOG_DEBUG("detect r/w remount in mount_setattr_hook !!!");
		struct block_device *bdev = target.mnt->mnt_sb->s_bdev;
		if (!bdev || !bdev->bd_disk) goto free_path;
		char *dev_name = kmalloc(PATH_MAX, GFP_ATOMIC);		
		if(!dev_name) {
			LOG_ERROR(-ENOMEM, "failed to allocate memory for dev_name");
			goto free_path;
		}

		LOG_DEBUG("bdevname %pg", bdev);
		snprintf(dev_name, PATH_MAX, "/dev/%pg", bdev);
		// bdev_name will be like sdb1, we want to make it look like /dev/sdb1
		LOG_DEBUG("dev_name %s", dev_name);

		// new read-write mount
		ret = setup_traced(dev_name);
		if(ret) {
			LOG_ERROR(ret, "failed to setup traced");
		}

		sys_ret = orig_mount_setattr(regs);
		if(!sys_ret) handle_bdev_mounted_writable_kernel(dir_name, &idx);
		kfree(dev_name);
	}
	
	// clean resoure
	path_put(&target);	
	LOG_DEBUG("EXIT mount_setattr_hook");
	return sys_ret;

free_path:
	path_put(&target);

call_orig:
	sys_ret = orig_mount_setattr(regs);
	return sys_ret;
}


#ifndef HAVE_BDEV_FREEZE
// kernel < 6.8
static inline void lock_ns_list(struct mnt_namespace *ns)
{
	spin_lock(&ns->ns_lock);
}

static inline void unlock_ns_list(struct mnt_namespace *ns)
{
	spin_unlock(&ns->ns_lock);
}
#endif



static asmlinkage long fsconfig_hook(struct pt_regs *regs){
	int ret;
	long sys_ret;
	unsigned int idx;
	struct fs_context *fc;
	struct fd f;
	struct super_block *sb;
	bool remount_ro = false;
	struct mnt_namespace *ns;
	struct mount *mnt = NULL;
#ifdef HAVE_BDEV_FREEZE
	struct mount *n = NULL;
#endif 
	struct dentry *target_dentry = NULL;
	struct path path = {};
	char *dir_name = NULL;
	int len_res;

	int fd;
	unsigned int cmd;
	char *key;
	void *value;
	int aux;

	ret = fsconfig_hook_extract_params(regs, &fd, &cmd, &key, &value, &aux);
	if (ret) {
		// should never happen
		LOG_ERROR(ret, "couldn't extract fsconfig params");
		return ret;
	}
	LOG_DEBUG("detected fsconfig hooked: cmd : 0x%x", cmd);
	// we only care about remount,ro case
	if (fd < 0) return -EINVAL;
	if (cmd != FSCONFIG_CMD_RECONFIGURE) goto call_orig;
	if (key || value || aux) return -EINVAL;

	LOG_DEBUG("fsconfig is FSCONFIG_CMD_RECONFIGUR (remount)");


	f = fdget(fd);
	if (!fd_file(f)) {
		LOG_DEBUG("fd_file(f) is null");
		return -EBADF;
	}
	fc = fd_file(f)->private_data;

	if (fc->phase != FS_CONTEXT_RECONF_PARAMS) goto out_f;
	sb = fc->root->d_sb;
	if (!ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)) {
		fc->phase = FS_CONTEXT_FAILED;
		goto out_f;
	}


	if (fc->sb_flags_mask & ~MS_RMT_MASK) goto out_f;
	if (sb->s_writers.frozen != SB_UNFROZEN) goto out_f;
	if (fc->sb_flags_mask & SB_RDONLY) {
#ifdef CONFIG_BLOCK
		if (!(fc->sb_flags & SB_RDONLY) && sb->s_bdev &&
		    bdev_read_only(sb->s_bdev))
			goto out_f;
#endif
		remount_ro = (fc->sb_flags & SB_RDONLY) && !sb_rdonly(sb);
	}

	if (!remount_ro) goto out_f;
	ns = current->nsproxy->mnt_ns;
	LOG_INFO("start to find fs's mount point in mnt_namespace list");

#if NAMESPACE_SEM_ADDR
	down_read((struct rw_semaphore *)(NAMESPACE_SEM_ADDR + (long long)(((void *)kfree) - (void *)KFREE_ADDR)));
#endif
#ifndef HAVE_BDEV_FREEZE
	lock_ns_list(ns);
	list_for_each_entry(mnt, &ns->list, mnt_list) {
#else
	rbtree_postorder_for_each_entry_safe(mnt, n, &ns->mounts, mnt_node) {
#endif
		if (!mnt || !mnt->mnt.mnt_root) LOG_WARN("found a NULL mount/vfsmount in mountpoint list");
		else if (fc->root == mnt->mnt.mnt_root) {
			LOG_DEBUG("found a filesystem root dentry in mountpoint list");
			target_dentry = mnt->mnt.mnt_root;
			path.dentry = target_dentry;
			path.mnt = &mnt->mnt;
			break;
		}
	}
#ifndef HAVE_BDEV_FREEZE
	unlock_ns_list(ns);
#endif 
#if NAMESPACE_SEM_ADDR
	up_read((struct rw_semaphore *)(NAMESPACE_SEM_ADDR + (long long)(((void *)kfree) - (void *)KFREE_ADDR)));
#endif

	if(!target_dentry) {
		LOG_ERROR(-ENOENT, "failed to find the dentry in current mount namespace");
		goto out_f;
	} 


	ret = path_get_absolute_pathname(&path, &dir_name, &len_res);
	if (ret){
		LOG_ERROR(ret, "error converting target to absolute pathname");
		goto out_f;
	} 

	LOG_DEBUG("dir_name = %s, len_res = %d", dir_name, len_res);


	ret = handle_bdev_mount_nowrite_kernel(dir_name, 0, &idx);
	sys_ret = orig_fsconfig(regs);
	post_umount_check(ret, sys_ret, idx, dir_name, 0);
	LOG_DEBUG("origin fsconfig returned: %ld", sys_ret);

	fdput(f);
	return sys_ret;

out_f:
	fdput(f);

call_orig:
	sys_ret = orig_fsconfig(regs);
	return sys_ret;

}


#endif // USE_NEW_MOUNT_API

#ifdef USE_ARCH_MOUNT_FUNCS
static asmlinkage long umount_hook(struct pt_regs *regs){
#else
static asmlinkage long umount_hook(char __user *name, int flags){
#endif
	int ret;
	long sys_ret;
	unsigned int idx;
	char* buff_dev_name = NULL;

#ifdef USE_ARCH_MOUNT_FUNCS
	unsigned long flags;
	char *name;

	ret = umount_hook_extract_params(regs, &name, &flags);
	if (ret) {
		// should never happen
		LOG_ERROR(ret, "couldn't extract umount params");
		return ret;
	}
#endif

	buff_dev_name = kmalloc(PATH_MAX, GFP_ATOMIC);
	if(!buff_dev_name) {
		return -ENOMEM;
	}

	ret = copy_from_user(buff_dev_name, name, PATH_MAX);
	if(ret)
		LOG_DEBUG("detected block device umount error: %d", ret);
	else
		LOG_DEBUG("detected block device umount: %s : %ld", buff_dev_name, (unsigned long) flags);

	kfree(buff_dev_name);

	ret = handle_bdev_mount_nowrite_user(name, flags, &idx);

#ifdef USE_ARCH_MOUNT_FUNCS
	sys_ret = orig_umount(regs);
#else
	sys_ret = orig_umount(name, flags);
#endif
	post_umount_check(ret, sys_ret, idx, name, 1);

	LOG_DEBUG("umount returned: %ld", sys_ret);

	return sys_ret;
}

#ifdef HAVE_SYS_OLDUMOUNT
static asmlinkage long oldumount_hook(char __user *name){
	int ret;
	long sys_ret;
	unsigned int idx;
	char* buff_dev_name = NULL;

	buff_dev_name = kmalloc(PATH_MAX, GFP_ATOMIC);
	if(!buff_dev_name) {
		return -ENOMEM;
	}
	ret=copy_from_user(buff_dev_name, name, PATH_MAX);
	if(ret)
		LOG_DEBUG("detected block device oldumount error:%d", ret);
	else
		LOG_DEBUG("detected block device oldumount: %s", name);
	kfree(buff_dev_name);

	ret = handle_bdev_mount_nowrite_user(name, 0, &idx);
	sys_ret = orig_oldumount(name);
	post_umount_check(ret, sys_ret, idx, name, 1);

	LOG_DEBUG("oldumount returned: %ld", sys_ret);

	return sys_ret;
}
#endif

/**
 * find_sys_call_table() - Finds the system call table address.
 *
 * Return: the system call table address.
 */
static void **find_sys_call_table(void){
	long long umount_address = 0;
#ifdef USE_NEW_MOUNT_API
	// kernel 6.6
	long long move_mount_address = 0;
	long long mount_setattr_address = 0;
	long long fsconfig_address = 0;
#else
	long long mount_address = 0;
#endif
	long long offset = 0;
	void **sct;

	if(!SYS_CALL_TABLE_ADDR)
		return NULL;

// On kernels after 4.9+, sys_mount() & sys_umount()
// have been switched to the architecture-dependent
// functions, f.e., __x86_64_sys_mount() or __arm64_sys_umount()
// These functions use 'struct pt_regs *' as a parameter.
// Hence, we added additional define USE_ARCH_MOUNT_FUNCS
// to support mount hooks on different kernels
#if !defined(USE_ARCH_MOUNT_FUNCS) && !defined(USE_NEW_MOUNT_API)
// USE_ARCH_MOUNT_FUNCS and kernel < 6.6
	mount_address = SYS_MOUNT_ADDR;
	umount_address = SYS_UMOUNT_ADDR;
#else
#if __X64_SYS_MOUNT_ADDR
#ifdef USE_NEW_MOUNT_API
// kernel >= 6.6
	move_mount_address = __X64_SYS_MOVE_MOUNT_ADDR;
	mount_setattr_address = __X64_SYS_MOUNT_SETATTR_ADDR;
	fsconfig_address = __X64_SYS_FSCONFIG_ADDR;
#else
	mount_address = __X64_SYS_MOUNT_ADDR;
#endif // USE_NEW_MOUNT_API
	umount_address = __X64_SYS_UMOUNT_ADDR;

#elif __ARM64_SYS_MOUNT_ADDR
#ifdef USE_NEW_MOUNT_API
// kernel >= 6.6
	move_mount_address = __ARM64_SYS_MOVE_MOUNT_ADDR;
	mount_setattr_address = __ARM64_SYS_MOUNT_SETATTR_ADDR;
	fsconfig_address = __ARM64_SYS_FSCONFIG_ADDR;
#else
	mount_address = __ARM64_SYS_MOUNT_ADDR;
#endif
	umount_address = __ARM64_SYS_UMOUNT_ADDR;
#else
#error "Architecture not supported"
#endif // __X64_SYS_MOUNT_ADDR
#endif // USE_ARCH_MOUNT_FUNCS


#ifdef USE_NEW_MOUNT_API
// kernel >= 6.6
	if (!move_mount_address || !mount_setattr_address || !umount_address || !fsconfig_address)
		return NULL;
#else
	if (!mount_address || !umount_address)
		return NULL;
#endif 

	offset = ((void *)kfree) - (void *)KFREE_ADDR;
	sct = (void **)SYS_CALL_TABLE_ADDR + offset / sizeof(void **);
#ifdef USE_NEW_MOUNT_API
// kernel >= 6.6
	if(sct[__NR_move_mount] != (void **)move_mount_address + offset / sizeof(void **)) return NULL;
	if(sct[__NR_mount_setattr] != (void **)mount_setattr_address + offset / sizeof(void **)) return NULL;
	if(sct[__NR_fsconfig] != (void **)fsconfig_address + offset / sizeof(void **)) return NULL;
#else	
	if(sct[__NR_mount] != (void **)mount_address + offset / sizeof(void **)) return NULL;
#endif
	if(sct[__NR_umount2] != (void **)umount_address + offset / sizeof(void **)) return NULL;
#ifdef HAVE_SYS_OLDUMOUNT
	if(sct[__NR_umount] != (void **)SYS_OLDUMOUNT_ADDR + offset / sizeof(void **)) return NULL;
#endif

	LOG_DEBUG("system call table located at 0x%p", sct);

	return sct;
}

/** generic function to set a system call table to a read-write mode */
static inline int syscall_mode_rw(void **syscall_table, int syscall_num, unsigned long *flags)
{
	if (!flags) return -EINVAL;

#if defined(CONFIG_X86_64)
	*flags = disable_page_protection();
	return 0;
#elif defined(CONFIG_ARM64)
	return set_page_rw((unsigned long) (syscall_table + syscall_num));
#else
	return -EOPNOTSUPP;
#endif
}

/** generic function to set a system call table to a read-only mode */
static inline long syscall_mode_ro(void **syscall_table, int syscall_num, unsigned long flags)
{
#if defined(CONFIG_X86_64)
	reenable_page_protection(flags);
#elif defined(CONFIG_ARM64)
	return set_page_ro((unsigned long) (syscall_table + syscall_num));
#else
	return -EOPNOTSUPP;
#endif
	return 0;
}

static inline int syscall_set_hook(void **syscall_table,
		int syscall_num, void **orig_hook, void *new_hook)
{
	int ret;
	unsigned long flags;

	ret = syscall_mode_rw(syscall_table, syscall_num, &flags);
	if (ret) {
		LOG_ERROR(ret, "failed to switch the system call table to the read-write mode");
		return ret;
	}

	if (orig_hook)
		*orig_hook = syscall_table[syscall_num];

	syscall_table[syscall_num] = new_hook;
	syscall_mode_ro(syscall_table, syscall_num, flags);

	return 0;
}




/**
 * restore_system_call_table() - Restored the system call table, removing this
 *                               driver's hooks.
 */
void restore_system_call_table(void)
{
	if(system_call_table){
		LOG_DEBUG("restoring system call table");

		preempt_disable();
		// break back into the syscall table and replace the hooks we stole
#ifdef USE_NEW_MOUNT_API
		// kernel >= 6.6
		syscall_set_hook(system_call_table, __NR_move_mount, NULL, orig_move_mount);
		syscall_set_hook(system_call_table, __NR_mount_setattr, NULL, orig_mount_setattr);
		syscall_set_hook(system_call_table, __NR_fsconfig, NULL, orig_fsconfig);
#else
		syscall_set_hook(system_call_table, __NR_mount, NULL, orig_mount);
#endif //USE_NEW_MOUNT_API
		syscall_set_hook(system_call_table, __NR_umount2, NULL, orig_umount);
#ifdef HAVE_SYS_OLDUMOUNT
		syscall_set_hook(system_call_table, __NR_umount, NULL, orig_oldmount);
#endif
		preempt_enable();
	}
}

/**
 * hook_system_call_table() - Insert this driver's hooks for detecting events
 * such as mount and umount.
 *
 * Return:
 * * 0 - success
 * * !0 - errno indicating the error
 */
int hook_system_call_table(void)
{
	int ret = 0;

	//find sys_call_table
	LOG_DEBUG("locating system call table");
	system_call_table = find_sys_call_table();
	if(!system_call_table){
		LOG_ERROR(-ENOENT, "failed to locate system call table, persistence disabled");

		if (!SYS_CALL_TABLE_ADDR) {
			LOG_WARN("make sure that CONFIG_KALLSYMS_ALL is enabled");
		}

		return -ENOENT;
	}

	preempt_disable();
	//break into the syscall table and steal the hooks we need
#ifdef USE_NEW_MOUNT_API
// kernel >= 6.6
	ret = syscall_set_hook(system_call_table, __NR_move_mount, (void **) &orig_move_mount, move_mount_hook);
	ret |= syscall_set_hook(system_call_table, __NR_mount_setattr, (void **) &orig_mount_setattr, mount_setattr_hook);
	ret |= syscall_set_hook(system_call_table, __NR_fsconfig, (void **) &orig_fsconfig, fsconfig_hook);
#else
	ret = syscall_set_hook(system_call_table, __NR_mount, (void **) &orig_mount, mount_hook);
#endif // USE_NEW_MOUNT_API
	ret |= syscall_set_hook(system_call_table, __NR_umount2, (void **) &orig_umount, umount_hook);
#ifdef HAVE_SYS_OLDUMOUNT
	ret |= syscall_set_hook(system_call_table, __NR_umount, (void **) &orig_oldumount, oldumount_hook);
#endif
	preempt_enable();

	return ret;
}
