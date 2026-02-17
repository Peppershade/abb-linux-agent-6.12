#include "bdev_state_handler.h"
#include <linux/version.h>

/**
 * auto_transition_dormant() - Transitions an active snapshot to dormant.
 *
 * @minor: the device's minor number.
 */
static void auto_transition_dormant(unsigned int minor)
{
        LOG_DEBUG("ENTER %s minor: %d", __func__, minor);

        mutex_lock(&ioctl_mutex);
        __tracer_active_to_dormant(snap_devices[minor]);
        mutex_unlock(&ioctl_mutex);
        
        LOG_DEBUG("EXIT %s", __func__);
}

/**
 * auto_transition_active() - Transitions a device to an active state
 *                            whether snapshot or incremental.
 *
 * @minor: the device's minor number.
 * @dir_name: the directory name of the mount.
 * @is_user_space: Whether the dir_name is in user space or not.
 */
static void auto_transition_active(unsigned int minor, const char *dir_name, int is_user_space)
{
        struct snap_device *dev = snap_devices[minor];

LOG_DEBUG("ENTER %s minor: %d", __func__, minor);
        mutex_lock(&ioctl_mutex);

        if (test_bit(UNVERIFIED, &dev->sd_state)) {
                if (test_bit(SNAPSHOT, &dev->sd_state))
                        __tracer_unverified_snap_to_active(dev, dir_name, is_user_space);
                else
                        __tracer_unverified_inc_to_active(dev, dir_name, is_user_space);
        } else
                __tracer_dormant_to_active(dev, dir_name, is_user_space);

        mutex_unlock(&ioctl_mutex);

        LOG_DEBUG("EXIT %s", __func__);
}

/**
 * __handle_bdev_mount_nowrite() - Transitions a device to a dormant state
 *                                 when it is unmounted.
 *
 * @mnt: The &struct vfsmount object pointer.
 * @idx_out: Output the minor device number of the transitioned device.
 *
 * Return:
 * * 0 - success
 * * !0 - errno indicating the error
 */
static int __handle_bdev_mount_nowrite(const struct vfsmount *mnt,
                                unsigned int *idx_out)
{
        int ret;
        unsigned int i;
        struct snap_device *dev;
        tracer_for_each(dev, i)
        {
                if (!dev || tracer_read_fail_state(dev) || !test_bit(ACTIVE, &dev->sd_state) || dev->sd_base_dev != mnt->mnt_sb->s_bdev) continue;

                if (mnt == dattobd_get_mnt(dev->sd_cow->filp)) {
                        LOG_DEBUG("block device umount detected for device %d",
                                  i);
                        auto_transition_dormant(i);

                        ret = 0;
                        goto out;
                }
                
        }
        i = 0;
        ret = -ENODEV;
        LOG_DEBUG("block device umount has not been detected for device");
out:
        *idx_out = i;
        return ret;
}

/**
 * __handle_bdev_mount_writable() - Transitions a dormant device to active
 *                                  on mount, if one exists.
 *
 * @dir_name: the directory name of the mount.
 * @bdev: The &struct block_device that stores the COW data.
 * @idx_out: Output the minor device number of the transitioned device.
 * @is_user_space: Whether the dir_name is in user space or not.
 * Return:
 * * 0 - success
 * * !0 - errno indicating the error
 */
static int __handle_bdev_mount_writable(const char *dir_name,
                                 const struct block_device *bdev,
                                 unsigned int *idx_out,
                                 int is_user_space)
{
        int ret;
        unsigned int i;
        struct snap_device *dev;
        struct block_device *cur_bdev;
#ifdef HAVE_BDEV_FILE_OPEN_BY_PATH
        struct file *cur_file;
#elif defined(HAVE_BDEV_OPEN_BY_PATH)
        struct bdev_handle *cur_handle;
#endif

        LOG_DEBUG("ENTER __handle_bdev_mount_writable");

        tracer_for_each(dev, i)
        {
                if (!dev || tracer_read_fail_state(dev) || test_bit(ACTIVE, &dev->sd_state)) continue;
                if (test_bit(UNVERIFIED, &dev->sd_state)) {
                        // get the block device for the unverified tracer we are
                        // looking into
#ifdef HAVE_BDEV_FILE_OPEN_BY_PATH
                        cur_file = bdev_file_open_by_path(dev->sd_bdev_path, BLK_OPEN_READ, NULL, NULL);
                        if (IS_ERR(cur_file)) {
                                cur_file = NULL;
                                continue;
                        }
                        cur_bdev = file_bdev(cur_file);
#elif defined(HAVE_BDEV_OPEN_BY_PATH)
                        cur_handle = bdev_open_by_path(dev->sd_bdev_path, FMODE_READ, NULL, NULL);
                        if (IS_ERR(cur_handle)) {
                                cur_handle = NULL;
                                continue;
                        }
                        cur_bdev = cur_handle->bdev;
#else
                        cur_bdev = dattobd_blkdev_get_by_path(dev->sd_bdev_path, FMODE_READ, NULL);
#endif

                        if (IS_ERR(cur_bdev)) {
#ifdef HAVE_BDEV_FILE_OPEN_BY_PATH
                                fput(cur_file);
#elif defined(HAVE_BDEV_OPEN_BY_PATH)
                                bdev_release(cur_handle);
#endif
                                cur_bdev = NULL;
                                continue;
                        }

                        // if the tracer's block device exists and matches the
                        // one being mounted perform transition
                        if (cur_bdev == bdev) {
                                LOG_DEBUG("block device mount detected for "
                                          "unverified device %d",
                                          i);
                                auto_transition_active(i, dir_name, is_user_space);
#ifdef HAVE_BDEV_FILE_OPEN_BY_PATH
                                fput(cur_file);
                                cur_bdev = NULL;
#elif defined(HAVE_BDEV_OPEN_BY_PATH)
                                bdev_release(cur_handle);
                                cur_bdev = NULL;
#else
                                dattobd_blkdev_put(cur_bdev);
#endif

                                clear_bit(TRACED, &dev->sd_state);

                                ret = 0;
                                goto out;
                        }

                        // put the block device
#ifdef HAVE_BDEV_FILE_OPEN_BY_PATH
                        fput(cur_file);
                        cur_bdev = NULL;
#elif defined(HAVE_BDEV_OPEN_BY_PATH)
                        bdev_release(cur_handle);
                        cur_bdev = NULL;
#else
                        dattobd_blkdev_put(cur_bdev);
#endif


                } else if (dev->sd_base_dev == bdev) {
                        LOG_DEBUG(
                                "block device mount detected for dormant device %d",
                                i);
                        auto_transition_active(i, dir_name, is_user_space);

                        clear_bit(TRACED, &dev->sd_state);

                        ret = 0;
                        goto out;
                }
        }
        i = 0;
        ret = -ENODEV;
        LOG_DEBUG("not found bdev in mount_writable");

out:
        LOG_DEBUG("EXIT __handle_bdev_mount_writable");
        *idx_out = i;
        return ret;
}

/**
 * handle_bdev_mount_event() - A common impl used to handle a mount event.
 *
 * @dir_name: the directory name of the mount.
 * @follow_flags: flags passed to the system call.cd /
 * @idx_out: Output the minor device number of the transitioned device.
 * @mount_writable: Whether the mount is writable or not.
 * @is_user_space: Whether the dir_name is in user space or not.
 * Return:
 * * 0 - success.
 * * !0 - errno indicating the error.
 */
int handle_bdev_mount_event(const char *dir_name, int follow_flags,
                            unsigned int *idx_out, int mount_writable, int is_user_space)
{
        int ret = 0; 
        int lookup_flags = 0; // init_umount LOOKUP_MOUNTPOINT;
        struct path path = {};
        struct block_device *bdev;

        LOG_DEBUG("ENTER %s", __func__);

        if (!(follow_flags & UMOUNT_NOFOLLOW))
                lookup_flags |= LOOKUP_FOLLOW;


// #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
        // ret = kern_path(dir_name, lookup_flags, &path);
// #else
//         ret = user_path_at(AT_FDCWD, dir_name, lookup_flags, &path);
// #endif //LINUX_VERSION_CODE
        // ret = user_path_at(0, dir_name, lookup_flags, &path);

        if (is_user_space) ret = user_path_at(0, dir_name, lookup_flags, &path);
        else ret = kern_path(dir_name, lookup_flags, &path);
        if (ret) {
            LOG_DEBUG("error finding path");
            goto out;
        }
        LOG_DEBUG("path->dentry: %s, path->mnt->mnt_root: %s", path.dentry->d_name.name, path.mnt->mnt_root->d_name.name);

        if (path.dentry != path.mnt->mnt_root) {
                // path specified isn't a mount point
                ret = -ENODEV;
                LOG_DEBUG("path specified isn't a mount point for dir name");
        
                goto out;
        }

        bdev = path.mnt->mnt_sb->s_bdev;        
        if (!bdev) {
                LOG_DEBUG("path specified isn't mounted on a block device");
                ret = -ENODEV;
                goto out;
        }

        if (!mount_writable)
                ret = __handle_bdev_mount_nowrite(path.mnt, idx_out);
        else
                ret = __handle_bdev_mount_writable(dir_name, bdev, idx_out, is_user_space);
        if (ret) {
                // no block device found that matched an incremental
                // do not print user space param here
                LOG_DEBUG("no block device found that matched an incremental for dir name");
                goto out;
        }

        path_put(&path);
        return ret;
out:
        path_put(&path);
        *idx_out = 0;
        return ret;
}

/**
 * post_umount_check() - Checks to make sure umount succeeded and the driver
 *                       is in a good state.
 *
 * @dormant_ret: the return value from transitioning to dormant.
 * @umount_ret: the return value from the original umount call.
 * @idx: the device minor number.
 * @dir_name: the directory name of the mount.
 * @is_user_space: Whether the dir_name is in user space or not.
 */
void post_umount_check(int dormant_ret, int umount_ret, unsigned int idx,
                       const char *dir_name, int is_user_space)
{
        struct snap_device *dev;
        struct super_block *sb;

        LOG_DEBUG("ENTER %s", __func__);
        // if we didn't do anything or failed, just return
        if (dormant_ret) return;
        dev = snap_devices[idx];


        // if we successfully went dormant, but the umount call failed,
        // reactivate
        if (umount_ret) {
                struct block_device *bdev;
#ifdef HAVE_BDEV_FILE_OPEN_BY_PATH
                struct file *bdev_file = bdev_file_open_by_path(dev->sd_bdev_path, BLK_OPEN_READ, NULL, NULL);
                if (IS_ERR(bdev_file)) {
                        bdev_file = NULL;
                        LOG_DEBUG("device gone, moving to error state");
                        tracer_set_fail_state(dev, -ENODEV);
                        return;
                }
                bdev = file_bdev(bdev_file);
#elif defined(HAVE_BDEV_OPEN_BY_PATH)
                struct bdev_handle *handle = bdev_open_by_path(dev->sd_bdev_path, FMODE_READ, NULL, NULL);
                if (IS_ERR(handle)) {
                        handle = NULL;
                        LOG_DEBUG("device gone, moving to error state");
                        tracer_set_fail_state(dev, -ENODEV);
                        return;
                }
                bdev = handle->bdev;
#else
                bdev = dattobd_blkdev_get_by_path(dev->sd_bdev_path, FMODE_READ, NULL);
#endif
                if (!bdev || IS_ERR(bdev)) {
                        LOG_DEBUG("device gone, moving to error state");
#ifdef HAVE_BDEV_FILE_OPEN_BY_PATH
                        fput(bdev_file);
#elif defined(HAVE_BDEV_OPEN_BY_PATH)
                        bdev_release(handle);
#endif
                        tracer_set_fail_state(dev, -ENODEV);
                        return;
                }

#ifdef HAVE_BDEV_FILE_OPEN_BY_PATH
                fput(bdev_file);
                bdev = NULL;
#elif defined(HAVE_BDEV_OPEN_BY_PATH)
                bdev_release(handle);
                bdev = NULL;
#else
                dattobd_blkdev_put(bdev);
#endif

                LOG_DEBUG("umount call failed, reactivating tracer %u", idx);
                auto_transition_active(idx, dir_name, is_user_space);
                return;
        }

        // force the umount operation to complete synchronously
        LOG_DEBUG("[post_umount_check] task_work_flush start ");
        task_work_flush();
        LOG_DEBUG("[post_umount_check] task_work_flush end");



        // if we went dormant, but the block device is still mounted somewhere,
        // goto fail state
        sb = dattobd_get_super(dev->sd_base_dev);

        if (sb) {
                if (!(sb->s_flags & MS_RDONLY)) {
                        LOG_ERROR(
                                -EIO,
                                "device still mounted after umounting cow file's "
                                "file-system. entering error state");
                        tracer_set_fail_state(dev, -EIO);
                        dattobd_drop_super(sb);
                        return;
                }
                dattobd_drop_super(sb);
        }

        LOG_DEBUG("EXIT %s", __func__);
}
