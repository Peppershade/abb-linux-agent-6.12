// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#ifndef SNAP_DEVICE_H_
#define SNAP_DEVICE_H_

#include "bio_helper.h" // needed for USE_BDOPS_SUBMIT_BIO to be defined
#include "bio_queue.h"
#include "bio_request_callback.h"
#include "includes.h"
#include "submit_bio.h"
#include "sset_queue.h"

// macros for defining the state of a tracing struct (bit offsets)
#define SNAPSHOT 0
#define ACTIVE 1
#define UNVERIFIED 2
#define TRACED 3


#define LOWLEVEL_IO_DATA_COUNT 2040
#define LOWLEVEL_IO_META_COUNT 8
#define BLOCK_TO_SECTOR_BY_BLOCK_SIZE(blocknr, block_size) ((blocknr) * ((block_size) / SECTOR_SIZE))
#define SECTOR_TO_BLOCK_BY_BLOCK_SIZE(sect, block_size) ((sect) / ((block_size) / SECTOR_SIZE))


struct lowlevel_io{
	struct lowlevel_io_meta *meta;
	struct lowlevel_io_range *range;
	unsigned long block_size;
	struct file *filp;
        int max_pair_in_meta;
	int blocks_per_page;
};

struct block_pair_count{
	uint64_t size;
	uint64_t reserved;
};

struct lowlevel_io_meta{
	struct page *page;
	 // contains one block_pair_count and various number of block_pair
	struct block_pair_count used;
	void *addr;

	uint64_t blocknr; // meta address in disk
	struct lowlevel_io_meta *next;
};
struct lowlevel_io_range{
	uint64_t blocknr; // range address in disk
	int total;
	int used;
	struct lowlevel_io_range *next;
};

struct block_pair{
	uint64_t start; // cow changed block start
	union {
		uint64_t end; // cow changed block end
		uint64_t blocknr; // blocknr in lowlevel io file
	};
};

#ifdef USE_BDOPS_SUBMIT_BIO
struct tracing_ops {
	struct block_device_operations *bd_ops;
#ifdef HAVE_BD_HAS_SUBMIT_BIO
	bool has_submit_bio; // kernel version >= 6.4
#endif
	atomic_t refs;
};

static inline struct tracing_ops* tracing_ops_get(struct tracing_ops *trops) {
	if (trops) atomic_inc(&trops->refs);
	return trops;
}

static inline void tracing_ops_put(struct tracing_ops *trops) {
	//drop a reference to the tracing ops
	if(atomic_dec_and_test(&trops->refs)) {
		kfree(trops->bd_ops);
		kfree(trops);
	}
}
#endif

struct snap_device {
        struct lowlevel_io *sd_lowlevel_io; // lowlevel io for miss tracked changed when umount
        unsigned int sd_minor; // minor number of the snapshot
        unsigned long sd_state; // current state of the snapshot
        unsigned long sd_falloc_size; // space allocated to the cow file (in
                                      // megabytes)
        unsigned long sd_cache_size; // maximum cache size (in bytes)
        atomic_t sd_refs; // number of users who have this device open
        atomic_t sd_fail_code; // failure return code
        atomic_t sd_active; // boolean for whether the snap device is set up and ready to trace i/o
        sector_t sd_sect_off; // starting sector of base block device
        sector_t sd_size; // size of device in sectors
        struct request_queue *sd_queue; // snap device request queue
        struct gendisk *sd_gd; // snap device gendisk
        struct block_device *sd_base_dev; // device being snapshot
#ifdef HAVE_BDEV_FILE_OPEN_BY_PATH
        struct file *sd_base_file; // file for base device (kernel >= 6.9)
#elif defined(HAVE_BDEV_OPEN_BY_PATH)
        struct bdev_handle *sd_base_handle; // handle for base device (kernel 6.8)
#endif
        char *sd_bdev_path; // base device file path
        struct cow_manager *sd_cow; // cow manager
        struct mutex sd_cow_mutex; // mutex for writing filp
        char *sd_cow_path; // cow file path
        struct inode *sd_cow_inode; // cow file inode
        BIO_REQUEST_CALLBACK_FN *sd_orig_request_fn; // block device's original make_request_fn or submit_bio function ptr.
        struct task_struct *sd_cow_thread; // thread for handling file read/writes
        struct bio_queue sd_cow_bios; // list of outstanding cow bios
        struct task_struct *sd_mrf_thread; // thread for handling file
                                           // read/writes
        struct bio_queue sd_orig_bios; // list of outstanding original bios
        struct sset_queue sd_pending_ssets; // list of outstanding sector sets
#ifndef HAVE_BIOSET_INIT
        //#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
        struct bio_set *sd_bioset; // allocation pool for bios
#else
        struct bio_set sd_bioset; // allocation pool for bios
#endif
        atomic64_t sd_submitted_cnt; // count of read clones submitted to
                                     // underlying driver
        atomic64_t sd_received_cnt; // count of read clones submitted to
                                    // underlying driver
        atomic64_t sd_processed_cnt; //count of read clones processed in snap_cow_thread()
#ifdef USE_BDOPS_SUBMIT_BIO
        struct block_device_operations *bd_ops;
        struct tracing_ops *sd_tracing_ops; //copy of original block_device_operations but with request_function for tracing
#endif
};

#endif /* SNAP_DEVICE_H_ */
