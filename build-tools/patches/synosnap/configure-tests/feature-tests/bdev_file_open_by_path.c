// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Synology Inc.
 * Kernel >= 6.9: bdev_open_by_path replaced with bdev_file_open_by_path
 */

#include "includes.h"

MODULE_LICENSE("GPL");

static int __init dummy_init(void){
	struct file *f;
	const char *path = "/dev/null";
	f = bdev_file_open_by_path(path, BLK_OPEN_READ, NULL, NULL);
	if(IS_ERR(f)) return PTR_ERR(f);
	fput(f);
	return 0;
}

static void __exit dummy_exit(void){}

module_init(dummy_init);
module_exit(dummy_exit);
