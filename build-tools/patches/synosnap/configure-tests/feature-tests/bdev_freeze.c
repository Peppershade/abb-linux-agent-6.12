// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Synology Inc.
 */

#include "includes.h"

MODULE_LICENSE("GPL");

static int __init dummy_init(void){
	int (*fn)(struct block_device *) = bdev_freeze;
	(void)fn;
	return 0;
}

static void __exit dummy_exit(void){}

module_init(dummy_init);
module_exit(dummy_exit);
