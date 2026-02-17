// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Synology Inc.
 * Kernel >= 6.9: blk_alloc_disk takes (lim, node_id) instead of just (node_id)
 */

#include "includes.h"

MODULE_LICENSE("GPL");

static int __init dummy_init(void){
	struct gendisk *gd = blk_alloc_disk(NULL, NUMA_NO_NODE);
	if (IS_ERR(gd)) return PTR_ERR(gd);
	put_disk(gd);
	return 0;
}

static void __exit dummy_exit(void){}

module_init(dummy_init);
module_exit(dummy_exit);
