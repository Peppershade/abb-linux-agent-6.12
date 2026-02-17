// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

// 5.16 <= kernel_version

#include "includes.h"

MODULE_LICENSE("GPL");

static inline void dummy(void){
	struct block_device *bdev = NULL;
	struct bio_set *bs = NULL;
	struct bio *b = bio_alloc_bioset(bdev, 0, REQ_OP_READ, GFP_NOIO, bs);
	(void)b;
}
