// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Synology Inc.
 * Kernel >= 6.10: bd_has_submit_bio replaced with bdev_test_flag(bdev, BD_HAS_SUBMIT_BIO)
 */

#include "includes.h"

MODULE_LICENSE("GPL");

static inline void dummy(void){
	struct block_device *bdev = NULL;
	bool val = bdev_test_flag(bdev, BD_HAS_SUBMIT_BIO);
	(void)val;
}
