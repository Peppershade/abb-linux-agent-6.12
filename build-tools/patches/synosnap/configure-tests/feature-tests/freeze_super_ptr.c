// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Axcient Software Inc.
 */

// kernel_version < 6.6

#include "includes.h"
MODULE_LICENSE("GPL");

static inline void dummy(void){
    struct super_block *sb;
	if (sb->s_op->freeze_super)
		sb->s_op->freeze_super(sb);
}
