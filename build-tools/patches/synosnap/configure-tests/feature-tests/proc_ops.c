// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2021 Datto Inc.
 */

#include "includes.h"

MODULE_LICENSE("GPL");

static int __init dummy_init(void){
	static const struct proc_ops pops = {};
	struct proc_dir_entry *e = proc_create("dattobd_test", 0, NULL, &pops);
	if (e) proc_remove(e);
	return 0;
}

static void __exit dummy_exit(void){}

module_init(dummy_init);
module_exit(dummy_exit);
