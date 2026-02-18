// SPDX-License-Identifier: GPL-2.0-only

/*
 * Kernel >= 6.17: submit_bio_noacct() returns void instead of a value.
 */

#include "includes.h"

MODULE_LICENSE("GPL");

static int __init dummy_init(void){
	void (*fn)(struct bio *) = submit_bio_noacct;
	(void)fn;
	return 0;
}

static void __exit dummy_exit(void){}

module_init(dummy_init);
module_exit(dummy_exit);
