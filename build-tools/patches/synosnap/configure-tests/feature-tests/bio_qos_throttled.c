// SPDX-License-Identifier: GPL-2.0-only

/*
 * Kernel >= 6.17: BIO_THROTTLED renamed to BIO_QOS_THROTTLED.
 */

#include "includes.h"

MODULE_LICENSE("GPL");

static int __init dummy_init(void){
	struct bio bio = {};
	bio_set_flag(&bio, BIO_QOS_THROTTLED);
	return 0;
}

static void __exit dummy_exit(void){}

module_init(dummy_init);
module_exit(dummy_exit);
