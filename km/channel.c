#include "channel.h"


static int channel_show(struct seq_file *m, void *v) {
	seq_printf(m, "%s\n", "hello world!");
	return 0;
}

static int channel_open(struct inode *inode, struct file *file) {
	return single_open(file, channel_show, NULL);
}