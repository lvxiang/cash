#ifndef _CASH_CHANNEL_H
#define _CASH_CHANNEL_H

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>

static int channel_show(struct seq_file *m, void *v);

static int channel_open(struct inode *inode, struct file *file);

#endif