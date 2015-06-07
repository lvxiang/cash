/**
 * The kernel module of cash, create a /proc virtual file 
 * system for each candidate container
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>

#include "channel.h"

/* Defines the license for this LKM */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kernel module for cash");
MODULE_AUTHOR("lx");


// static pid_t selected_pid;
static struct proc_dir_entry *root;
static struct proc_dir_entry *channel;

static const struct file_operations channel_ops = {
	.owner = THIS_MODULE,
	.open = channel_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* Init function called on module entry */
int my_module_init( void )
{
	printk(KERN_INFO "kernel module installed.\n");
	// create root folder
	root = proc_mkdir("containers", NULL);
	// channel = proc_create("channel", 0, root, &channel_ops);
  	return 0;
}


/* Cleanup function called on module exit */
void my_module_cleanup( void )
{
  printk(KERN_INFO "my_module_cleanup called.  Module is now unloaded.\n");
  return;
}
/* Declare entry and exit functions */
module_init( my_module_init );
module_exit( my_module_cleanup );