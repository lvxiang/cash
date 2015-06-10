/**
 * The kernel module of cash, create a /proc virtual file 
 * system for each candidate container
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/cgroup.h>
#include <linux/string.h>
#include <asm/uaccess.h>

// #include "channel.h"

/* Defines the license for this LKM */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kernel module for cash");
MODULE_AUTHOR("lx");


static pid_t selected_pid;
static struct proc_dir_entry *root;
static struct proc_dir_entry *channel;

static int channel_show(struct seq_file *m, void *v) {
	seq_printf(m, "%d\n", selected_pid);
	return 0;
}

static int channel_open(struct inode *inode, struct file *file) {
	return single_open(file, channel_show, NULL);
}

static ssize_t channel_write(struct file *file, const char __user *buff, size_t len, loff_t *data) {
	
	struct task_struct *task;
	struct css_set *cgroups;
	struct cgroup_subsys_state *css_ptr;
	struct cgroup *cgroup;
	struct cgroup_subsys *subsys;

	char *tmp;
	int css_length;
	int i;

	// this is seq write, but only accept input less than PAGE_SIZE
	if(len > PAGE_SIZE) {
		return -EFAULT;
	}
	tmp = vmalloc(len + 1);
	
	if(tmp == NULL)
		return -ENOMEM;

	if(copy_from_user(tmp, buff, len)) {
		return -EFAULT;
	}
	tmp[len] = '\0';
	kstrtoint(tmp, 10, &selected_pid);
	vfree(tmp);

	// start a thread to deal with the process id
	for_each_process(task) {
		if(task->pid == selected_pid) {
			// get css_set from task struct
			// note that the css_field is protected by rcu lock
			// use rcu_read_lock and rcu_read_unlock pairs to create critical section
			rcu_read_lock();
			cgroups = rcu_dereference(task->cgroups);
			css_length = sizeof(cgroups->subsys) / sizeof(cgroups->subsys[0]);

			// get pointer to each cgroup subsystem state object this process is attached to
			for(i = 0; i < css_length; i ++) {
				css_ptr = cgroups->subsys[i];
				if(css_ptr != NULL) {
					cgroup  = css_ptr->cgroup; // public and immutable, access directly
					subsys  = css_ptr->ss;     // public and immutable, access directly
					if(subsys != NULL) {
						printk(KERN_INFO "subsys name %s\n", subsys->name);
					}

					if(strcmp(subsys->name, "cpuset") == 0) {
						// cpuset cgroup config
						
					} else if(strcmp(subsys->name, "memory") == 0) {
						// memory cgroup config

					}
				}
			}

			rcu_read_unlock();
			printk(KERN_INFO "%s\n", task->comm);
			break;
		}
	}

	return len;
}

static const struct file_operations channel_ops = {
	.owner   = THIS_MODULE,
	.open    = channel_open,
	.read    = seq_read,
	.write   = channel_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

/* Init function called on module entry */
int my_module_init( void )
{
	printk(KERN_INFO "kernel module installed.\n");
	// create root folder
	root = proc_mkdir("containers", NULL);
	channel = proc_create("channel", 0660, root, &channel_ops);
  	return 0;
}

/* Cleanup function called on module exit */
void my_module_cleanup( void )
{
	proc_remove(channel);
	proc_remove(root);
	printk(KERN_INFO "my_module_cleanup called.  Module is now unloaded.\n");
  	return;
}

/* Declare entry and exit functions */
module_init( my_module_init );
module_exit( my_module_cleanup );