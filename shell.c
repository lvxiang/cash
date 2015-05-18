#define _GNU_SOURCE
#include <sched.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define _NS_TYPE_ALL 0
#define READLINK(ns,fd,ret,path,dest,len) ret = readlink((path),(dest),(len));\
                                    dest[ret] = '\0';\
                                    ns.fd = getNamespaceId(dest);

#define READLINK_FROM(path,pid,buf,ns,fd,ret,dest,len) sprintf(buf, path, pid);\
                                    READLINK(ns,fd,ret,buf,dest,len);

#define SAME_NS(ns1,ns2) ns1->ipc == ns2->ipc && \
                         ns1->mnt == ns2->mnt && \
                         ns1->pid == ns2->pid && \
                         ns1->uts == ns2->uts && \
                         ns1->net == ns2->net

struct process {
	int pid;
	struct process *next_proc;
};

struct namespace {
    unsigned long ipc;
    unsigned long mnt;
    unsigned long pid;
    unsigned long uts;
    unsigned long net;
    struct namespace *next_ns;
    struct process *proc_list;
} root_namespace;

unsigned long getNamespaceId(const char *link);

int main() {

    // check if program run in root mode
    if(geteuid() != 0) {
        printf("The program must run as root!\n");
        return 1;
    }

    // get namespaces of init process
    int  ret; 
    char buf[32];
    READLINK(root_namespace, ipc, ret, "/proc/1/ns/ipc", buf, 32);
    READLINK(root_namespace, mnt, ret, "/proc/1/ns/mnt", buf, 32);
    READLINK(root_namespace, pid, ret, "/proc/1/ns/pid", buf, 32);
    READLINK(root_namespace, uts, ret, "/proc/1/ns/uts", buf, 32);
    READLINK(root_namespace, net, ret, "/proc/1/ns/net", buf, 32);
    root_namespace.proc_list = (struct process *)(&({1, NULL}));

    // init number regular expression
    regex_t num_regex;
    int ret = regcomp(&num_regex, "\\d\\+", 0);
    if(ret != 0) {
        printf("regex initialize error!\n");
        regfree(&num_regex);
        return -1;
    }

	// check the /proc directory and look for namespaces
	// other than the original namespaces which the proc
	// with PID 1 belongs to.
    DIR  *d;
    struct dirent *dir;
    char path[32];
    struct namespace *tmp_ns = malloc(sizeof(*tmp_ns));

    d = opendir("/proc");
    if (d) {
    	// the files under /proc already ordered in ascending order
    	while((dir = readdir(d)) != NULL) {
    		char *dname = dir->d_name;
            if(regexec(&num_regex, dname, 0, NULL, 0) != 0) {
            	// process folder
                if(strlen(dname) != 1 || dname[0] != '1') {
                    // not init process
                    READLINK_FROM("/proc/%s/ns/ipc",dname,path,tmp_namespace,ipc,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/mnt",dname,path,tmp_namespace,mnt,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/pid",dname,path,tmp_namespace,pid,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/uts",dname,path,tmp_namespace,uts,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/net",dname,path,tmp_namespace,net,ret,buf,32);
                    struct *cmp_ns = &root_namespace;
                    while(!(SAME_NS(cmp_ns, tmp_ns))) {
                        if(cmp_ns->next_ns == NULL) {
                            // found a new namespace | container candidate
                            cmp_ns->next_ns = tmp_ns;
                            tmp_ns->proc_list = (struct process *)(&({atoi(dname), NULL}));
                            tmp_ns = malloc(sizeof(*tmp_ns));
                        } else {
                            cmp_ns = cmp_ns->next_ns;
                        }
                    }
                    // append current process to the namespace structure
                    struct process proc = {atoi(dname), NULL};
                    proc.next_proc = cmp_ns->proc_list;
                    cmp_ns->proc_list = &proc;
                }
    		}
    	} 
    	closedir(d);
    }
    regfree(&num_regex);

    // prompt user to choose a container with specific namespace
    
    
    // clone a process and set to the chosen namespace
    

    // now do whatever is possible in a shell!

    return 0;
}

unsigned long getNamespaceId(const char *link) {
	int i = 0;
	char buf[16];
	char *p = buf;
	while(link[i++] != '[');
	while(link[i] != ']') {
		*p++ = link[i++];
	}
	*p = '\0';
	return atol(buf);
}