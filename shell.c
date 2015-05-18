#define _GNU_SOURCE
#include <sched.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>

#define _NS_TYPE_ALL 0
#define READLINK(ret,path,dest,len) ret = readlink((path),(dest),(len));\
                                    dest[ret] = '\0';

struct namespace {
	unsigned long ipc;
	unsigned long mnt;
	unsigned long pid;
	unsigned long uts;
	unsigned long net;
	struct namespace *next_ns;

} root_namespace;

struct process {
	int pid;
	struct process *next_proc;
};

unsigned long getNamespaceId(const char *link);

int main() {

    regex_t num_regex;
    int ret = regcomp(&num_regex, "\\d\\+", 0);
    if(ret != 0) {
    	printf("regex initialize error!\n");
    	regfree(&num_regex);
    	return -1;
    }

    // get namespaces of init process
    char ipc[32];
    char mnt[32];
    char pid[32];
    char uts[32];
    char net[32];
    READLINK(ret, "/proc/1/ns/ipc", ipc, 32);
    READLINK(ret, "/proc/1/ns/mnt", mnt, 32);
    READLINK(ret, "/proc/1/ns/pid", pid, 32);
    READLINK(ret, "/proc/1/ns/uts", uts, 32);
    READLINK(ret, "/proc/1/ns/net", net, 32);
    root_namespace.ipc = getNamespaceId(ipc);
    root_namespace.mnt = getNamespaceId(mnt);
    root_namespace.pid = getNamespaceId(pid);
    root_namespace.uts = getNamespaceId(uts);
    root_namespace.net = getNamespaceId(net);

	// check the /proc directory and look for namespaces
	// other than the original namespaces which the proc
	// with PID 1 belongs to.
    DIR  *d;
    struct dirent *dir;
    d = opendir("/proc");
    if (d) {
    	// the files under /proc already ordered in ascending order
    	while((dir = readdir(d)) != NULL) {
    		char *dname = dir->d_name;
            if(regexec(&num_regex, dname, 0, NULL, 0) != 0) {
            	
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