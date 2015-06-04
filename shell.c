#define _GNU_SOURCE
#include <sched.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#define _NS_TYPE_ALL 0
#define READLINK(ns,fd,ret,path,dest,len) ret = readlink((path),(dest),(len));\
                                    dest[ret] = '\0';\
                                    (ns).fd = getNamespaceId(dest);

#define READLINK_FROM(path,pid,buf,ns,fd,ret,dest,len) sprintf((buf), (path), (pid));\
                                    READLINK(ns,fd,ret,buf,dest,len);

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
    int cid;
} root_namespace;

enum NAMESPACE_TYPE {
    NS_DEFAULT, NS_CUSTOM
};

/***
 * parse symbolic link and get the inode id as corresponding namespace id
 */ 
unsigned long getNamespaceId(const char *);

/***
 * print a container info
 */
void printContainer(const struct namespace*, const enum NAMESPACE_TYPE);

/***
 * print field in a namespace struct
 */
void printNamespace(const struct namespace*);

/***
 * count processes in a namespace
 */
int countProcesses(const struct namespace*);

/***
 * Check if two namespaces are exatly the same
 */
int sameNs(const struct namespace *, const struct namespace *);

/***
 * set namespace of the calling thread
 */
void setNs(const char *ns, const long pid);

static int cid = 1;   // container id counter

int main() {

    // check if program run in root mode
    if(geteuid() != 0) {
        printf("The program must run as root!\n");
        return 1;
    }

    // get namespaces of init process
    int  ret;                           // tmp var for int return values
    char buf[32];                       // tmp buffer for chars
    struct process proc = {1, NULL};    // tmp process struct
    READLINK(root_namespace, ipc, ret, "/proc/1/ns/ipc", buf, 32);
    READLINK(root_namespace, mnt, ret, "/proc/1/ns/mnt", buf, 32);
    READLINK(root_namespace, pid, ret, "/proc/1/ns/pid", buf, 32);
    READLINK(root_namespace, uts, ret, "/proc/1/ns/uts", buf, 32);
    READLINK(root_namespace, net, ret, "/proc/1/ns/net", buf, 32);
    root_namespace.proc_list = &proc;
    root_namespace.cid       = cid ++;
    // printNamespace(&root_namespace);

    // init number regular expression
    regex_t num_regex;
    ret = regcomp(&num_regex, "\\d\\+", 0);
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
                if(!(strlen(dname) == 1 && dname[0] == '1')) {
                    // not init process
                    READLINK_FROM("/proc/%s/ns/ipc",dname,path,*tmp_ns,ipc,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/mnt",dname,path,*tmp_ns,mnt,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/pid",dname,path,*tmp_ns,pid,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/uts",dname,path,*tmp_ns,uts,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/net",dname,path,*tmp_ns,net,ret,buf,32);

                    struct namespace *cmp_ns = &root_namespace;
                    printNamespace(cmp_ns);
                    while((cmp_ns->pid) != (tmp_ns->pid) ||
                          (cmp_ns->uts) != (tmp_ns->uts) ||
                          (cmp_ns->net) != (tmp_ns->net) ||
                          (cmp_ns->ipc) != (tmp_ns->ipc) ||
                          (cmp_ns->mnt) != (tmp_ns->mnt)) {
                        if(cmp_ns->next_ns == NULL) {
                            // found a new namespace | container candidate
                            struct process proc = {atoi(dname), NULL};
                            tmp_ns->proc_list = &proc;
                            tmp_ns->cid = cid ++;
                            cmp_ns->next_ns = tmp_ns;
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
    printf("possible containers detected:\n");
    
    struct namespace *p = &root_namespace;
    while(p != NULL) {
        if(p == &root_namespace) {
            printContainer(p, NS_DEFAULT);
        } else {
            printContainer(p, NS_CUSTOM);
        }
        p = p->next_ns;
    }

    while(1) {
        printf("Please choose a container, enter the id\n");
        scanf("%s", buf);
        int id = atoi(buf);
        if(id == 1) {
            printf("You cannot choose the default container!\n");
        } else {
            int found = 0;
            p = root_namespace.next_ns;
            while(p != NULL) {
                if(p->cid == id) {
                    found = 1;
                    break;
                }
                p = p->next_ns;
            }
            if(found) {
                break;
            }
        }
    }

    // clone a process and set to the chosen namespace
    pid_t cpid = fork();
    if(fpid < 0) {
    	printf("error creating shell process");
    } else if(fpid == 0) {
        // in child process
 	setNs("ipc", p->proc_list->pid);
	setNs("mnt", p->proc_list->pid);
	setNs("pid", p->proc_list->pid);
	setNs("net", p->proc_list->pid);
	setNs("uts", p->proc_list->pid);
	
        // TODO start shell and play with some commands
			
    } else {
        // in parent process
    }

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

void printContainer(const struct namespace* ns, const enum NAMESPACE_TYPE type) {
    printf("-------------------------------------\n");
    printf("|   Container ID: %3d             |\n", ns->cid);
    switch(type) {
        case NS_DEFAULT:
            printf("|   Container Type: DEFAULT     |\n");
            break;
        case NS_CUSTOM:
            printf("|   Container Type: CUSTOM      |\n");
            break;
    }
    printf("|   pid ns: %ld   |\n", ns->pid);
    printf("|   mnt ns: %ld   |\n", ns->mnt);
    printf("|   ipc ns: %ld   |\n", ns->ipc);
    printf("|   uts ns: %ld   |\n", ns->uts);
    printf("|   net ns: %ld   |\n", ns->net);
    printf("| num processes: %d |\n", countProcesses(ns));
    printf("-------------------------------------\n\n");
}

int countProcesses(const struct namespace *ns) {
    int count = 0;
    struct process *p = ns->proc_list;
    while(p != NULL) {
        count ++;
        p = p->next_proc;
    }
    return count;
}

void printNamespace(const struct namespace *ns) {
    printf("pid: %ld\n", ns->pid);
    printf("uts: %ld\n", ns->uts);
    printf("mnt: %ld\n", ns->mnt);
    printf("ipc: %ld\n", ns->ipc);
    printf("net: %ld\n", ns->net);
}

int sameNs(const struct namespace *ns1, const struct namespace *ns2) {
    // printNamespace(ns1);
    // printNamespace(ns2);
    if(ns1->ipc == ns2->ipc && ns1->pid == ns2->pid &&
       ns1->uts == ns2->uts && ns1->net == ns2->net &&
       ns1->mnt == ns2->mnt) return 1;
    return 0;
}

void setNs(const char *ns, const long pid) {
    char path[32];
    sprintf(path, "/proc/%ld/ns/%s", pid, ns);
    int fd = open(path, O_RDONLY);
    setns(fd, 0);
    close(fd);
    free(path);
}
