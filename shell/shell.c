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
#include <sys/time.h>
#include <errno.h>

#include "util.h"

#define _NS_TYPE_ALL 0
#define READLINK(ns,fd,ret,path,dest,len) ret = readlink((path),(dest),(len));\
                                    if(ret>0){dest[ret] = '\0';(ns).fd = getNamespaceId(dest);}

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
    unsigned long usr;
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
 * print detailed container info
 */
void printContainerInfo(const struct namespace *);

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
<<<<<<< HEAD
 * List all containers found
 */
void listContainers(struct namespace *);

/***
 * free mem used by a specific container
 */
void freeContainer(struct namespace *);

/***
 * set namespace of the calling thread
 */
int setNs(const char *ns, const long pid, int nstype);

static int cid = 1;   // container id counter

int main() {

    // check if program run in root mode
    if(geteuid() != 0) {
        printf("The program must run as root!\n");
        return 1;
    }

    // init
    setbuf(stdout, NULL);

PARSE_CONTAINERS:
    printf("parsing namespaces...\n");
    // get namespaces of init process
    int  ret;                           // tmp var for int return values
    char buf[32];                       // tmp buffer for chars
    READLINK(root_namespace, ipc, ret, "/proc/1/ns/ipc", buf, 32);
    READLINK(root_namespace, mnt, ret, "/proc/1/ns/mnt", buf, 32);
    READLINK(root_namespace, pid, ret, "/proc/1/ns/pid", buf, 32);
    READLINK(root_namespace, uts, ret, "/proc/1/ns/uts", buf, 32);
    READLINK(root_namespace, net, ret, "/proc/1/ns/net", buf, 32);
    struct process *proc = calloc(1, sizeof(*proc));
    proc->pid = 1;
    root_namespace.proc_list = proc;
    root_namespace.cid       = cid ++;

    // init number regular expression
    regex_t num_regex;
    ret = regcomp(&num_regex, "[123456789][0123456789]*", REG_EXTENDED);
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
    struct namespace *tmp_ns = calloc(1, sizeof(*tmp_ns));

    d = opendir("/proc");
    if (d) {
    	// the files under /proc already ordered in ascending order
    	while((dir = readdir(d)) != NULL) {
    		char *dname = dir->d_name;
            if(regexec(&num_regex, dname, 0, NULL, 0) == 0) {
                // process folder
                if(!(strlen(dname) == 1 && dname[0] == '1')) {
                    // printf("parsing process %s\n", dname);
                    // not init process
                    READLINK_FROM("/proc/%s/ns/ipc",dname,path,*tmp_ns,ipc,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/mnt",dname,path,*tmp_ns,mnt,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/pid",dname,path,*tmp_ns,pid,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/uts",dname,path,*tmp_ns,uts,ret,buf,32);
                    READLINK_FROM("/proc/%s/ns/net",dname,path,*tmp_ns,net,ret,buf,32);
		    // READLING_FROM("/proc/%s/ns/usr",dname,path,*tmp_ns,usr,ret,buf,32);

                    struct namespace *cmp_ns = &root_namespace;
                    while((cmp_ns->pid != tmp_ns->pid) ||
                          (cmp_ns->uts != tmp_ns->uts) ||
                          (cmp_ns->net != tmp_ns->net) ||
                          (cmp_ns->ipc != tmp_ns->ipc) ||
                          (cmp_ns->mnt != tmp_ns->mnt)) {
                        
                        if(cmp_ns->next_ns == NULL) {
                            struct process *proc = calloc(1, sizeof(*proc));
                            proc->pid = atoi(dname);
                            tmp_ns->proc_list = proc;
                            tmp_ns->cid = cid ++;
                            cmp_ns->next_ns = tmp_ns;
                            cmp_ns = tmp_ns;
                            tmp_ns = calloc(1, sizeof(*tmp_ns));
                            break;
                        } else {
                            cmp_ns = cmp_ns->next_ns;
                        }
                    }

                    // append current process to the namespace structure
                    // note that processes are inserted reversely
                    struct process *proc = calloc(1, sizeof(*proc));
                    proc->pid = atoi(dname);
                    proc->next_proc = cmp_ns->proc_list;
                    cmp_ns->proc_list = proc;
                }
    		}
    	} 
    	closedir(d);
    }
    regfree(&num_regex);

    // prompt user to choose a container with specific namespace
    printf("done parsing containers.\n");
    
    while(1) {
        printf("Type 'ent <cid>' to enter a container, or type help for more options\n");
        printf(">>");
	char c;
	int i = 0;
	while((c = getchar()) != '\n'&& c != EOF && i < 31) {
	    buf[i] = c;
	    i ++;
	}
	buf[i] = '\0';

        if(strcmp(buf, "help") == 0) {
            printf("%6s  enter a specific container\n", "ent");
            printf("%6s  show detailed information of a container\n", "info");
            printf("%6s  list all containers found\n", "list");
            printf("%6s  refresh current container list\n", "ref");
            printf("%6s  to exit\n", "exit");
        } else if(strcmp(buf, "list") == 0) {
            listContainers(&root_namespace);
        } else if(strstr(buf, "info") != NULL) {
            int id = nextInt(buf);
            if(id > 0) {
                struct namespace *p = &root_namespace;
                SEARCH_LIST(p, cid, id, next_ns);
                if(p != NULL) {
                    printContainerInfo(p);
                    continue;
                }
            }
            printf("invalid container id: %d\n", id);
        } else if(strcmp(buf, "ref") == 0) {
            // clear stuff first
            struct namespace *ns  = &root_namespace;
            struct namespace *tns = NULL;
            while(ns != NULL) {
                tns = ns->next_ns;
                freeContainer(ns);
                ns = tns;
            }
            root_namespace = *((struct namespace *)calloc(1, sizeof(struct namespace)));
            goto PARSE_CONTAINERS;
        } else if(strcmp("exit", buf) == 0) {
            printf("bye\n");
            return 0;
        } else if(strstr(buf, "ent") != NULL){
            // should be a number for container id
            int id = nextInt(buf);
            if(id == 1) {
                printf("You cannot choose the default container!\n");
            } else {
                struct namespace *p = root_namespace.next_ns;
                SEARCH_LIST(p,cid,id,next_ns);
                if(p != NULL) {
                    printf("entering container %d\n", p->cid);
		    
		    pid_t fpid = fork();
    		    if(fpid < 0) {
			perror("fork");
    			// printf("error creating shell process");
    		    } else if(fpid == 0) {
			
			printf("in child process\n");
	
			// in child process
 		 	// setNs("ipc", p->proc_list->pid);
			if(//setNs("mnt", p->proc_list->pid, CLONE_NEWNS) == 0 &&
                           setNs("pid", p->proc_list->pid, CLONE_NEWPID) == 0 &&
                           setNs("net", p->proc_list->pid, CLONE_NEWNET) == 0 && 
                           setNs("uts", p->proc_list->pid, CLONE_NEWUTS) == 0 &&
                           setNs("mnt", p->proc_list->pid, CLONE_NEWNS) == 0) { 
			    printf("entered target namespace.\n");
			    printf(">>");
		   	    execl("/bin/bash", "", (char *) NULL);	
			} else {
			    printf("failed to enter namespace\n");
			    switch(errno) {
				case EBADF: printf("invalid file descriptor\n");break;
				case EINVAL: printf("fd and type not match\n");break;
				default: printf("errno: %d\n", errno);
			    }	
			}
		    } else {
		    	printf("in parent process\n");
		    	wait(); // wait for child to terminate
		    	printf("child exit\n");
		    }
		  
                } else {
                    printf("no matching container with specified id found!\n");
                }
            }
        } else if(strlen(buf) == 0) {
	    printf(">>");
	}
	else {
            printf("unknown command '%s'\n", buf);
        }
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
    printf("-------------------------------\n");
    printf("|   Container ID: %3d         |\n", ns->cid);
    switch(type) {
        case NS_DEFAULT:
            printf("|   Container Type: DEFAULT   |\n");
            break;
        case NS_CUSTOM:
            printf("|   Container Type: CUSTOM    |\n");
            break;
    }
    printf("|   ipc ns: %14ld    |\n", ns->ipc);
    printf("|   mnt ns: %14ld    |\n", ns->mnt);
    printf("|   net ns: %14ld    |\n", ns->net);
    printf("|   pid ns: %14ld    |\n", ns->pid);
    printf("|   uts ns: %14ld    |\n", ns->uts);
    printf("|   num processes: %7d    |\n", countProcesses(ns));
    printf("-------------------------------\n\n");
}

void printContainerInfo(const struct namespace *ns) {
    printf("Container ID: %3d\n", ns->cid);
    printf("ipc ns: %14ld\n", ns->ipc);
    printf("mnt ns: %14ld\n", ns->mnt);
    printf("net ns: %14ld\n", ns->net);
    printf("pid ns: %14ld\n", ns->pid);
    printf("uts ns: %14ld\n", ns->uts);
    printf("num processes: %7d\n", countProcesses(ns));
    struct process *p = ns->proc_list;
    while(p->next_proc != NULL) {
        p = p->next_proc;
    }
    printf("root process id: %d\n", p->pid);
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

void listContainers(struct namespace *ns) {
    struct namespace *p = ns;
    while(p != NULL) {
        if(p == &root_namespace) {
            printContainer(p, NS_DEFAULT);
        } else {
            printContainer(p, NS_CUSTOM);
        }
        p = p->next_ns;
    }
}

void freeContainer(struct namespace *ns) {
    struct process *pr = NULL;
    while(ns->proc_list != NULL) {
        pr = ns->proc_list;
        ns->proc_list = ns->proc_list->next_proc;
        free(pr);
    }
    free(ns);
}

int setNs(const char *ns, const long pid, int nstype) {
    char path[32];
    sprintf(path, "/proc/%ld/ns/%s", pid, ns);
    printf("setting namespace to %s\n", path);
    int fd = open(path, O_RDONLY);
    if(fd <= 0) {
	perror("open");
    }
    int ret = setns(fd, nstype);
    close(fd);
    return ret;
}
