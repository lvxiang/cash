#define _GNU_SOURCE
#include <sched.h>

#define _NS_TYPE_ALL 0

int main() {
        
	int result = setns(, _NS_TYPE_ALL);
}
