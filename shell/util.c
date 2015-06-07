#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

int nextInt(char *buf) {
	if(buf != NULL) {
		int i = 0;
		int len = strlen(buf);
		while(i < len && (buf[i] < '0' || buf[i] > '9')) i ++;
		int j = i + 1;
		while(j < len && (buf[j] >= '0' && buf[j] <= '9')) j ++;
		char swap = buf[j];
		buf[j] = '\0';
		int ret = atoi(buf + i);
		buf[j] = swap;
		return ret;
	}
	return 0;
}