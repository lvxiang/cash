/***
 * util functions
 */
#ifndef _CASH_UTIL_H
#define _CASH_UTIL_H

/***
 * search for a list node with specific field equal the specified target,
 * continue searching till the last list node
 */
#define SEARCH_LIST(p,fd,target,next) while((p) != NULL) {\
									  	if((p)->fd == (target)) break;\
									  	p = (p)->next;}

/***
 * Find the first integer from a string
 */
int nextInt(char *);

#endif