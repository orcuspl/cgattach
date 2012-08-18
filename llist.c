#include <syslog.h>
#include <stdlib.h>

#include "llist.h"

struct llist* llist_new() {
	struct llist* pids = malloc(sizeof(struct llist));
	if(pids == NULL) {
		syslog(LOG_CRIT, "No memory for llist.");
		exit(6);
	}
	pids->pids = malloc(sizeof(short) * 4);
	if(pids->pids == NULL) {
		syslog(LOG_CRIT, "No memory for llists llist.");
		exit(7);
	}
	pids->n = 0;
	pids->max = 4;
	return pids;
}

void llist_add(struct llist* pids, const long pid) {
	if(pids->n >= pids->max) {
		pids->max <<= 1;
		if(pids->max < 0) {
			syslog(LOG_CRIT, "Llist max overflow.");
			exit(9);
		}
		pids->pids = realloc(pids, pids->max * sizeof(short));
		if(pids->pids == NULL) {
			syslog(LOG_CRIT, "No memory for llist(reallloc).");
			exit(8);
		}
	}
	pids->pids[pids->n++] = pid;
}

char llist_test(const struct llist* pids, const long pid) {
	short i;
	for(i = 0; i < pids->n; ++i) {
		if(pids->pids[i] == pid) {
			return 1;
		}
	}
	return 0;
}

void llist_free(struct llist* pids) {
	free(pids->pids);
	free(pids);
}
