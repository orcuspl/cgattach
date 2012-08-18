#ifndef PIDLIST_H
#define PIDLIST_H

struct llist {
	long* pids;
	short n;
	short max;
};
struct llist* llist_new();
void llist_add(struct llist*, const long);
char llist_test(const struct llist*, const long);
void llist_free(struct llist*);
#endif
