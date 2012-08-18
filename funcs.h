#ifndef FUNCS_H
#define FUNCS_H

#include "llist.h"

#define CG_NOACT 0
#define CG_SET 1
#define CG_ADD 2
#define CG_REM 3

struct config_t {
	int daemon;
	char* syslog_name;
	int facility;
	int debug;
	int action;
	int uid;
	int64_t mem;
	struct llist* cpus;
	int shares;
	int delay;
};

struct config_t set_config(int, char* const*);
void init(struct config_t*);
void loop();
void daemonize();

struct traverse_proc_func {
	char (*test)(char* , void*);
	char (*func)(void*);
};
void traverse_proc(struct traverse_proc_func**, struct llist*, void*);
#endif
