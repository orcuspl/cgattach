#ifndef CGROUPS_H
#define CGROUPS_H

#include "funcs.h"

#define TPF_FUNC(NAME, TEST, FUNC) struct traverse_proc_func tpf_##NAME = {(char (*)(char*, void*))TEST, (char (*)(void*))FUNC};

#define TPF_TEST(NAME, FORMAT, VAR) \
char tpf_##NAME##_test(char* line, struct tpf_data_t* data) { \
return (sscanf(line, FORMAT, VAR) == 1); \
} 

#define TPF_TEST_FUNC(NAME, FORMAT, VAR) \
TPF_TEST(NAME, FORMAT, VAR) \
TPF_FUNC(NAME, &tpf_##NAME##_test, NULL)

struct cgroup* get_or_create(const int);
struct cgroup* get(const int);
int attach(const int, const short, const char*);
int add_memory(unsigned, long long);

struct tpf_data_t {
	short pid;
	short ppid;
	unsigned uid;
	char pname[30];
	struct llist* pids;
};

char tpf_pid_test(char*, struct tpf_data_t*);
char tpf_ppid_test(char*, struct tpf_data_t*);

int memory(int, long long, int); 
int cpus(int, struct llist*, int);
int shares(int, int, int); 

#endif
