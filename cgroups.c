#include <libcgroup.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>

#include "cgroups.h"
#include "funcs.h"
#include "llist.h"

char* uid_to_path(const int uid) {
	int err = 0;
	char* path = malloc(sizeof(char) * 50);
	if(path == NULL) {
		syslog(LOG_CRIT, "No memory(50 bytes!) for path.");
		exit(5);
	}
	err = (uid > 0 ? sprintf(path, "users/%u", uid) : sprintf(path, "users"));
	if(err <= 0) {
		syslog(LOG_ERR, "Cannot convert uid(%u) to string.", uid);
		free(path);
		exit(5);
	}
	return path;
}

void zeroize(struct cgroup* cg, const int uid) {
	struct cgroup_controller* cgc = NULL;
	int64_t limit;	
	int err;
	cgc = cgroup_get_controller(cg, "memory");
	if(cgc == NULL) {
		syslog(LOG_ERR, "Cannot get cgroup %d memory controller.", uid);
	} else {
		err = cgroup_set_value_int64(cgc, "memory.limit_in_bytes", 0);
		if(err != 0) {
			syslog(LOG_ERR, "Cannot modify cgroup %d memory limit(%d: %s).", uid, err, cgroup_strerror(err));
		}
	}
	cgc = cgroup_get_controller(cg, "cpuset");
	if(cgc == NULL) {
		syslog(LOG_ERR, "Cannot get cgroup %d cpuset controller.", uid);
	} else {
		err = cgroup_set_value_string(cgc, "cpuset.cpus", "");
		if(err != 0) {
			syslog(LOG_ERR, "Cannot modify cgroup %d allowed cpus(%d: %s).", uid, err, cgroup_strerror(err));
		}
	}
	cgc = cgroup_get_controller(cg, "cpu");
	if(cgc == NULL) {
		syslog(LOG_ERR, "Cannot get cgroup %d cpuset controller.", uid);
	} else {
		err = cgroup_set_value_int64(cgc, "cpu.shares", 1024);
		if(err != 0) {
			syslog(LOG_ERR, "Cannot modify cgroup %d cpu shares(%d: %s).", uid, err, cgroup_strerror(err));
		}
	}
}

struct cgroup* get_or_create(const int uid) {
	int err;
	char* path = uid_to_path(uid);
	struct cgroup* cg = cgroup_new_cgroup(path);
	if(cg == NULL) {
		syslog(LOG_ERR, "Cannot create local cgorup structure for '%d'.", uid);
		free(path);
		return NULL;
	}
	err = cgroup_get_cgroup(cg);
	if(err != 0) {
		struct cgroup* cg2 = cgroup_new_cgroup(path);
		free(path);
		u_int64_t limit = 0;
		syslog(LOG_INFO, "Cannot get cgroup %d data from cgroup fs(%d: %s). Creating from parent.", uid, err, cgroup_strerror(err));
		err = cgroup_create_cgroup_from_parent(cg, 0);
		syslog(LOG_DEBUG, "Cgroup %d created. Parent values cloned(%d).", uid, err);
		err = cgroup_get_cgroup(cg2);
		if(err != 0) {
			syslog(LOG_ERR, "Cannot get just creted cgroup %d data from kernel(%d: %s).", uid, err, cgroup_strerror(err));
			cgroup_free_controllers(cg);
			cgroup_free(&cg);
			return NULL;
		}
		cgroup_free_controllers(cg2);
		cgroup_free(&cg2);
		if(uid > 1000) {
			zeroize(cg, uid);
		}
	} else {
		free(path);
	}
	return cg;
}

struct cgroup* get(const int uid) {
	int err = 0;
	char* path = uid_to_path(uid);	
	struct cgroup* cg = cgroup_new_cgroup(path);
	free(path);
	if(cg == NULL) {
		syslog(LOG_ERR, "Cannot create local cgorup structure for '%d'.", uid);
		return NULL;
	}
	err = cgroup_get_cgroup(cg);
	if(err != 0) {
		syslog(LOG_ERR, "Cannot get cgroup %d data from cgroup fs(%d: %s).", uid, err, cgroup_strerror(err));
		cgroup_free_controllers(cg);
		cgroup_free(&cg);
		return NULL;
	}
	return cg;
}

int attach_pid(const unsigned uid, const short pid, const char* pname) {
	int err = 0;
	struct cgroup* cg;
	const char* controllers[] = {"memory", "cpuset", NULL};
	char* path;
	path = uid_to_path(uid);
	err = cgroup_change_cgroup_path(path, pid, controllers);
	free(path);	
	cg = get(uid);
	if(cg == NULL) {
		syslog(LOG_INFO, "No cgroup %d for process %s[%hd]. Sending SIGKILL.", uid, pname, pid);
 		kill(pid, SIGKILL); 
 		return -2;
	}
	cgroup_free_controllers(cg);
	cgroup_free(&cg);
	
	if(err != 0) {
		syslog(LOG_ERR, "Cannot attach process %s[%hd] to cgroup %d(%d: %s).", pname, pid, uid, err, cgroup_strerror(err));
		return -1;
	}
	syslog(LOG_DEBUG, "Process %s[%d] attached to cgroup %d.", pname, pid, uid);
	return 0;
}

TPF_TEST_FUNC(pname, "Name:%*[ \t]%30s", data->pname)
TPF_TEST_FUNC(pid, "Pid:%*[ \t]%hd", &(data->pid))
TPF_TEST_FUNC(ppid, "PPid:%*[ \t]%hd", &(data->ppid))
TPF_TEST(uid, "Uid:%*[ \t]%u", &(data->uid))

char tpf_attach(struct tpf_data_t* data) {
	if(data->uid > 1000) {
		attach_pid(data->uid, data->pid, data->pname);
		llist_add(data->pids, data->pid);
		return 1;
	}
	return 0;
}

TPF_FUNC(uid, &tpf_uid_test, &tpf_attach)
struct traverse_proc_func* tpf_table[] = {&tpf_pname, &tpf_pid, &tpf_ppid, &tpf_uid, NULL};

void attach_tree(const short pid) {
	struct tpf_data_t tpf_data;
	tpf_data.pids = llist_new();
	llist_add(tpf_data.pids, pid);

	traverse_proc(tpf_table, tpf_data.pids, &tpf_data);

	llist_free(tpf_data.pids);
}

int attach(const int uid, const short pid, const char* pname) {
	attach_pid(uid, pid, pname);
	attach_tree(pid);
	return 0;
}

void killall(char* path, char* controller, int sig) {
	int err = 0;
	void** h = malloc(255);
	pid_t pid;
	err = cgroup_get_task_begin(path, controller, h, &pid); 
	if(err != 0 && err != ECGEOF) {
		syslog(LOG_ERR, "Cannot get cgroup %s(%s) tasks(%d: %s).", path, controller, err, cgroup_strerror(err));
	} else {
		while(err != ECGEOF) {
			syslog(LOG_INFO, "Sending signal %d to tasks in cgroup %s(%s): pid = %d.", sig, path, controller, pid);
			kill(pid, sig); 
			err = cgroup_get_task_next(h, &pid); 
			if(err != 0 && err != ECGEOF) {
				syslog(LOG_ERR, "Cannot get cgroup %s(%s) next task(%d: %s).", path, controller, err, cgroup_strerror(err));
			}
		}
		cgroup_get_task_end(h);
	}
}

int remove_cgroup(int uid, struct cgroup* cg) {
	int err = 0;
	char* path = uid_to_path(uid);
	killall(path, "memory", SIGTERM);
	sleep(1);
	killall(path, "cpuset", SIGTERM);
	killall(path, "cpu", SIGTERM);
	killall(path, "memory", SIGKILL);
	killall(path, "cpuset", SIGKILL);
	killall(path, "cpu", SIGKILL);
	sleep(1);
	err = cgroup_delete_cgroup_ext(cg, 0); 
	free(path);
	if(err != 0 && err != 50016) {
		syslog(LOG_ERR, "Cannot remove cgroup %d(%d: %s).", uid, err, cgroup_strerror(err));
		return 1;
	}
	return 0;
}

int memory(int uid, long long bytes, int act) {
	int err = 0;	
	struct cgroup* cg = NULL;
	struct cgroup_controller* memory = NULL;
	int64_t limit;
	int ret = 0;

	cg = get_or_create(uid);
	memory = cgroup_get_controller(cg, "memory");
	err = cgroup_get_value_int64(memory, "memory.limit_in_bytes", &limit);
	if(err != 0) {
		syslog(LOG_ERR, "Cannot get cgroup %d memory limit(%d: %s).", uid, err, cgroup_strerror(err));
		cgroup_free_controllers(cg);
		cgroup_free(&cg);
		return -1;
	}

	switch(act) {
		case CG_SET:
			limit = bytes;
			break;
		case CG_ADD:
			if(limit < LLONG_MAX - bytes) {
				limit += bytes;
			} else if(limit >= LLONG_MAX || limit < 0) {
				limit = bytes;
			} else if(limit < LLONG_MAX && limit >= LLONG_MAX - bytes) { // I don't belive it would ever happen
				limit = LLONG_MAX;
			}
			break;
		case CG_REM:
			if(limit > bytes) {
				limit -= bytes;
			} else if(limit >= 0 && limit <= bytes) { 
				limit = 0;
			}
			break;
	}

	if(limit < 4096) {
		remove_cgroup(uid, cg);
	} else {
		err = cgroup_set_value_int64(memory, "memory.limit_in_bytes", limit);
		if(err != 0) {
			syslog(LOG_ERR, "Cannot modify cgroup %d memory limit(%d: %s).", uid, err, cgroup_strerror(err));
			ret = 1;
		} else {
			err = cgroup_modify_cgroup(cg);
			if(err != 0) {
				syslog(LOG_ERR, "Cannot apply cgroup %d memory limit to kernel(%d: %s).", uid, err, cgroup_strerror(err));
				ret = 2;
			} else {
				syslog(LOG_DEBUG, "Cgroup %d memory limit set to %"PRId64".", uid, limit);
			}
		}
	}

	cgroup_free_controllers(cg);
	cgroup_free(&cg);
	return ret;
}

char* llist_to_cpus(const struct llist* cpus_list, const char* prefix) {
	int n = 0; 
	char* str = NULL;
	int i = 0;
	int si = 0;
	int plen = (prefix == NULL ? 0 : strlen(prefix));
	long* curr = cpus_list->pids;

	for(i = 0; i < cpus_list->n; i++) {
		if(cpus_list->pids[i] == INT_MIN)
			++(cpus_list->pids[i]);
		n += lrint(ceil(log10(abs(cpus_list->pids[i])))) + 1 + (cpus_list->pids[i] < 0);
	}
	n++;
	str = malloc(sizeof(char) * (n + plen));
	if(str == NULL) {
		syslog(LOG_ERR, "Cannot get memory for cpus to string conversion.");
		exit(10);
	}
	if(plen > 0) {
		strcpy(str, prefix);
		str[plen-1] = ',';
		si += plen;
	}
	for(i = 0; i < cpus_list->n; i++) {
		si += sprintf(&(str[si]), "%ld,", cpus_list->pids[i]);
	}
	if(si > 0) {
		--si;
	}
	str[si] = 0;
	return str;
}

int cpus(int uid, struct llist* cpus_list, int act) {
	struct cgroup* cg = NULL;;
	struct cgroup_controller* cpuset = NULL;
	char* cpus_kern_str = NULL;
	char* cpus_str = NULL;
	int ret = 0;
	int err = 0;

	cg = get_or_create(uid);
	cpuset = cgroup_get_controller(cg, "cpuset");
	err = cgroup_get_value_string(cpuset, "cpuset.cpus", &cpus_kern_str);
	if(err != 0) {
		syslog(LOG_ERR, "Cannot get cgroup %d allowed cpus list(%d: %s).", uid, err, cgroup_strerror(err));
		cgroup_free_controllers(cg);
		cgroup_free(&cg);
		return -1;
	}
	switch(act) {
		case CG_ADD:
			cpus_str = llist_to_cpus(cpus_list, cpus_kern_str);
			break;
		case CG_SET: 
			cpus_str = llist_to_cpus(cpus_list, NULL);
			break;
		case CG_REM: {
			int i;
			struct llist* cpus_kern_list = llist_new();
			char* curr = cpus_kern_str;
			long cpu;
			while(*curr != 0) {
				cpu = strtol(curr, &curr, 10);
				if(*curr == '-') {
					int start = cpu;
					int i;
					curr++;
					cpu = strtol(curr, &curr, 10);
					for(i = start; i <= cpu; i++) {
						if(!llist_test(cpus_list, i)) {
							llist_add(cpus_kern_list, i);
						}
					} 
				} else {
					if(!llist_test(cpus_list, cpu)) {
						llist_add(cpus_kern_list, cpu);
					}
				}
				if(*curr == ',')
					curr++;
			}
			cpus_str = llist_to_cpus(cpus_kern_list, NULL);
			}
			break;
	}
	if(strlen(cpus_str) < 1) {
		remove_cgroup(uid, cg);
	} else {
		err = cgroup_set_value_string(cpuset, "cpuset.cpus", cpus_str);
		if(err != 0) {
			syslog(LOG_ERR, "Cannot set cgroup %d allowed cpus list(%d: %s).", uid, err, cgroup_strerror(err));
			ret = 1;
		} else {
			err = cgroup_modify_cgroup(cg);
			if(err != 0) {
				syslog(LOG_ERR, "Cannot apply cgroup %d allowed cpus list(%s) to kernel(%d: %s).", uid, cpus_str, err, cgroup_strerror(err));
				ret = 2;
			} else {
				syslog(LOG_DEBUG, "Cgroup %d allowed cpus list set to %s.", uid, cpus_str);
			}
		}
	}
	cgroup_free_controllers(cg);
	cgroup_free(&cg);
	free(cpus_str);
	return ret;
}

int shares(int uid, int shares, int act) {
	int err = 0;	
	struct cgroup* cg = NULL;
	struct cgroup_controller* cpu = NULL;
	int64_t shares_kern;
	int ret = 0;

	cg = get_or_create(uid);
	cpu = cgroup_get_controller(cg, "cpu");
	err = cgroup_get_value_int64(cpu, "cpu.shares", &shares_kern);
	if(err != 0) {
		syslog(LOG_ERR, "Cannot get cgroup %d cpu shares(%d: %s).", uid, err, cgroup_strerror(err));
		cgroup_free_controllers(cg);
		cgroup_free(&cg);
		return -1;
	}

	switch(act) {
		case CG_SET:
			shares_kern = shares;
			break;
		case CG_ADD:
			if(shares_kern < LLONG_MAX - shares) {
				shares_kern += shares;
			} else if(shares_kern >= LLONG_MAX || shares_kern < 0) {
				shares_kern = shares;
			} else if(shares_kern < LLONG_MAX && shares_kern >= LLONG_MAX - shares) {
				shares_kern = LLONG_MAX;
			}
			break;
		case CG_REM:
			if(shares_kern > shares) {
				shares_kern -= shares;
			} else if(shares_kern >= 0 && shares_kern <= shares) { 
				shares_kern = 0;
			}
			break;
	}

	if(shares_kern < 1) {
		remove_cgroup(uid, cg);
	} else {
		err = cgroup_set_value_int64(cpu, "cpu.shares", shares_kern);
		if(err != 0) {
			syslog(LOG_ERR, "Cannot modify cgroup %d cpu_shares(%d: %s).", uid, err, cgroup_strerror(err));
			ret = 1;
		} else {
			err = cgroup_modify_cgroup(cg);
			if(err != 0) {
				syslog(LOG_ERR, "Cannot apply cgroup %d cpu shares to kernel(%d: %s).", uid, err, cgroup_strerror(err));
				ret = 2;
			} else {
				syslog(LOG_DEBUG, "Cgroup %d cpu shares set to %"PRId64".", uid, shares_kern);
			}
		}
	}

	cgroup_free_controllers(cg);
	cgroup_free(&cg);
	return ret;
}
