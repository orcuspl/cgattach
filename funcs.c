#include <libcgroup.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <pwd.h>

#define SYSLOG_NAMES
#include <syslog.h>

#include "funcs.h"
#include "cgroups.h"
#include "llist.h"


void print_facilitynames() {
	int i = 0;
	fprintf(stderr, "Valid facility names:\n");
	while(i <= LOG_NFACILITIES && facilitynames[i].c_name != NULL) {
		fprintf(stderr, "%s ", facilitynames[i].c_name);
		i++;
	}
	fprintf(stderr, "\n");
}

char set_facility(int* n, char* str) {
	int i = 0;
	while(i <= LOG_NFACILITIES && facilitynames[i].c_name != NULL) {
		if(strcmp(facilitynames[i].c_name, str) == 0) {
			*n = facilitynames[i].c_val;
			return 0;
		}
		++i;
	}
	fprintf(stderr, "\nInvalid facility name: %s\n", str);
	print_facilitynames();
	return 1;
}

char set_uid(int* uid, const char* str) {
	char* end = NULL;
	*uid = strtol(str, &end, 0);
	if(*uid < 1000 || *end != 0) {
		fprintf(stderr, "\nWrong uid: %s\n", str);
		return 1;
	}
	return 0;
}

char set_login(int* uid, const char* str) {
	struct passwd* pwd = getpwnam(str);
	if(pwd == NULL) {
		fprintf(stderr, "\nWrong username: %s(%d: %s)\n", str, errno, strerror(errno));
		return 1;
	}
	*uid = pwd->pw_uid;
	return 0;
}

char set_mem(int64_t* mem, const char* str, const char shift) {
	long long add = -1;
	char* end = NULL;
	add = strtoll(str, &end, 0);
	if(add >= 0 && *end == 0) {
		if(*mem == -1) {
			*mem = 0;
		} 
		*mem += (add << shift);
		return 0;
	}
	fprintf(stderr, "\nWrong number in one of mem's opts: %s\n", str);
	return 1;
}

char set_cpus(struct llist** cpus, char* str) {
	long cpun = -1;
	char* end = NULL;
	cpun = strtol(str, &end, 0);
	if(cpun >= 0 && *end == 0) {
		if(*cpus == NULL) {
			*cpus = llist_new();
		}
		llist_add(*cpus, cpun);
		return 0;
	}
	fprintf(stderr, "\nWrong number in one of cpus opts: %s\n", str);
	return 1;
}

char set_shares(int* shares, char* str) {
	long shares_in = -1;
	char* end = NULL;
	shares_in = strtoll(str, &end, 0);
	if(shares_in >= 0 && *end == 0) {
		if(*shares == -1) {
			*shares = 0;
		} 
		*shares += shares_in;
		return 0;
	}
	fprintf(stderr, "\nWrong number in one of shares opts: %s\n", str);
	return 1;
	
}

char set_delay(int* delay, char* str) {
	long delay_in = -1;
	char* end = NULL;
	delay_in = strtol(str, &end, 0);
	if(delay_in >= 0 && *end == 0) {
		if(*delay == -1) {
			*delay = 0;
		} 
		*delay += delay_in;
		return 0;
	}
	fprintf(stderr, "\nWrong number in one of delay opts: %s\n", str);
	return 1;
	
}

void print_help(const char* name) {
	fprintf(stderr, "\nUsage: %s [options]\n\n", name);
	fprintf(stderr, "options(do not use --deamon with cgroup/mem/cpu options):\n");
	fprintf(stderr, "--deamon - run deamon, no cgroup changes allowed\n");
	fprintf(stderr, "--facility/-f faility_name - syslog facility\n");
	fprintf(stderr, "--debug - do not fork and show what will be done\n");
	fprintf(stderr, "--quiet - supress all output not related to arguments(syslog still get messages)\n");
	fprintf(stderr, "--delay secs - delay given action for secs seconds\n");
	print_facilitynames();
	fprintf(stderr, "\ncgroup options:\n");
	fprintf(stderr, "--add - adding resources to cgroup\n");
	fprintf(stderr, "--rem - removing resources to cgroup\n");
	fprintf(stderr, "--set - setting resources in cgroup\n");
	fprintf(stderr, "--uid/-u number - uid whose cgroup should be changed\n");
	fprintf(stderr, "--login/-l username - username whose cgroup should be changed\n");
	fprintf(stderr, "\nmem options:\n");
	fprintf(stderr, "--mem/-b number - mem in bytes\n");
	fprintf(stderr, "--kmem/-k number - mem in kbytes\n");
	fprintf(stderr, "--mmem/-m number - mem in mbytes\n");
	fprintf(stderr, "--gmem/-g number - mem in gbytes\n");
	fprintf(stderr, "\ncpu options:\n");
	fprintf(stderr, "--cpu/-c number - cpu number\n");
	fprintf(stderr, "--shares/-s number - cpu shares\n");
}

char sanity(struct config_t config) {
	char err = 0;
	if(config.daemon == 1 && (config.action != CG_NOACT || config.mem != -1 || config.uid != -1 || config.cpus != NULL || config.shares != -1)) {
		fprintf(stderr, "\nCombining --deamon option with any of cgroup/mem/cpu options is prohibited\n");
		err |= 1;	
	}
	if(config.daemon == 0) {
		if(config.action == CG_NOACT) {
			fprintf(stderr, "\nNo --add/--rem/--set option\n");
			err |= 1;
		}
		if(config.uid < 1000) {
			fprintf(stderr, "\nNo --uid nor valid --login given\n");
			err |= 1;
		}
		if(config.mem < 0 && config.cpus == NULL && config.shares < 0) {
			fprintf(stderr, "\nNo mem/cpu option given.\n");
			err |= 1;
		}
	}
	if(config.delay > 0 && config.debug > 0) {
		fprintf(stderr, "\nCannot debug delayed action.\n");
		err |= 1;	
	}
	if(err != 0) {
		return 1;
	}
	return 0;
}

struct config_t set_config(int argc, char* const* argv) {
	int c = 0;
	char error = 0;
	int option_index = 0;
	struct config_t config = {0, "cgattach", LOG_DAEMON, 0, CG_NOACT, -1, -1, NULL, -1, -1};
	struct option long_options[] = {
		{"daemon", no_argument, &(config.daemon), 1},
		{"facility", required_argument, 0, 'f'},
		{"syslog_name", required_argument, 0, 'n'},
		{"debug", no_argument, &(config.debug), 1},
		{"quiet", no_argument, &(config.debug), -1},
		{"add", no_argument, &(config.action), CG_ADD},
		{"rem", no_argument, &(config.action), CG_REM},
		{"set", no_argument, &(config.action), CG_SET},
		{"uid", required_argument, 0, 'u'}, 
		{"login", required_argument, 0, 'l'}, 
		{"mem", required_argument, 0, 'b'}, 
		{"kmem", required_argument, 0, 'k'}, 
		{"mmem", required_argument, 0, 'm'}, 
		{"gmem", required_argument, 0, 'g'}, 
		{"cpu", required_argument, 0, 'c'},
		{"shares", required_argument, 0, 's'},
		{"help", no_argument, 0, 'h'},
		{"delay", required_argument, 0, 'd'},
		{0, 0, 0, 0}
	};
	while((c = getopt_long(argc, argv, "f:n:u:l:b:k:m:g:c:s:h:d:", long_options, &option_index)) != -1) {
		switch(c) {
			case 'f':
				error |= set_facility(&(config.facility), optarg); 
				break;
			case 'n':
				config.syslog_name = optarg;
				break;
			case 'u':
				error |= set_uid(&(config.uid), optarg);
				break;
			case 'l':
				error |= set_login(&(config.uid), optarg);
				break;
			case 'b':
				error |= set_mem(&(config.mem), optarg, 0);
				break;
			case 'k':
				error |= set_mem(&(config.mem), optarg, 10);
				break;
			case 'm':
				error |= set_mem(&(config.mem), optarg, 20);
				break;
			case 'g':
				error |= set_mem(&(config.mem), optarg, 30);
				break;
			case 'c':
				error |= set_cpus(&(config.cpus), optarg);
				break;
			case 's':
				error |= set_shares(&(config.shares), optarg);
				break;
			case 'd':
				error |= set_delay(&(config.delay), optarg);
				break;
			case 'h':
				print_help(argv[0]);
				exit(0);
				break;
		}	
	}
	error |= sanity(config);
	if(error != 0) {
		printf("\nNothing done\n\n");
		exit(9);
	}
	return config;
}

void init(struct config_t* config) {
	int err = 0;
	struct cgroup* cg = NULL;
	FILE* ev = NULL;

	openlog("cgattach", (config->debug == 1 ? LOG_PERROR : 0), LOG_DAEMON);
	if(config->debug == -1) {
		fclose(stderr);
		fclose(stdout);
	}
	err = cgroup_init();
	if(err != 0) {
		syslog(LOG_CRIT, "Initialization FAILED. Check cgroup filesystem. Extiting.");
		closelog();
		exit(1);
	}
	cg = get_or_create(-1);
	if(cg == NULL) {
		syslog(LOG_CRIT, "Initialization FAILED. Cannot get nor create 'users' cgroup. Extiting.");
		closelog();
		exit(2);
	}
	cgroup_free(&cg);
//	syslog(LOG_DEBUG, "Initialization OK");
}

void daemonize() {
	pid_t pid;
	if (daemon(0, 0) == -1) {
		syslog(LOG_CRIT, "Cannot daemonize(%d: %s). Exiting.", errno, strerror(errno)); 
		exit(7);
	}
	if((pid = fork()) == -1) {
		syslog(LOG_CRIT, "Cannot fork(%d: %s). Exiting.", errno, strerror(errno));
		closelog();
		exit(7);
	} else if(pid != 0) {
		syslog(LOG_DEBUG, "Forked child's pid: %d.", pid);
		closelog();
		exit(0);
	}
}

void loop() {
	FILE* ev = NULL;
	char *line = NULL;
	size_t line_len = 0;
	char* pname = NULL;
	short pid = 0;
	unsigned int uid = 0;
	int matches = 0;
	
	pname = malloc(21*sizeof(char));
	if(pname == NULL) {
		syslog(LOG_CRIT, "No memory(21 bytes) for pname! Exiting.");
		exit(3);
	}
	ev = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
	if(ev == NULL) {
		syslog(LOG_CRIT, "Cannot open '/sys/kernel/debug/tracing/trace' for reading(%d: %s). Extiting.", errno, strerror(errno));
		closelog();
		exit(4);
	}
	while(getline(&line, &line_len, ev) > 0) {
		matches = sscanf(line, "%*[ ]%20[^-]-%hd%*[ ][%*d]%*[ ]%*u.%*u: sys_setuid(uid: %x)", pname, &pid, &uid);
		if(matches == 3) {
			attach(uid, pid, pname);
		} else {
			matches = sscanf(line, "%*[ ]%20[^-]-%hd%*[ ][%*d]%*[ ]%*d.%*d: sys_setresuid(ruid: %x, euid:", pname, &pid, &uid);
			if(matches == 3) {
				attach(uid, pid, pname);
			}
			else {
				syslog(LOG_ERR, "Unknown line in event tracking pipe: %s.", line);
			}
		}
	}
}

void traverse_proc(struct traverse_proc_func* tpf[], struct llist* skip, void* data) {
	char flag = 1;
	short pid = 0;
	DIR* proc = opendir("/proc");
	struct dirent* curr = NULL;
	FILE* stat = NULL;
	char statfn[20];
	char *line = NULL;
	size_t line_len = 0;
	short tpf_i = 0;
	char retval = 0;
	if(proc == NULL) {
		syslog(LOG_ERR, "Cannot open dir /proc(%d: %s).", errno, strerror(errno));
		flag = 0;
	}
	while(flag == 1) {
		flag = 0;
		while((curr = readdir(proc)) != NULL) {
			if(curr->d_type == DT_DIR && sscanf(curr->d_name, "%hd", &pid) == 1 && !llist_test(skip, pid)) {
				sprintf(statfn, "/proc/%hd/status", pid);
				stat = fopen(statfn, "r");
				if(stat == NULL) {
					if(errno != 2) 
						syslog(LOG_ERR, "Cannot open %s for reading(%d: %s). Skipping.", statfn, errno, strerror(errno));
				} else {
					while(getline(&line, &line_len, stat) > 0) {
						tpf_i = 0;
						while(tpf[tpf_i] != NULL && ~retval & 2) {
							retval = tpf[tpf_i]->test(line, data);
							if((retval & 1) && tpf[tpf_i]->func != NULL) {
								flag |= tpf[tpf_i]->func(data);
							} 
							tpf_i++;
						}
					}
					fclose(stat);
				}
			}
		}
		rewinddir(proc);
	}
}
