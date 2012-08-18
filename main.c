#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "funcs.h"
#include "cgroups.h"

int main(int argc, char** argv) {
	struct config_t config = set_config(argc, argv);
	init(&config);
	if(config.daemon != 0) {
		if(config.debug < 1) 
			daemonize();
		loop();	
	} else if(config.action != CG_NOACT) {
		if(config.delay > 0) {
			daemonize();
			sleep(config.delay);
		}
		if(config.mem > -1) 
			memory(config.uid, config.mem, config.action);
		if(config.cpus != NULL) 
			cpus(config.uid, config.cpus, config.action);
		if(config.shares > -1) 
			shares(config.uid, config.shares, config.action);
	}
	return 0;
}
