ld.so.eBPF utilizes eBPF (Extended Berkeley Packet Filter) to replicate the behavior of ld.so.preload, allowing dynamic injection of shared libraries into processes by modifying the environment of executing processes. It hooks into the sys_enter_execve and sys_enter_execveat syscalls, which handle process execution requests, and manipulates the environment pointer (envp) to inject a custom LD_PRELOAD environment variable.

By doing so, the project offers a lightweight and flexible approach for library injection across various processes without needing to alter the executable files themselves or rely on traditional static methods. The result is a more dynamic method for enhancing process behaviors with additional functionality.

To compile the project, run the following command:

./compile.sh

Once compiled, the program requires two parameters for execution:

./loader &lt;full path to the library to inject&gt; &lt;name of the process to inject&gt;

For example, to inject the library /tmp/rogue.so into the bash process, the command would be:

./loader /tmp/rogue.so bash

For optimal chances of success when executing the loader, it's recommended to execute it with high-priority settings, ensuring that the process has full control over the CPU and IO priority. You can achieve this by running the following command:

chrt -f 99 taskset -c 0 bash -c 'ulimit -l unlimited && ionice -c1 -n0 ./loader /tmp/rogue.so /bin/bash'

![Demo]([(https://github.com/YJesus/Ld.so.eBPF/blob/main/demo.gif))

Tested in RHEL 9.5
