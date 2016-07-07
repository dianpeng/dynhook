DynHook: A high performance dynamic function hook for x64 Linux
============================

#Introduction
Allow user to replace a function of a running process with another function without *STOPPING* the process with minimal overhead.

#Motivation
1. Ptrace + trap is too slow , not usable for real time profiling
2. Ptrace + trap is hard to allow user execute old function in multiple thread environment. GDB solves it by simulating single instruction in ptrace process which is too heavy weight; most of user recover the old instruction where the int 3 inserts , but this opens a window that other thread may miss the trap while execution.
3. High performance dynamic hook for real time profiling , monitoring use case. Think it as kprobe but in user space

#Feature
1. Dynhook is built for real time use and high performance dynamic hook.
2. Unlike most of the ptrace + trap( int 3 ) hook, dynhook implements inline hook, which means after hooking, everything will happen inside of the remote process. The ptrace tracer does nothing at all.
3. Each hooked function will only have 1-4 instructions overhead during invocation.
4. User is allowed to call original function. Calling the original function will have 3 instructions overhead during invocation.
5. Dynhook has 3 different built in hook types. It will try to choose the most performant one for hooking.

#How to use?
sudo ./dynhook --pid RunningProcessPID --hook Path@Target:Hook:Entry --hook ...

1. RunningProcessPID : The process's pid that gonna be hooked
2. Path : The shared object's path that you want to inject, if the path is relative path, make sure it is relative path to the target process.
3. Target: The *SYMBOL* name of function that you want to hook in *REMOTE* process. Use objdump or whatever tool to grab it.
4. Hook: The *SYMBOL* name of function that you want to use from shared object to replace the function in target process
5. Entry: The *SYMBOL* name of function in shared object that will be called *BEFORE* the hook start and also this function will get the function pointer of hooked function in case user want to call it in new function.

User can press any key to quit the dynhook process, once user quit the process the hooked code will be recoveried and old function will come back.

#Caveats
1. In general, there's no requirements for target process except the symbol should be inside of the ELF file of target process.
2. User is recommended to compile its code with -fPIC but not required.
3. A function that is inlined cannot be hooked and also a function is not inside of the symbol table of ELF file cannot be hooked.
4. A function size is less than 5 bytes cannot be hooked.
5. A function's first few instruction has jcc family instructions cannot be hooked.
6. A function's first few instruction has jump but not compiled with -fPIC cannot be hooked.
7. A function has instruction that jumps back to the first few bytes of function cannot be hooked.
8. There will be a minor memory leak in the target running process after hooking. Each function hooked will occupied at most around 40 bytes, but we will have to allocate 2 pages even user want to hook one functions. So in most cases, user will have 8KB leak every time you invoke the dynhook. Dynhook simply doesn't unmap those mapped memory due to it is too hard to figure out a correct time to unmap it. ( It's doable, but too slow and complicated )
9. The shared object will be mapped until the target process quit. This won't cause any issue in X64 since we have 64 bit address spaces.
10. Current implementation , *IN THEORY* ,may have corner case which will cause process hang. This will be resolved in future ,but it is highly unlikely user will catch it.

#Dependency
1. libelf
2. boost
3. luajit ( only for invoke dynasm while building dynhook )
4. google-log 

#Build
make
