Backtrack
=========

Several files are provided :

* A compiled binary
* The source code of this binary (C++)
* A *Dockerfile* allowing to locally test and debug the exploit in the same environment (Ubuntu 18.04)

The source code is very short :

1. The ``main()`` creates three treads : **listen_loop**, **do_reads** and **memory_loop**. Then it execute a **menu** in an infinite loop.
2. The ``listen_loop()`` accept a incomming connection and a the new socket in the ``fds`` array, as well as adding NULL in the ``buffers`` array.
3. The ``do_reads()`` performs a non blocking ``recv()`` on each file descriptor in the ``fds`` array using the buffer from the ``buffers`` array.
4. The ``memory_loop()`` is responsible of allocating and freeing the buffers in the ``buffers`` for each newly added file descriptor in ``fds`` and for each delete ones (from the menu).
5. The ``menu()`` executed in the main thread allows to perform several allocation : *listing* the ``fds`` array, *removing* an entry in ``fds`` or *dislaying* the buffer associated to an entry in ``fds``.

![Threads](images/overview.png)

The ``fds`` and ``buffers`` objects are defined as globals :

```cpp
std::vector<int> fds;
std::vector<char*> buffers;
```

The vulnerabilities
-------------------

As we can guess, the main problem is that several variables are used from several threads without locking mechanism. There are several locations where a race condition can occurs but the easiest to exploit is in the ``do_reads()`` function :

```cpp
        std::vector<char*> valid_buf;
        std::vector<int> valid_fd;
        for (int i = 0; i < fds.size(); i++) {
            if (fds[i] != -1 && buffers[i] != nullptr) {
                valid_fd.push_back(fds[i]);
[1]             valid_buf.push_back(buffers[i]);
            }
        }
[2]     sleep(1);
        for (int i = 0; i < valid_fd.size(); i++) {
[3]         int res = recv(valid_fd[i], valid_buf[i], 0x40, MSG_DONTWAIT);
        }
```

In this code, the ``do_reads`` thread **copy** the reference of a valid allocated buffer [1], wait **one second** [2] and the fill it with user-controled input data [3]. So, if during this second, another thread has deleted the allocation, the ``recv()`` writes data into a freed chunk (UAF).

To trigger this Use After Free, one can just do the following :

1. Connect to the port 31337 : a new file descriptor is added in the ``fds`` array. The memory loop will allocate the associated within **1ms**.
2. Wait 1s : the ``do_reads`` have a copy of this file descriptor and its associated buffer.
3. Ask to delete the fd in the ``menu`` : this won't close it but just setting the entry in ``fds`` to ``-1``.
4. Send data in this buffer

To make sure we win this 1 second race, the buffer content can be polled using the ``menu`` to synchronize the exploit code with the ``do_reads`` loop : the content of the buffer is changed when the ``recv()`` is performed.

The other problem in the source code is that the allocations are not zeroed. So allocating a buffer and then printing it will display the content of the memory where this chunk is allocated (infoleak).

R/W stabilization
-----------------

The allocations are made using ``new char[0x40]`` which just use the libc using ``malloc()`` with the same size. As we can allocate and free them at will, one can leak the libc metadata by removing a chunk, allocating a new one and using the infoleak. In these leaked metadata, there is the pointer of the next free chunk after this one. Using this pointer, the address of all allocations can be guessed in a determinist way.

After retrieving this address in heap, the UAF is used to overwrite the metadata of a freed buffer in order to take over **one* chunk. Indeed, if the content of a freed chunk is overwriten after been freed (using ``do_read``) the ``FD``/``BK`` pointers can be overwritten. By writing an arbitrary address, this address will be returned by the second next ``malloc()``.

This gdb script prints the address of the allocated buffers :

```
b *0x0401941
commands
    silent
    printf "%016llx\n", $rax
    c
end
```

Overwriting the libc metata with an address shows that the chunk is returned after two allocations (the next one being the chunk used as UAF) :

![Controled chunk allocation](images/takeover.png)

The libc expect to find metadata in this last chunk. So if we allocate again a new chunk, it will use the first 64 bytes located at this address as the next chunk. So the exploitation never allocates again a new buffer after this step.

The idea of the stablization is to get reusable read/write primitives by taking over one object at a known address. Using the infoleak, an address in heap is retrieved but there are mostly only other buffers which content is controled anyway. But the program is compiled without PIC, this means it is loaded at the same address :

```
00400000-00406000 r-xp 00000000 fd:00 29101970                           /chall
00606000-00607000 r--p 00006000 fd:00 29101970                           /chall
00607000-00608000 rw-p 00007000 fd:00 29101970                           /chall
```

The ``fd`` and ``buffers`` vectors are both composed of 3 64-bytes values. The first one is the start of the data of this vector and the second one is the end. So taking over a vector allows to define **where it is stored** in memory (as well as its size). To get stable R/W, we only need to take over the ``buffers`` vector.

As the address of all the first allocations are known (using the pointer leaked previouly), the overwritten ``buffers`` vector can point to controled data. This fake buffer table is made to :

1. Have the same size as the previous one
2. Have the same NULL entry (otherwise the memory loop thread would perform an allocation)
3. Have one entry pointing to itself : so we can update it and get reusable R/W primitives
4. Have another non-NULL entry pointing to the victim we want to read or write

![Fake buffer table](images/fake_vector.png)

With this setup, updating this table can be done by filling buffer 1. Reading memory at an arbitrary address can be done by using the menu with buffer index 3. Writing to this address can be done by sending data on the connection corresponding to the buffer 3.

Flag
----

From these primitives, gaining command execution is easy because the program has no PIC and the GOT can be overwritten (it is mapped as rw). Moreover, there is a call to ``system()`` in the menu.

To get the flag :

1. Write the command somewhere in memory
2. Overwrite the GOT entry of ``puts()`` with ``system()``
3. Update the address of one buffer
4. Print it with the menu, this will execute the command

```Python
mem_write(0x607140, b'/bin/sh -c "cat /flag.txt"\x00')
mem_write(0x607100, int(0x401086).to_bytes(8, 'little'))
update_buffer_table(1, buffer_0_addr, 0x607140)
print_buffer(3)
# Printed : HTB{wh0_n33ds_mut3x35_4nyw4y!?!?}
```
