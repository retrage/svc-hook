# Supplemental Documentation for svc-hook

This page provides supplementary material for the svc-hook paper. It presents experimental results that could not be included due to space constraints. All results reflect the implementation state at the time this document was committed. We plan to update this page if the implementation changes in the future.

## Experiment Setup

- Computer: HoneyComb LX2
- CPU: NXP LX2160A 16-core Arm Cortex A72 CPU (running up to 2.2 GH)
- DRAM: 64 GB
- OS: Linux 5.10

## Memory Footprint of the Trampoline Code

We measure the memory footprint of the trampoline code of svc-hook.

We have compiled the following minimalistic C program, whose main function immediately returns. This time, the compiled program is named `a.out`.

```c
int main(int argc, char const* argv[])
{
        return 0;
}
```

The compiled program links the following shared objects; here, the version of glibc is 2.31.

```shell
$ ldd ./a.out
        linux-vdso.so.1 (0x0000ffffb6e56000)
        libc.so.6 => /lib/aarch64-linux-gnu/libc.so.6 (0x0000ffffb6ca1000)
        /lib/ld-linux-aarch64.so.1 (0x0000ffffb6e26000)
```

When we apply svc-hook to this minimalistic program using the following command.

```shell
LD_PRELOAD=./libsvchook.so ./a.out
```

We found 20812 bytes have been used for the trampoline code.

Here, we look into the breakdown of 20812 bytes.

Our prototype separates the trampoline code into common [jump](https://github.com/retrage/svc-hook/blob/f65a553fa95ffa130636c40022d9764394dce0e3/main.c#L773-L792) and [misc](https://github.com/retrage/svc-hook/blob/f65a553fa95ffa130636c40022d9764394dce0e3/main.c#L98-L207) parts and uncommon [return address preserving](https://github.com/retrage/svc-hook/blob/f65a553fa95ffa130636c40022d9764394dce0e3/main.c#L809-L821) parts; the uncommon part has to be instantiated for every replaced `b` because the return address for each is different, on the other hand, we do not duplicate the common parts for each svc.

In our experiment environment, the common parts have consumed 428 bytes, and the remaining 20384 bytes are used by the uncommon parts for 728 of `svc` instructions.
Each uncommon part of the trampoline code consists of 7 CPU instructions and thereby consumes 28 bytes (728 of 28-byte uncommon parts use 20384 bytes).

5 out of 728 `svc` instructions are found in `linux-vdso.so.1`, 685 are in `libc.so.6`, and 38 are in `/lib/ld-linux-aarch64.so.1`.

When we run a program that additionally links `libpthread.so` that contains 202 `svc` instructions, the total memory size consumed for the trampoline code is increased to 26468 bytes; the 5656-byte gap to 20812 bytes comes from 202 of 28-byte uncommon parts.

In summary, the memory footprint of svc-hook's trampoline code is the summation of the common part size and the size of the uncommon part multiplied by the number of `svc` instructions found in the hook-applied program.

Based on these numbers, we consider the memory size required for the trampoline code acceptably small. We also expect that the memory footprint of svc-hook will not drastically increase in other environments because `svc` instructions are not often found in programs.

## Performance Overhead for Hook-applied Applications

We examine if svc-hook imposes negative performance impacts on hook-applied application programs, using a set of popular applications including [SQLite][sqlite], [PostgreSQL][postgresql], and [Samba][samba].

We apply svc-hook to the programs above. Once the hook is applied, system calls, which a hook-applied user-space program has attempted to invoke, are hooked by svc-hook, and its [default hook function](https://github.com/retrage/svc-hook/blob/f65a553fa95ffa130636c40022d9764394dce0e3/main.c#L209-L211) executes `svc` and returns the results of the invoked system calls to the hook-applied user-space program.

We compare the case where the hook program mentioned above is applied by svc-hook and the case where system calls are not hooked, to highlight the performance penalty of svc-hook.
For the following experiments, we run the benchmark target applications and the benchmark tools on the same machine to minimize networking overhead and let the application programs trigger system calls frequently.

### SQLite

We run an [SQLite benchmark program][sqlite-bench] which links the SQLite library and measures its performance for reading and writing key-value records in a table of a database.

We place the files manipulated by SQLite in a directory backed by tmpfs. We type the following commands to mount tmpfs.

```shell
mkdir ./tmpfs
sudo mount -t tmpfs -o size=18G tmpfs ./tmpfs
```

We make the following change to Makefile of the benchmark tool.

```diff
diff --git a/Makefile b/Makefile
index 2ab27b7..dc32280 100644
--- a/Makefile
+++ b/Makefile
@@ -8,7 +8,7 @@ UNAME_S := $(shell uname -s)
 ifeq ($(UNAME_S),Darwin)
        LDFLAGS=-lpthread -ldl -lm
 else
-       LDFLAGS=-lpthread -ldl -lm -static
+       LDFLAGS=-lpthread -ldl -lm
 endif
```

This benchmark uses one million records, and we configure the key size to be 16 bytes and the value size to be 100 bytes.
We use the Write-Ahead Logging (WAL) mode of SQLite.

The following command is for the case that does not apply svc-hook; labeled `without svc-hook`.

```shell
/bin/rm ./tmpfs/*; ./sqlite-bench --db=./tmpfs/ --benchmarks=fillseq,fillrandom,readseq,readrandom --num=1000000 --compression_ratio=0 --WAL_enabled=1 --use_existing_db=0
```

The following command is for the case that applies svc-hook; labeled `with svc-hook`.

```shell
/bin/rm ./tmpfs/*; LD_PRELOAD=PATH_TO/libsvchook.so ./sqlite-bench --db=./tmpfs/ --benchmarks=fillseq,fillrandom,readseq,readrandom --num=1000000 --compression_ratio=0 --WAL_enabled=1 --use_existing_db=0
```

The following table shows the results (time spent on a single operation in microseconds); when svc-hook is applied, the operation time increases by 0.01% to 2.6%.

| Workload                | without svc-hook | with svc-hook |
|-------------------------|------------------|---------------|
| Sequential Fill (Write) | 22.971           | 23.572        |
| Random Fill (Write)     | 39.996           | 40.253        |
| Sequential Read         | 8.321            | 8.498         |
| Random Read             | 12.572           | 12.574        |

### PostgreSQL

We use PostgreSQL version 17.6.
For the benchmark client, we use the pgbench benchmark tool distributed as part of the source code of PostgreSQL and generates workloads loosely based on TPC-B.

We put the database files manipulated by PostgreSQL in a directory backed by tmpfs so that we can minimize the wait time for storage I/O and the PostgreSQL process will trigger system calls frequently; we type the following command for the tmpfs directory setup.

```shell
mkdir pg-tmp
sudo mount -t tmpfs -o size=8G tmpfs ./pg-tmp
sudo chown -R user:user ./pg-tmp
```

We initialize the database with the following commands.

```shell
cd pg-tmp
PATH_TO/initdb -D ./
PATH_TO/postgres -D ./
```

The following command creates a database for the benchmark.

```shell
PATH_TO/createdb pgbenchddb
```

The following command initializes the database with the scaling factor of 256.

```shell
PATH_TO/pgbench -i -s 256 pgbenchddb
```

We assign 12 CPU cores out of 16 to PostgreSQL, and pgbench uses the remaining 4 CPU cores to send requests to PostgreSQL over 36 clients using 4 threads.

The pgbench is run by the following command.

```shell
askset -c 12-15 PATH_TO/pgbench -c 36 -j 4 -T 10 pgbenchddb
```

The following command is for the case that does not apply svc-hook.

```shell
taskset -c 0-11 PATH_TO/postgres -D ./
```

The following command is for the case that applies svc-hook.

```shell
LD_PRELOAD=PATH_TO/libsvchook.so taskset -c 0-11 PATH_TO/postgres -D ./
```

When we apply the hook program using svc-hook, the result is 10790 TPS (Transactions Per Second). When the hook program is not applied, the result is 10923 TPS. Here, we have observed a 1.2% performance reduction.
### Samba

We employ Samba version 4.15 and measure the throughput to transfer a 16 GB file between the Samba server and smbclient, which is the client command line tool maintained as part of the Samba suite.

We make a directory ```/smb/share``` and mount tmpfs using the following command. The Samba file server process stores the data in this directory.

```shell
sudo mount -t tmpfs -o size=18G tmpfs /smb/share
```

We make another directory ```./smb-local``` using the following command; smbclient puts data in this directory.

```shell
sudo mount -t tmpfs -o size=18G tmpfs ./smb-local
```

The 16 GB file is generated by the following command.

```shell
dd if=/dev/zero of=./data.img bs=1G count=16
```

For the setting of the server, we add the following lines to ```/etc/samba/smb.conf```.

```conf
[share]
   path = /smb/share
   browseable = yes
   read only = no
   guest ok = yes
```

The following command launches the Samba file server without applying svc-hook.

```shell
sudo /usr/sbin/smbd -i
```

The following command launches the Samba file server while applying svc-hook.

```shell
sudo LD_PRELOAD=PATH_TO/libsvchook.so /usr/sbin/smbd -i
```

For the download experiment, we put the 16 GB file in ```/smb/share``` and copied it to ```./smb-local``` by smbclient's get command.

```shell
$ smbclient //localhost/share -N
smb: \> get data.img PATH_TO/smb-local/data.img
```

For the upload experiment, we put the 16 GB file in ```./smb-local``` and copied it to ```/smb/share``` by smbclient's put command.

```shell
$ smbclient //localhost/share -N
smb: \> put PATH_TO/data.img data.img
```

The following table shows the results. svc-hook reduces throughput by 0.9% and 0.1% for download and upload, respectively.

| Workload       | without svc-hook | with svc-hook |
|----------------|------------------|---------------|
| get (download) | 647 MB/s         | 641 MB/s      |
| put (upload)   | 858 MB/s         | 857 MB/s      |

### Summary

Based on the experimental results above, we consider that the system call hooks applied by svc-hook do not significantly negate the performance of hook-applied application programs.

[sqlite]: https://sqlite.org
[postgresql]: https://www.postgresql.org
[samba]: https://www.samba.org
[sqlite-bench]: https://github.com/ukontainer/sqlite-bench/tree/78e6cdc3d8791c28730f35ba0bd527d34aed2af4
