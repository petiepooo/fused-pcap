#fused-pcap

####A fuse filesystem that concatenates pcaps in a directory, optionally as they are being created, and optionally split into streams like a PFRING cluster

This is a file-system abstraction layer that concatenates sequential pcap files in a directory such as those written by daemonlogger or gulp.  This allows certain tools such as snort and tshark to use the on-disk full packet capture files as a live (medium latency) source rather than pulling directly from the NIC, theoretically increasing the packet processing rate on commodity hardware.

##HOWTOs

###How to compile:

###How to install:

###How to use:

##Development Notes

###Concepts:

Access is read-only by default.  Read-write support may be added if a valid use case surfaces.

The directory containing the pcap files to concatenate is specified during mount creation.

The pcap file to start with is specified when calling open().

The pcap file to end with is optionally specified when calling open().  The format for that is "actualstartfile..actualendfile" as the filename.  Tab completion doesn't seem to be possible for the range format.

If start and end files are both specified at open time, actual filesize can be computed and returned by fstat().  If clustersize < 1, it will be larger than what is actually read before EOF is sent.

The ending file can also be specified by writing to a virtual file, eg: $echo \* > /mnt/pcap/.end.  This file is checked whenever a new file is poised to be concatenated.

If the .end file has a process id suffix, eg: /mnt/pcap/.end.1234, it only triggers an EOF for that specific process.  This allows several processes to use the same mountpoint (with clustersize=1).  This should not be used on clustersize>1.

When .end is present, the ending file has been processed, and EOF(s) has been sent, the last fully processed file's name will be available at /mnt/pcap/.last.  The next file that would be processed is at /mnt/pcap/.next. If a pid suffix is specified on .end, it will be present for .last and .next as well, eg: /mnt/pcap/.end.1234.

If one process in a cluster ends prematurely, it would normally block all others.  If this is detected (the fd is closed), one of three actions can be taken depending on the clusterabend option setting: 

1. The remaining members continue to receive packets until the end of the current file.  .abend is created containing the pid(s) that closed early.  .last and .next contain the file names specified above.
2. The remaining members receive an EOF on next read.  .abend, .last, and .next are created as above.
3. The remaminig members receive an EINVAL error on next read.  .abend, .last, and .next are created as above.

For clustersize==1, reads are just forwarded to the calling pid as is in large chunks.  No parsing takes place.

For clustersize>1, reads are performed by the cluster member that first tries to read a block past what's been previously read.  This works out since it's the furthest ahead and likely the lightest loaded member.  That reader is responsible for reading a block from disk, parsing the packet headers, determining which member should receive it, and adding the packets to the queues.

Packet queues are implemented as linked lists of slab chunks.  Links are removed from the head as they're sent to the users, and added to the tail by the parsing member.  Removals are done in a thread-safe manner by the owning member.  The only time mutex protection is needed is when the final link is removed and the head pointer is set to NULL.  The parsing member needs to acquire a mutex on each addition, so will grab the mutex the whole time it's adding links.  This also ensures there are not two members reading and parsing the same portion of the input file.

Link structures will be slab allocated so memory isn't thrashed, and so the next link pointer remains valid even after a member removes it from the head.  Since the parsing member would be the only one changing the next pointer, it just needs to ensure it's reached the tail of all lists (thus protected by the mutex) before it makes changes.

As a member pulls links off its head, it adds them to the free list head.  This list uses a second next pointer so as not to disturb the pointer that the parsing member may be accessing.  The parsing member, on reaching tail, can reap blocks from this list starting with block #2, leaving he first one with the reading member.

###Options:

Read-time options can be specified as preceeding subdirectories, and take precedence over mount-time options, eg: /mnt/pcap/clustersize=6/eth0.pcap.1092933

Mount-time options use the usual -o method, eg: mount.pcap /storage/pcap/eth0 /mnt/pcap/eth0 -o blockslack=16,clustersize=8

open() and mount-time options include:

* clustersize=X - block reads until X processes have connected to and read from the same file (default 1).
* blockslack=X - number of blocks to allow between leading and lagging reads in a cluster (default TBD).
* filesize=X - size of file returned in fstat() call, K, M, G, T, and P suffixes allowed (default 512T).
* clusterabend=X - how to handle premature closure of cluster member's read handle (0=err, 1=eof, 2=ignore) (default=0).
* clustermode=X - how to distribute packets between cluster members (0=vlan+ip+port, 1=vlan, 2=ip, 3=vlan+ip, 4=ip+port) (default=0).
* keepcache - enables fuse keepcache option

###Potential pitfalls:

* Reading from a file instead of a stream usually means that programs know what size a file is.  We don't, so we'll have to fake it by specifying a really, really large filesize.  If a program wants to try to lseek() beyond what currently exists, we'll have to return an error.
* We might actually want to make the filesize a realistic value to avoid edge cases due to long long int sign and rollover issues.  To make testing that easier, an (undocumented) option to set the filesize.
* We should handle O_NONBLOCK or O_NDELAY option during open() correctly, returing EAGAIN on read() if appropriate.  I don't know yet how that would work.
* To avoid padding short reads with zeroes, the direct_io option is enabled at all times.

###Development plan:

1. Shell fuse app with access to single file
2. Basic concatenation with end file specified
3. Concatenation with no end file (no clustersize option), equivalent to followdir.
4. Test with several different pcap handling programs, including snort, tcpdump, nprobe, tshark, the tcpreplay suite, (???).
5. Add clustersize options, equivalent to followdir plus pcaptee.
6. Stress test, stress test, and test some more.
7. ...
8. Profit!

##Legalities

###Bugs:

1. Not feature complete.

###License:

fused-pcap is licensed under GPLv2.

###Contributors:

Pete Nelson (concept, lead developer)

