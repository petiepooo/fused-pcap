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

The directory containing the pcap files to concatenate is specified during mount creation.  Pcaps can also be located within subdirectories of the mountpoint.

Opening pcap files takes the format startfile[..[endfile]]  If no double-dot separator is specified, a single file is processed until EOF.

If a double-dot separator is specified, processing starts on startfile and continues until an error occurs or an end file is specified by writing to the special "..end" file in the same directory.  Whenever a new file appears, presence and content of the virtual ..end file is checked to know whether to end processing then.  If the ..end file has a process id suffix, eg: /mnt/pcap/..end.1234, it only triggers an EOF for that specific process.  This allows several processes to use the same mountpoint (with clustersize==1).  This should not be used on clustersize>1.

If both starting and ending files are specified separated by the double-dot, the two files, along with any pertinent files chronologically between the two, are concatenated.  Pcap file headers are skipped on all files except the first.

Tab completion doesn't seem to be possible when using the double-dot format, as the shell iterates through the directory without giving fuse any indication of what's been typed so far.

If starting and ending files are both specified at open time, actual filesize can be computed and returned by fstat().  If clustersize > 1, it may be larger than what is actually read before EOF is sent.

When ..end is present, the ending file has been processed, and EOF(s) has been sent, the last fully processed file's name will be available at /mnt/pcap/..last.  The next file that would be processed is at /mnt/pcap/..next. If a pid suffix is specified on ..end, it will be present for ..last and ..next as well, eg: /mnt/pcap/..end.1234.

If one process in a cluster ends prematurely, it would normally block all others, as the blocks written would fall behind those being read.  If this is detected (the fd is closed), one of five actions can be taken depending on the clusterabend option setting: 

1. The remaining members continue to receive packets until the end of the current file, at which time they receive an EOF.  ..abend is created containing the pid(s) that closed early.  ..last and ..next contain the file names specified above.
2. The remaining members continue to receive packets until the end of the current file, at which time they receive an EINVAL error.  Special files are created as above
3. The remaining members receive an EOF on next read.  Special files are created as above.
4. The remaminig members receive an EINVAL error on next read.  Special files are created as above.
5. The remaining members continue to receive packets as usual for as long as they would normally (faulted member is simply ignored).

For clustersize==1, reads are just forwarded to the calling process as is.  No parsing takes place.

For clustersize>1, reads are performed by the cluster member that first tries to read a block past what's been previously read.  This works out since it's the furthest ahead and likely the lightest loaded member.  That reader is responsible for reading a block from disk, parsing the packet headers, determining which member should receive it, and adding their packets to the queues.

Packet queues are implemented as linked lists of links carved from a slab of memory.  Links are removed from the head as they're sent to the reading processes, and added to the tail by the parsing cluster member.  Removals are done in a thread-safe manner by the owning member.  The only time mutex protection is needed is when the final link is removed and the head pointer is set to NULL.  The parsing member needs to acquire a mutex on each addition, so will grab the mutex the whole time it's adding links.  This also ensures there are not two members reading and parsing the same portion of the input file.

As a member pulls links off its head, it adds them to the free list head.  This list uses a second next-link pointer so as not to disturb the pointer that the parsing member may be accessing.  The parsing member, on reaching tail, can reap blocks from this list starting with block #2, leaving he first one with the reading member so that it can move blocks from queue to free without a mutex.

###Options:

Read-time options can be specified as preceeding subdirectories, and take precedence over mount-time options, eg: /mnt/pcap/clustersize=6/eth0.pcap.1092933

Mount-time options use the usual -o method, eg: mount.pcap /storage/pcap/eth0 /mnt/pcap/eth0 -o blockslack=16,clustersize=8

open() and mount-time options include:

* clustersize=X - block reads until X processes have connected to and read from the same file (default 1).
* blockslack=X - number of blocks to allow between leading and lagging reads in a cluster (default 2048).
* filesize=X - size of file returned in fstat() call, K, M, G, T, and P suffixes allowed (default 2048P).
* clusterabend=X - how to handle premature closure of cluster member's read handle (1=eof-on-eof, 2=err-on-eof, 3=immed-eof, 4=immed-err, 5=ignore) (default=1).
* clustermode=X - how to distribute packets between cluster members (1=vlan, 2=ip, 3=vlan+ip, 4=ip+port, 5=vlan+ip+port) (default=5).
* keepcache - enables fuse keepcache option
* filematch=STR - filters display of files to those contining STR as a substring within their name (STR cannot contain a comma or slash).

These options show up as special directories under the mountpoint and each real or virtual subdirectory.  Each option appears as the option specifier preceeded by two dots, eg. /mnt/..clustersize=1/eth0.pcap.  This can be used to confirm the existing options, and can also be used to allow differentiation of readers using similar options.

###Potential pitfalls:

* Reading from a file instead of a stream usually means that programs know what size a file is.  We don't, so we'll have to fake it by specifying a really, really large filesize.  To avoid needing to handle seeking within the file, we'll simply disallow it.
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

