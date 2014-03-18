/*
 * main.c
 * fused-pcap
 *
 * Copyright (C) 2014 Peter Nelson, All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as publised
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * without any warranty, without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU GPL for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, you may write to the Free Software Foundation,
 * Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define FUSE_USE_VERSION	26
#define _FILE_OFFSET_BITS	64

static const char *fusedPcapVersion = "0.0.2a";

#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include <sys/statvfs.h>
#include <errno.h>
//#include <assert.h>
#include <dirent.h>
#include <fuse.h>

// DEFAULT VALUES AND CONSTRAINTS

// range and default slack between slowest and fastest cluster member in blocks
#define DEFAULT_BLOCK_SLACK 2048
#define MIN_BLOCK_SLACK 1
#define MAX_BLOCK_SLACK 1048576

// MAX members in a cluster
#define MAX_CLUSTER_SIZE 32

// default pcap filesize is two exabytes
#define DEFAULT_PCAP_FILESIZE 1024LL * 1024 * 1024 * 1024 * 1024 * 1024 * 2
// minimum is 1, maximum is however much an "off_t" type can hold

// enumerated and default cluster modes
enum {
  CLUSTER_MODE_INVALID,
  CLUSTER_MODE_VLAN,
  CLUSTER_MODE_IP,
  CLUSTER_MODE_VLAN_IP,
  CLUSTER_MODE_IP_PORT,
  CLUSTER_MODE_VLAN_IP_PORT
};
#define DEFAULT_CLUSTER_MODE CLUSTER_MODE_VLAN_IP_PORT

// enumerated and default cluster abnormal end behaviors
enum {
  CLUSTER_ABEND_INVALID,
  CLUSTER_ABEND_EOF_ALL_AT_EOF,
  CLUSTER_ABEND_ERR_ALL_AT_EOF,
  CLUSTER_ABEND_IMMEDIATE_EOF_ALL,
  CLUSTER_ABEND_IMMEDIATE_ERROR_ALL,
  CLUSTER_ABEND_IGNORE
};
#define DEFAULT_CLUSTER_ABEND CLUSTER_ABEND_EOF_ALL_AT_EOF

// GLOBAL STRUCTURES

static struct {
  char pcapDirectory[PATH_MAX + 1];
  char mountDirectory[PATH_MAX + 1];
  int debug;
} fusedPcapGlobal;

static struct fusedPcapConfig_s {
  off_t filesize;
  int clustersize;
  int clustermode;
  int clusterabend;
  int blockslack;
} fusedPcapConfig;

// SUPPORT FUNCTIONS

static void printConfigStruct(struct fusedPcapConfig_s *config)
{
  fprintf(stderr, "  %s: 0x%016llx\n  %s: %d  %s: %d\n  %s: %d  %s: %d\n",
          "filesize", (long long int) config->filesize,
          "clustersize", config->clustersize,
          "clusterabend", config->clusterabend,
          "clustermode", config->clustermode,
          "blockslack", config->blockslack);
}

static int convertValidateFilesize(off_t *size /*output*/, const char *input)
{
  const char *suffix;

  if (input == NULL)
    *size = DEFAULT_PCAP_FILESIZE;
  else {
    off_t multiplier;

    suffix = input;
    while (isdigit(suffix[0]))
      suffix++;
    switch (suffix[0]) {
    case '\0':
    case '/':
      multiplier = 1ll;
      break;
    case 'K':
    case 'k':
      multiplier = 1024ll;
      break;
    case 'M':
    case 'm':
      multiplier = 1024ll * 1024;
      break;
    case 'G':
    case 'g':
      multiplier = 1024ll * 1024 * 1024;
      break;
    case 'T':
    case 't':
      multiplier = 1024ll * 1024 * 1024 * 1024;
      break;
    case 'P':
    case 'p':
      multiplier = 1024ll * 1024 * 1024 * 1024 * 1024;
      break;
    default:
      return 1;
      break;
    }

    *size = atoll(input) * multiplier;
    if (*size < multiplier)
      return 1;
    if (fusedPcapGlobal.debug) {
      char value[32];
      memset(value, '\0', 32);
      strncpy(value, input, strchr(input, '/') ? (strchr(input, '/') - input) & 31ll : 31);
      fprintf(stderr, "FUSED_PCAP_OPT: filesize=%s (0x%016llx)\n", value, (long long int)*size);
    }
  }
  return 0;
}

static int convertValidateClustersize(int *size /*output*/, const char *input)
{
  if (input == 0)
    *size = 1;
  else {
    *size = atoi(input);
    if (*size < 1 || *size > MAX_CLUSTER_SIZE)
      return 1;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: clustersize=%d\n", *size);
  }
  return 0;
}

static int convertValidateClustermode(int *mode /*output*/, const char *input)
{
  if (input == 0)
    *mode = DEFAULT_CLUSTER_MODE;
  else {
    *mode = atoi(input);
    if (*mode < CLUSTER_MODE_VLAN || *mode > CLUSTER_MODE_VLAN_IP_PORT)
      return 1;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: clustermode=%d\n", *mode);
  }
  return 0;
}

static int convertValidateClusterabend(int *action /*output*/, const char *input)
{
  if (input == 0)
    *action = DEFAULT_CLUSTER_ABEND;
  else {
    *action = atoi(input);
    if (*action < CLUSTER_ABEND_EOF_ALL_AT_EOF || *action > CLUSTER_ABEND_IGNORE)
      return 1;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: clusterabend=%d\n", *action);
  }
  return 0;
}

static int convertValidateBlockslack(int *slack /*output*/, const char *input)
{
  if (input == 0)
    *slack = DEFAULT_BLOCK_SLACK;
  else {
    *slack = atoi(input);
    if (*slack < MIN_BLOCK_SLACK || *slack > MAX_BLOCK_SLACK)
      return 1;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: blockslack=%d\n", *slack);
  }
  return 0;
}

static int reapConfigDirs(const char *path, char **shortPath, struct fusedPcapConfig_s *fileConfig)
{
  *shortPath = (char *)path;
  memcpy(fileConfig, &fusedPcapConfig, sizeof(struct fusedPcapConfig_s));
  if (path == NULL || path[0] != '/')
    return 1;
  while (*shortPath) {
    if (strncmp("/filesize=", *shortPath, 10) == 0) {
      *shortPath += 10;
      if (convertValidateFilesize(&fileConfig->filesize, *shortPath))
        return 1;
      *shortPath = strchr(*shortPath, '/');
      continue;
    }
    if (strncmp("/blockslack=", *shortPath, 12) == 0) {
      *shortPath += 12;
      if (convertValidateBlockslack(&fileConfig->blockslack, *shortPath))
        return 1;
      *shortPath = strchr(*shortPath, '/');
      continue;
    }
    if (strncmp("/cluster", *shortPath, 8) == 0) {
      if (strncmp("size=", *shortPath + 8, 5) == 0) {
        *shortPath += 13;
        if (convertValidateClustersize(&fileConfig->clustersize, *shortPath))
          return 1;
        *shortPath = strchr(*shortPath, '/');
        continue;
      }
      if (strncmp("mode=", *shortPath + 8, 5) == 0) {
        *shortPath += 13;
        if (convertValidateClustermode(&fileConfig->clustermode, *shortPath))
          return 1;
        *shortPath = strchr(*shortPath, '/');
        continue;
      }
      if (strncmp("abend=",* shortPath + 8, 6) == 0) {
        *shortPath += 14;
        if (convertValidateClusterabend(&fileConfig->clusterabend, *shortPath))
          return 1;
        *shortPath = strchr(*shortPath, '/');
        continue;
      }
    }
    break;
  }
  return 0;
}

static int isSpecialFile(const char *path)
{
  if (strncmp("..", path, 2) == 0)
    if ((strncmp("status", path + 2, 6) == 0) ||
        (strncmp("last", path + 2, 4) == 0) ||
        (strncmp("next", path + 2, 4) == 0))
      return 1;
  return 0;
}

static int separateEndingFile(char **fullPath, char **firstFile)
{
  char *delimiter;

  delimiter = strstr(*fullPath, "..");
  if (delimiter) {
    //NOTE: this will break if there are actual subdirectories under the mountpoint
    *delimiter++ = '\0';
    *delimiter = '/';
    if (firstFile != NULL) {
      if (firstFile != fullPath) {
        //fullPath points toward end, first toward first
        *firstFile = *fullPath;
        *fullPath = delimiter;
      }
      //unless they're the same, where end file is just truncated
    }
    else
      //if firstFile isn't given, just endfile is returned
      *fullPath = delimiter;
    return 1;
  }
  return 0;
}

static int fused_pcap_getattr(const char *path, struct stat *stData)
{
  char mountPath[PATH_MAX + 1];
  struct fusedPcapConfig_s fileConfig;
  char *shortPath;

  //TODO:
  if (isSpecialFile(path)) {
    //return the file's stData
  }

  //first time calling, build cache entry
  if (reapConfigDirs(path, &shortPath, &fileConfig))
    return -ENOENT;
  if (fusedPcapGlobal.debug)
    printConfigStruct(&fileConfig);

  separateEndingFile(&shortPath, &shortPath);

  if (! shortPath)
    shortPath = "/";
  snprintf(mountPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, shortPath);

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "getattr calling stat for %s\n", mountPath);
  if (stat(mountPath, stData) == -1) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "stat returned error\n");
    return -errno;
  }

  //TODO:
  //stData->st_size = fusedPcapConfig.filesize;
  //if (endFile)
    //stData->st_size = computeFilesize(mountPath, endFile);

  return 0;
}

static int fused_pcap_readlink(const char *path, char *buffer, size_t size)
{
  //TODO: finish
  (void)path;
  (void)buffer;
  (void)size;
  return -EROFS;
}

static int fused_pcap_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fileInfo)
{
  char mountPath[PATH_MAX + 1];
  struct fusedPcapConfig_s fileConfig;
  char *shortPath;
  //char *endFile;
  DIR *directory;
  struct dirent *entry;
  struct stat status;

  (void)offset;
  (void)fileInfo;

  if (reapConfigDirs(path, &shortPath, &fileConfig))
    return -ENOENT;
  if (fusedPcapGlobal.debug)
    printConfigStruct(&fileConfig);

  if (! shortPath)
    shortPath = "/";
  snprintf(mountPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, shortPath);

  directory = opendir(mountPath);
  if (directory == NULL)
    return -errno;

  while ((entry = readdir(directory)) != NULL) {
    memset(&status, 0, sizeof(struct stat));
    status.st_ino = entry->d_ino;
    status.st_mode = entry->d_type << 12;
    if (filler(buffer, entry->d_name, &status, 0))
      break;
  }

  closedir(directory);

  //add special files
  //memset(&status, 0, sizeof(struct stat));
  //status.st_ino = 999990;
  //status.st_mode = S_IRUSR | S_IRGRP | S_IROTH;
  //filler(buffer, "..status",  &status, 0);
  //if (fileIsOpen(mountPath))
    //filler(buffer, "..pids", &status, 0);

  return 0;
}

static int fused_pcap_create(const char *path, mode_t mode, struct fuse_file_info *fileInfo)
{
  (void)path;
  (void)mode;
  (void)fileInfo;
  return -EROFS;
}

static int fused_pcap_mknod(const char *path, mode_t mode, dev_t rdev)
{
  (void)path;
  (void)mode;
  (void)rdev;
  return -EROFS;
}

static int fused_pcap_mkdir(const char *path, mode_t mode)
{
  (void)path;
  (void)mode;
  return -EROFS;
}

static int fused_pcap_unlink(const char *path)
{
  (void)path;
  return -EROFS;
}

static int fused_pcap_rmdir(const char *path)
{
  (void)path;
  return -EROFS;
}

static int fused_pcap_symlink(const char *from, const char *to)
{
  (void)from;
  (void)to;
  return -EROFS;
}

static int fused_pcap_rename(const char *from, const char *to)
{
  (void)from;
  (void)to;
  return -EROFS;
}

static int fused_pcap_link(const char *from, const char *to)
{
  (void)from;
  (void)to;
  return -EROFS;
}

static int fused_pcap_chmod(const char *path, mode_t mode)
{
  (void)path;
  (void)mode;
  return -EROFS;
}

static int fused_pcap_chown(const char *path, uid_t uid, gid_t gid)
{
  (void)path;
  (void)uid;
  (void)gid;
  return -EROFS;
}

static int fused_pcap_truncate(const char *path, off_t size)
{
  (void)path;
  (void)size;
  return -EROFS;
}

static int fused_pcap_utimens(const char *path, const struct timespec timeSpec[2])
{
  (void)path;
  (void)timeSpec;
  return -EROFS;
}

static int fused_pcap_open(const char *path, struct fuse_file_info *fileInfo)
{
  char mountPath[PATH_MAX + 1];
  struct fusedPcapConfig_s fileConfig;
  char *shortPath;
  int ret;
  
  if (isSpecialFile(path)) {
    //return the file's fd
  }

  if (reapConfigDirs(path, &shortPath, &fileConfig))
    return -ENOENT;
  if (fusedPcapGlobal.debug)
    printConfigStruct(&fileConfig);

  if (! shortPath)
    shortPath = "/";
  snprintf(mountPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, shortPath);

  //TODO: check fileInfo->flags for inappropriate values

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "open calling open for %s\n", mountPath);
  ret = open(mountPath, fileInfo->flags);
  if (ret == -1)
    return -errno;

  //TODO: create new per-fh entry in array, store in fileInfo->fh_old
  //allocate a new fileEntry
  //memcpy(fileEntry->fileConfig, fileConfig, sizeof(struct fusedPcapConfig_t));
  //strdup(fileEntry->shortPath, shortPath);
  //strdup(fileEntry->fusePath, path);
  //fileEntry->flags = fileInfo->flags;
  //fileEntry->inputOffset = 0;
  //fileEntry->readOffset = 0;
  //fileEntry->fd = ret;
  //if (fileConfig.clustersize > 1)
    //find (or populate) clusterIndex
    //fileEntry->clusterIndex = clusterIndex;
    //clusterMember = determine which member this fh will be
    //fileEntry->clusterMember = clusterMember;
    //clusterIndex->member[clusterMember] = fileEntry;
    //trip event
  //fileInfo->fh = (uint64_t)fileEntry;

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "fd %x stored in fuse_file_info for %s\n", ret, mountPath);
  fileInfo->fh = ret;
  return 0;
}

static int fused_pcap_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
  off_t offRes;
  ssize_t sizeRes;

  //TODO: finish

  //fileEntry = (struct fileEntry_t *)fileInfo->fh;
  //if (fileEntry->readOffset != offset)
    //ERROR? not a sequential read

  //if (fileEntry->abortEof) {
    //if (fusedPcapGlobal.debug)
      //fprintf(stderr, "aborting cluster member %d before read with EOF\n", fileEntry->clusterMember);
    //fileEntry->fileConfig.fileSize = fileEntry->fileConfig.readOffset;
    //fileEntry->normalEnding = 1;
    //return 0;
  //}
  //if (fileEntry->abortErr) {
    //if (fusedPcapGlobal.debug)
      //fprintf(stderr, "aborting cluster member %d before read with ENOENT\n", fileEntry->clusterMember);
    //fileEntry->normalEnding = 1;
    //return -ENOENT;  //is this the right error?
  //}

  //clustersize = fileEntry->fileConfig.clustersize;
  //if (clustersize > 1) {
    //clusterIndex = fileEntry->clusterIndex;

    //if (! clusterIndex->fullyPopulated) {
      //do {
        //for (i=0; i<clustersize; i++) {
          //if (clusterIndex->member[i] == NULL) {
            //if (non-blocking)
              //return -EAGAIN;
            //else
              //break;
          //}
        //}
        //if (i == clustersize) {
          //clusterIndex->fullyPopulated = 1;
          //break;
        //}
      //} while (wait for next open event, blocking this read)
    //}

    //do (
      //for (i=0; i<clustersize; i++) (
        //if (clusterIndex->member[i] == NULL) {
          //if (clusterIndex->member[i]->readOffset too far behind) {
            //set cluster member to trigger read event (race condition between setting trigger and blocking?)
            //if (non-blocking)
              //return -EAGAIN;
            //else
              //break;
          //}
        //}
      //}
      //if (i == clustersize)
        //break;
    //} while (wait for next read event, blocking this read)
  //}
  
  //offRes = lseek(fileEntry->fd, fileEntry->inputOffset, SEEK_SET);
  offRes = lseek(fileInfo->fh, offset, SEEK_SET);
  if (offRes != offset)
    return -errno;

  //sizeRes = read(fileEntry->fd, buffer, size);
  sizeRes = read(fileInfo->fh, buffer, size);
  if (sizeRes == -1)
    return -errno;
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "read returned %lli\n", (long long int) sizeRes);

  if (sizeRes == 0) {
    // at end of cuurent file. 
    //is this lastFile?
      //fileEntry->normalEnding = 1;
      //fileEntry->abortEof = 1;
      //fileEntry->fileConfig.fileSize = fileEntry->fileConfig.readOffset;
      return 0;
    //if (is the next one ready?) {
      //close(fileEntry->fd);
      //fileEntry->fd = NULL;
      //if (fileEntry->fileEndEof) {
        //if (fusedPcapGlobal.debug)
          //fprintf(stderr, "setting cluster member %d to abort before next read with EOF\n", fileEntry->clusterMember);
        //fileEntry->abortEof = 1;
      //}
      //else if (fileEntry->fileEndErr) {
        //if (fusedPcapGlobal.debug)
          //fprintf(stderr, "setting cluster member %d to abort before next read with an error\n", fileEntry->clusterMember);
        //fileEntry->abortErr = 1;
      //}
      //else {
        //fileEntry->fd = open(nextFilePath, fileEntry->flags);
        //fileEntry->inputOffset
      //}
    //}
    //else {
      //if (! non-blocking)
        //block until more available //TODO: figure out how to determine more is available
      // return -EAGAIN
    //}
  }
  else {
    //fileEntry->readOffset += sizeRes;
    //fileEntry->inputOffset += sizeRes;
    return sizeRes;
  }
}

static int fused_pcap_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
  (void)path;
  (void)buffer;
  (void)size;
  (void)offset;
  (void)fileInfo;
  return -EROFS;
}

static int fused_pcap_statfs(const char *path, struct statvfs *status)
{
  (void)path;
  (void)status;
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "receiving statfs for %s\n", path);
  if (statvfs(fusedPcapGlobal.pcapDirectory, status) != 0)
    return -errno;
  status->f_blocks = status->f_blocks - status->f_bfree;
  status->f_bfree = status->f_bavail = 0;
  return 0;
}

static int fused_pcap_release(const char *path, struct fuse_file_info *fileInfo)
{
  int ret;

  //TODO: finish
  (void)path;
  //fileEntry = (struct fileEntry_t *)fileInfo->fh;
  //if (fileEntry->fd)
    //ret = close(fileEntry->fd);
  //if (! fileEntry->normalEnding)
    //for (each fileEntry structure in the cluster) {
      //switch (fileEntry->config.clusterabend) {
      //case CLUSTER_ABEND_EOF_ALL_AT_EOF:
        //fileEntry->fileEndEof = 1;
        //break;
      //case CLUSTER_ABEND_ERR_ALL_AT_EOF:
        //fileEntry->fileEndEof = 1;
        //break;
      //case CLUSTER_ABEND_IMMEDIATE_EOF_ALL:
        //fileEntry->abortEof = 1;
        //break;
      //case CLUSTER_ABEND_IMMEDIATE_ERROR_ALL:
        //fileEntry->abortErr = 1;
        //break;
      //case CLUSTER_ABEND_IGNORE:
        //break;
      //};
    //};
  //};
  //remove fileEntry from cluster index;
  //if (last fileEntry in clusterIndex)
    //clear clusterIndex
  //free(fileEntry);
  ret = close(fileInfo->fh);
  if (ret == -1)
    return -errno;
  return ret;
}

static int fused_pcap_fsync(const char *path, int dummy, struct fuse_file_info *fileInfo)
{
  (void)path;
  (void)dummy;
  (void)fileInfo;
  return -EROFS;
}

static int fused_pcap_access(const char *path, int mode)
{
  char mountPath[PATH_MAX + 1];
  struct fusedPcapConfig_s fileConfig;
  char *shortPath;
  //char *endFile;

  //TODO:
  if (isSpecialFile(path)) {
    //return the file's stData
  }
  //if (isInCache(path)
    //return the cached stData

  if (reapConfigDirs(path, &shortPath, &fileConfig))
    return -ENOENT;
  if (fusedPcapGlobal.debug)
    printConfigStruct(&fileConfig);

  if (! shortPath)
    shortPath = "/";
  snprintf(mountPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, shortPath);

  if (access(mountPath, mode) == -1)
    return -errno;

  return 0;
}

#ifdef HAVE_SETXATTR
static int fused_pcap_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
  (void)path;
  (void)name;
  (void)value;
  (void)flags;
  return -EROFS;
}

static int fused_pcap_getxattr(const char *path, const char *name, char *value, size_t size)
{
  char mountPath[PATH_MAX + 1];
  struct fusedPcapConfig_s fileConfig;
  char *shortPath;
  //char *endFile;
  int response;

  (void)name;
  (void)value;
  (void)size;

  if (reapConfigDirs(path, &shortPath, &fileConfig))
    return -ENOENT;
  if (fusedPcapGlobal.debug)
    printConfigStruct(&fileConfig);

  if (isSpecialFile(shortPath))
    return 0;  // extended attributes are not aupported on virtual files

  separateEndingFile(&shortPath, &shortPath);

  if (! shortPath)
    shortPath = "/";
  snprintf(mountPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, shortPath);

  response = lgetxattr(mountPath, name, value, size);
  if (response == -1)
    return -errno;
  return response;
}

static int fused_pcap_listxattr(const char *path, char *list, size_t size)
{
  //TODO: finish
  (void)path;
  (void)list;
  (void)size;
  return -EROFS;
}

static int fused_pcap_removexattr(const char *path, const char *name)
{
  (void)path;
  (void)name;
  return -EROFS;
}
#endif


struct fuse_operations callbackOperations = {
  .getattr     = fused_pcap_getattr,
  .access      = fused_pcap_access,
  .readlink    = fused_pcap_readlink,
  .readdir     = fused_pcap_readdir,
  .create      = fused_pcap_create,
  .mknod       = fused_pcap_mknod,
  .mkdir       = fused_pcap_mkdir,
  .symlink     = fused_pcap_symlink,
  .unlink      = fused_pcap_unlink,
  .rmdir       = fused_pcap_rmdir,
  .rename      = fused_pcap_rename,
  .link        = fused_pcap_link,
  .chmod       = fused_pcap_chmod,
  .chown       = fused_pcap_chown,
  .truncate    = fused_pcap_truncate,
  .utimens     = fused_pcap_utimens,
  .open        = fused_pcap_open,
  .read        = fused_pcap_read,
  .write       = fused_pcap_write,
  .statfs      = fused_pcap_statfs,
  .release     = fused_pcap_release,
  .fsync       = fused_pcap_fsync,
#ifdef HAVE_SETXATTR
  .setxattr    = fused_pcap_setxattr,
  .getxattr    = fused_pcap_getxattr,
  .listxattr   = fused_pcap_listxattr,
  .removexattr = fused_pcap_removexattr,
#endif
};

static void usage(const char *progname)
{
  fprintf(stdout,
"Usage: %s [-h | -v | -o opt[,opt[...]] pcapdirpath mountpoint\n"
"\n"
"%s options:\n"
"    -o filesize=N          set size of file returned in fstat() call, K, M, G, T, and P suffixes allowed (default 2048P)\n"
"    -o clustersize=N       block reads until N processes have connected to and read from the same file (default 1)\n"
"    -o clustermode=N       set distribution of packets to cluster members (1=vlan, 2=ip, 3=vlan+ip, 4=ip+port, 5=vlan+ip+port) (default=5)\n"
"    -o clusterabend=N      set handling of premature closure of a member's read handle (1=eof, 2=err, 3=imm_eof, 4-imm_err, 5=ign) (default=1)\n"
"    -o blockslack=N        set number of blocks to allow between leading and lagging reads in a cluster (default 2048)\n"
"\n", progname, progname);
}

// OPTION HANDLING

enum {
  FUSED_PCAP_OPT_KEY_HELP,
  FUSED_PCAP_OPT_KEY_VERSION,
  FUSED_PCAP_OPT_KEY_DEBUG,
};

struct fusedPcapInputs_s {
  char *filesize;
  char *clustermode;
  char *clusterabend;
  char *clustersize;
  char *blockslack;
  int help;
} fusedPcapInputs;

#define FUSED_PCAP_OPT(t, p, v) { t, offsetof(struct fusedPcapInputs_s, p), v }

static struct fuse_opt fusedPcapOptions[] = {
  FUSED_PCAP_OPT("filesize=%s",     filesize,     0),
  FUSED_PCAP_OPT("clustermode=%s",  clustermode,  0),
  FUSED_PCAP_OPT("clustersize=%s",  clustersize,  0),
  FUSED_PCAP_OPT("clusterabend=%s", clusterabend, 0),
  FUSED_PCAP_OPT("blockslack=%s",   blockslack,   0),

  FUSE_OPT_KEY("-h",        FUSED_PCAP_OPT_KEY_HELP),
  FUSE_OPT_KEY("--help",    FUSED_PCAP_OPT_KEY_HELP),
  FUSE_OPT_KEY("-v",        FUSED_PCAP_OPT_KEY_VERSION),
  FUSE_OPT_KEY("--version", FUSED_PCAP_OPT_KEY_VERSION),
  FUSE_OPT_KEY("debug",     FUSED_PCAP_OPT_KEY_DEBUG),
  FUSE_OPT_KEY("-d",        FUSED_PCAP_OPT_KEY_DEBUG),

  FUSE_OPT_END
};

static int parseMountOptions(void *data, const char *arg, int key, struct fuse_args *arguments)
{
  switch (key) {
  case FUSE_OPT_KEY_NONOPT:
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSE_PARAM: %s\n", arg);
    if (fusedPcapGlobal.pcapDirectory[0] == '\0') {
      realpath(arg, fusedPcapGlobal.pcapDirectory);
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "normalized to %s\n", fusedPcapGlobal.pcapDirectory);
      return 0;
    }
    else if (fusedPcapGlobal.mountDirectory[0] == '\0') {
      strncpy(fusedPcapGlobal.mountDirectory, arg, PATH_MAX);
      return 1;
    }
    else {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "(parameter %s ignored)\n", arg);
      return 0;
    }
    break;
  case FUSE_OPT_KEY_OPT:
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSE_OPT: %s\n", arg);
    break;
  case FUSED_PCAP_OPT_KEY_HELP:
    fusedPcapInputs.help = 1;
    usage(basename(arguments->argv[0]));
    return fuse_opt_add_arg(arguments, "-ho");
  case FUSED_PCAP_OPT_KEY_VERSION:
    fprintf(stdout, "%s version %s\n", basename(arguments->argv[0]), fusedPcapVersion);
    exit(0);
  case FUSED_PCAP_OPT_KEY_DEBUG:
    fusedPcapGlobal.debug = 1;
    fprintf(stderr, "FUSE_OPT: %s, debug enabled\n", arg);
    break;
  default:
    usage(arguments->argv[0]);
    exit(1);
  }
  return 1;
}

int main (int argc, char *argv[])
{
  struct fuse_args fuseArgs = FUSE_ARGS_INIT(argc, argv);
  //struct fuse_args moreArgs = FUSE_ARGS_INIT(0, NULL);

  if ((fuse_opt_parse(&fuseArgs, &fusedPcapInputs, fusedPcapOptions, parseMountOptions)) == -1) {
    fprintf(stderr, "%s: invalid arguments\n", argv[0]);
    return 1;
  }
  if (!fusedPcapInputs.help)
  {

    //TODO: add read-only option if needed
    //fuse_opt_add_arg (&moreArgs, "-oro");
    //fuse_opt_parse(&moreArgs, &fusedPcapConfig, fusedPcapOptions, parseMountOptions);

    // convert and validate options
    if (convertValidateFilesize(&fusedPcapConfig.filesize, fusedPcapInputs.filesize)) {
      fprintf(stderr, "%s: filesize option out of range (1..2^63-1)\n", argv[0]);
      if (fusedPcapConfig.filesize != 0 && fusedPcapInputs.filesize[0] != '-')
        fprintf(stderr, "Congratulations! you overflowed a 64-bit integer.\n");
      return 1;
    }
    if (convertValidateClustermode(&fusedPcapConfig.clustermode, fusedPcapInputs.clustermode)) {
      fprintf(stderr, "%s: clustermode option out of range (%d..%d)\n", argv[0], CLUSTER_MODE_VLAN, CLUSTER_MODE_VLAN_IP_PORT);
      return 1;
    }
    if (convertValidateClustersize(&fusedPcapConfig.clustersize, fusedPcapInputs.clustersize)) {
      fprintf(stderr, "%s: clustersize option out of range (1..%d)\n", argv[0], MAX_CLUSTER_SIZE);
      return 1;
    }
    if (convertValidateClusterabend(&fusedPcapConfig.clusterabend, fusedPcapInputs.clusterabend)) {
      fprintf(stderr, "%s: clusterabend option out of range (%d..%d)\n", argv[0], CLUSTER_ABEND_EOF_ALL_AT_EOF, CLUSTER_ABEND_IGNORE);
      return 1;
    }
    if (convertValidateBlockslack(&fusedPcapConfig.blockslack, fusedPcapInputs.blockslack)) {
      fprintf(stderr, "%s: blockslack option out of range (%d..%d)\n", argv[0], MIN_BLOCK_SLACK, MAX_BLOCK_SLACK);
      return 1;
    }

    if (fusedPcapGlobal.pcapDirectory[0] == '\0') {
      fprintf(stderr, "%s: missing pcap source directory\n", argv[0]);
      return 1;
    }

    //TODO: validate source directory parameter

    if (fusedPcapGlobal.debug) {
      printConfigStruct(&fusedPcapConfig);
      fprintf(stderr, "Parameters validated, calling fuse_main()\n");
    }
  }

#if FUSE_VERSION >= 26
  return fuse_main(fuseArgs.argc, fuseArgs.argv, &callbackOperations, NULL);
#else
  return fuse_main(fuseArgs.argc, fuseArgs.argv, &callbackOperations);
#endif
}



