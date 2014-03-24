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

static const char *fusedPcapVersion = "0.0.4a";

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
#include <pthread.h>
#include <syslog.h>
#include <fuse.h>

// DEFAULT VALUES AND CONSTRAINTS

// range and default slack between slowest and fastest cluster member in blocks
#define DEFAULT_BLOCK_SLACK 2048
#define MIN_BLOCK_SLACK 1
#define MAX_BLOCK_SLACK 1048576

// MAX members in a cluster
#define MAX_CLUSTER_SIZE 32
#define MAX_NUM_CLUSTERS 4

// number of linked linst nodes to add when exhausted
#define SLAB_ALLOC_COUNT 32

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

static struct fusedPcapGlobal_s {
  char pcapDirectory[PATH_MAX + 1];
  char mountDirectory[PATH_MAX + 1];
  int debug;
  long pageSize;
} fusedPcapGlobal;

static struct fusedPcapConfig_s {
  off_t filesize;
  int clustersize;
  int clustermode;
  int clusterabend;
  int blockslack;
  int keepcache;
} fusedPcapConfig;

// this mutex protects reads from the file into the cluster queue
pthread_mutex_t readqueueMutex = PTHREAD_MUTEX_INITIALIZER;

struct packet_link_s {
  char *buffer;
  int size;
  struct packet_link_s *next;
  struct packet_link_s *free;
};

static struct fusedPcapCluster_s {
  struct fusedPcapConfig_s config;
  char *shortPath;
  struct fusedPcapInstance_s *instance[MAX_CLUSTER_SIZE];
  struct packet_link_s *free;
  struct packet_link_s *slabs;
  //bitfields
  uint32_t fullyPopulated: 1;
} fusedPcapClusters[MAX_NUM_CLUSTERS];

// this mutex protects the array below; pid indicates whether an entry is free or not.
pthread_mutex_t instanceMutex = PTHREAD_MUTEX_INITIALIZER;

struct fusedPcapDirectory_s {
  char *shortPath; // allocated with strdup; must be freed when pid cleared
  DIR *fd;
  struct fusedPcapConfig_s config;
}; 

static struct fusedPcapInstance_s {
  off_t readOffset;
  off_t outputOffset;
  struct packet_link_s *queue;
  struct packet_link_s *free;
  struct fusedPcapCluster_s *cluster;
  char *shortPath; // allocated with strdup; must be freed when pid cleared
  char *readFile;  // allocated with strdup; must be freed when file closed
  int member;
  int fd;
  pid_t pid;
  struct fusedPcapConfig_s config;
  struct stat stData;
  char endFile[PATH_MAX + 1];
  // bitfields
  union {
    uint32_t bits;
    struct {
      uint32_t clusterMember: 5;
      uint32_t padding: 3;
      uint32_t normalEnding: 1;
      uint32_t fileEndEof: 1;
      uint32_t fileEndErr: 1;
      uint32_t abortEof: 1;
      uint32_t abortErr: 1;
      uint32_t reserved: 19;
    };
  };
} fusedPcapInstances[MAX_CLUSTER_SIZE];

// SUPPORT FUNCTIONS

static void printConfigStruct(struct fusedPcapConfig_s *config)
{
  fprintf(stderr, "  %s: 0x%016llx\n  %s: %d  %s: %d\n  %s: %d  %s: %d  %s\n",
          "filesize", (long long int) config->filesize,
          "clustersize", config->clustersize,
          "clusterabend", config->clusterabend,
          "clustermode", config->clustermode,
          "blockslack", config->blockslack,
          config->keepcache ? "keepcache: 1" : "");
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
      if (strncmp("abend=", *shortPath + 8, 6) == 0) {
        *shortPath += 14;
        if (convertValidateClusterabend(&fileConfig->clusterabend, *shortPath))
          return 1;
        *shortPath = strchr(*shortPath, '/');
        continue;
      }
    }
    if (strncmp("/keepcache", *shortPath, 10) == 0) {
      *shortPath += 1;
      fileConfig->keepcache = 1;
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "FUSED_PCAP_OPT: keepcache\n");
      *shortPath = strchr(*shortPath, '/');
      continue;
    }
    break;
  }
  return 0;
}

static int isOptionDir(const char *path)
{
  if (strncmp("/..", path, 3) == 0)
    if ((strncmp("filesize=", path + 3, 9) == 0) ||
        (strncmp("clustersize=", path + 3, 12) == 0) ||
        (strncmp("clustermode=", path + 3, 12) == 0) ||
        (strncmp("clusterabend=", path + 3, 13) == 0) ||
        (strncmp("blockslack=", path + 3, 11) == 0) ||
        (strncmp("keepcache", path + 3, 9) == 0))
      return 1;
  return 0;
}

static int isSpecialFile(const char *path)
{
  if (strncmp("/..", path, 3) == 0)
    if ((strncmp("status", path + 3, 6) == 0) ||
        (strncmp("last", path + 3, 4) == 0) ||
        (strncmp("next", path + 3, 4) == 0))
      return 1;
  return isOptionDir(path);;
}

//NOTE: this function modifies the string in fullPath if it finds a ".." delimiter
static int separateEndingFile(char **fullPath, char **endFile)
{
  char *delimiter;

  if (! *fullPath)
    return 0;

  delimiter = strstr(*fullPath, "..");
  if (delimiter) {
    //NOTE: this will break if there are actual subdirectories under the mountpoint
    *delimiter++ = '\0';
    *delimiter = '/';
    if (endFile != NULL && endFile != fullPath)
      *endFile = delimiter;
    return 1;
  }
  return 0;
}

static struct fusedPcapInstance_s *populateInstance(const char *shortPath, struct fusedPcapConfig_s *config)
{
  struct fuse_context *context;
  struct fusedPcapInstance_s *instance;
  struct fusedPcapCluster_s *cluster;
  struct packet_link_s *next;
  int i;

  cluster = NULL;
  context = fuse_get_context();

  //need to protect fusedPcapInstances array allocation with mutex
  pthread_mutex_lock(&instanceMutex);
  for (i=0; i<MAX_CLUSTER_SIZE; i++)
    if (fusedPcapInstances[i].pid == 0)
      break;
  if (i == MAX_CLUSTER_SIZE)
    return NULL;
  instance = &fusedPcapInstances[i];
  instance->pid = context->pid;
  //once pid is non-zero, other threads will skip the entry, so release mutex
  pthread_mutex_unlock(&instanceMutex);
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "populating %p instance struct for %s [%d]\n", instance, shortPath, context->pid);

  //NOTE: if strdup fails, this is set to NULL; always verify before dereferencing
  //readFile populated by caller
  //fd populated by caller
  instance->readOffset = 0ll;
  instance->outputOffset = 0ll;
  instance->endFile[0] = '\0';
  memcpy(&instance->config, config, sizeof(struct fusedPcapConfig_s));
  //stData cached by caller
  instance->bits = 0;
  if (config->clustersize == 1) {
    instance->shortPath = strdup(shortPath);
  }
  else {
    pthread_mutex_lock(&readqueueMutex);
    for (i=0; i<MAX_NUM_CLUSTERS; i++) {
      cluster = &fusedPcapClusters[i];
      if (cluster->shortPath &&
          strcmp(cluster->shortPath, shortPath) == 0 &&cluster->shortPath &&
          memcmp(&cluster->config, config, sizeof(struct fusedPcapConfig_s)) == 0)
        break;
    }
    if (i < MAX_NUM_CLUSTERS) {  // found a matching shortPath and config
      cluster = &fusedPcapClusters[i];
      for (i=0; i<config->clustersize; i++)
        if (cluster->instance[i] == NULL)
          break;
      if (i < config->clustersize) {
        if (fusedPcapGlobal.debug)
          fprintf(stderr, "joining instance %p to cluster %p as member %d\n", instance, cluster, i);
        instance->cluster = cluster;
        instance->member = i;
        instance->shortPath = cluster->shortPath;
        cluster->instance[i] = instance; // last change for thread safety
        if (i + 1 == config->clustersize)
          cluster->fullyPopulated = 1;
      }
      // otherwise, clean up and return NULL
    }
    else {
      for (i=0; i<MAX_NUM_CLUSTERS; i++)
        if (fusedPcapClusters[i].shortPath == NULL)
          break;
      if (i < MAX_NUM_CLUSTERS) {  // found a free cluster offset
        if (fusedPcapGlobal.debug)
          fprintf(stderr, "populating new cluster for instance %p at %p as member 0\n", instance, cluster);
        cluster = &fusedPcapClusters[0];
        instance->cluster = cluster;
        instance->member = 0;
        memcpy(&cluster->config, config, sizeof(struct fusedPcapConfig_s));
        cluster->shortPath = strdup(shortPath);
        instance->shortPath = cluster->shortPath;
        cluster->instance[0] = instance; // last change for thread safety
        cluster->slabs = calloc(SLAB_ALLOC_COUNT, sizeof(struct packet_link_s));
        if (cluster->slabs) {
          //struct packet_link_s *oldfree = cluster->free;  // if adding to rather than initializing
          cluster->free = next = cluster->slabs + 1;
          for (i=2; i<SLAB_ALLOC_COUNT; i++) { // first used by slabs, last has free=NULL
            next = next->free = next + 1;
          }
          //next->free = oldfree;
        }
      }
      // otherwise, clean up and return NULL
    }
    pthread_mutex_unlock(&readqueueMutex);
  }

  return instance;
}

static struct fusedPcapInstance_s *findInstance(void)
{
  struct fuse_context *context;
  int i;

  //this is read-only, no need to protect with a mutex
  context = fuse_get_context();
  for (i=0; i<MAX_CLUSTER_SIZE; i++)
    if (fusedPcapInstances[i].pid == context->pid)
      return &fusedPcapInstances[i];
  return NULL;
}

static void clearInstance(struct fusedPcapInstance_s *instance)
{
  int i;
  struct packet_link_s *slab;
  struct packet_link_s *head;

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "clearing instance %p\n", instance);
  //protect this whole operation with a mutex
  pthread_mutex_lock(&instanceMutex);
  if (instance->readFile)
    free(instance->readFile);
  if (instance->config.clustersize > 1 && instance->cluster) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "removing instance %p from cluster %p member %d\n", instance, instance->cluster, instance->member);
    if (fusedPcapGlobal.debug) {
      head = instance->free;
      i = 0;
      while (head) {
        i++;
        head = head->free;
      }
      fprintf(stderr, "%d free links in instance free list lost until cluster slabs are freed\n", i);
    }
    instance->cluster->instance[instance->member] = NULL;
    for (i=0; i<instance->config.clustersize; i++)
      if (instance->cluster->instance[i])
        break;
    if (i >= instance->config.clustersize) {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "last instance removed, clearing cluster too\n");
      if (instance->cluster->shortPath)
        free(instance->cluster->shortPath);
      if (fusedPcapGlobal.debug) {
        head = instance->cluster->free;
        i = 0;
        while (head) {
          i++;
          head = head->free;
        }
        fprintf(stderr, "%d free links in cluster free list\n", i);
      }
      slab = instance->cluster->slabs;
      i = 0;
      while (slab) {
        i++;
        head = slab;
        slab = slab->next;
        free(head);
      }
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "%d memory slabs freed from cluster\n", i);
      memset(instance->cluster, '\0', sizeof(struct fusedPcapCluster_s));
    }
  }
  else
    if (instance->shortPath)
      free(instance->shortPath);
  memset(instance, '\0', sizeof(struct fusedPcapInstance_s));
  pthread_mutex_unlock(&instanceMutex);
}

static inline void setInstance(struct fuse_file_info *fileInfo, struct fusedPcapInstance_s *instance)
{
  fileInfo->fh = (uint64_t)instance;  //masking only, no mutex needed
}

static inline struct fusedPcapInstance_s *getInstance(struct fuse_file_info *fileInfo)
{
  return (struct fusedPcapInstance_s *)fileInfo->fh;  //masking only, no mutex needed
}

static inline void setDirectory(struct fuse_file_info *fileInfo, struct fusedPcapDirectory_s *directory)
{
  fileInfo->fh = (uint64_t)directory;  //masking only, no mutex needed
}

static inline struct fusedPcapDirectory_s *getDirectory(struct fuse_file_info *fileInfo)
{
  return (struct fusedPcapDirectory_s *)fileInfo->fh;  //masking only, no mutex needed
}

// FUSE CALLBACKS

static void *fused_pcap_init(struct fuse_conn_info *conn)
{
  (void) conn;
  syslog(LOG_INFO, "fused_pcap initialized");
  return NULL;
}

static void fused_pcap_destroy(void *privateData)
{
  (void) privateData;
  syslog(LOG_INFO, "fused_pcap exiting");
}

static int fused_pcap_getattr(const char *path, struct stat *stData)
{
  char mountPath[PATH_MAX + 1];
  struct fusedPcapConfig_s fileConfig;
  char *shortPath;
  struct fusedPcapInstance_s *instance;

  //TODO:
  stData->st_ino = 99999;
  stData->st_uid = geteuid();
  stData->st_gid = getegid();
  stData->st_size = 1;
  stData->st_nlink = 1;
  stData->st_blocks = 1;
  if (isSpecialFile(path)) {
    if (isOptionDir(path)) {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "detected %s is a special directory\n", path);
      stData->st_size = 1;
      stData->st_mode = S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO;
      return 0;
    }
    else {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "detected %s is a special file\n", path);
      stData->st_size = 43;
      stData->st_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH;
      return 0;
    }
  }

  if (reapConfigDirs(path, &shortPath, &fileConfig))
    return -ENOENT;
  if (fusedPcapGlobal.debug)
    printConfigStruct(&fileConfig);

  // lookup calling pid, check if file is already opened
  instance = findInstance();
  if (instance && instance->shortPath && strcmp(shortPath, instance->shortPath) == 0) {
    // if it is, we need to return the cached attributes, as we may have
    // altered its virtual size or it may no longer exist.
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "getattr using cached stData for %s\n", shortPath);
    memcpy(stData, &instance->stData, sizeof(struct stat));
    return 0;
  }

  if (separateEndingFile(&shortPath, &shortPath)) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "getattr detected ending file but ignored it\n");
  }

  if (! shortPath)
    shortPath = "/";
  snprintf(mountPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, shortPath);

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "getattr calling stat for %s\n", mountPath);
  if (stat(mountPath, stData) == -1) {
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
  if (isSpecialFile(path)) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "detected %s is a special file\n", path);

    if (size >= 2) {
      buffer[0] = '.';
      buffer[1] = '\0';
    }
    return 0;
  }
  //TODO: finish
  return -EROFS;
}

static int fused_pcap_opendir(const char *path, struct fuse_file_info *fileInfo)
{
  char mountPath[PATH_MAX + 1];
  struct fusedPcapDirectory_s *dirInfo;
  //struct fusedPcapConfig_s fileConfig;
  char *shortPath;

  dirInfo = malloc(sizeof(struct fusedPcapDirectory_s));
  if (dirInfo == NULL)
    return -ENOMEM;

  if (reapConfigDirs(path, &shortPath, &dirInfo->config)) {
    return -ENOENT;
  }
  if (fusedPcapGlobal.debug)
    printConfigStruct(&dirInfo->config);

  if (! shortPath)
    shortPath = "/";
  snprintf(mountPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, shortPath);

  dirInfo->fd = opendir(mountPath);
  if (dirInfo->fd == NULL) {
    free(dirInfo);
    return -errno;
  }
  dirInfo->shortPath = strdup(shortPath);
  setDirectory(fileInfo, dirInfo);

  return 0;
}

static int fused_pcap_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fileInfo)
{
  char pseudoDir[PATH_MAX + 1];
  struct dirent *entry;
  struct stat status;
  struct fusedPcapDirectory_s *dirInfo;

  (void)path;  // should not use if flag_nopath is set
  (void)offset;

  dirInfo = getDirectory(fileInfo);
  while ((entry = readdir(dirInfo->fd)) != NULL) {
    memset(&status, 0, sizeof(struct stat));
    status.st_ino = entry->d_ino;
    status.st_mode = entry->d_type << 12;
    //TODO: add/remove options pseudodirs from path before returning d_name
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "sending %s to filler callback\n", entry->d_name);
    if (filler(buffer, entry->d_name, &status, 0))
      break;
  }

  //TODO: add special files
  memset(&status, 0, sizeof(struct stat));
  status.st_ino = 99999;
  status.st_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH;
  filler(buffer, "..status",  &status, 0);
  //if (fileIsOpen(mountPath))
    //filler(buffer, "..pids", &status, 0);

  //TODO: add options pseudodirs as special symlinks to ".."
  status.st_mode = S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO;
  status.st_uid = geteuid();
  status.st_gid = getegid();
  status.st_size = 1;
  status.st_nlink = 1;
  status.st_blocks = 1;
  snprintf(pseudoDir, PATH_MAX, "..filesize=%lli", (long long int)dirInfo->config.filesize);
  filler(buffer, pseudoDir,  &status, 0);
  snprintf(pseudoDir, PATH_MAX, "..clustersize=%d", dirInfo->config.clustersize);
  filler(buffer, pseudoDir,  &status, 0);
  snprintf(pseudoDir, PATH_MAX, "..clustermode=%d", dirInfo->config.clustermode);
  filler(buffer, pseudoDir,  &status, 0);
  snprintf(pseudoDir, PATH_MAX, "..clusterabend=%d", dirInfo->config.clusterabend);
  filler(buffer, pseudoDir,  &status, 0);
  snprintf(pseudoDir, PATH_MAX, "..blockslack=%d", dirInfo->config.blockslack);
  filler(buffer, pseudoDir,  &status, 0);
  if (dirInfo->config.keepcache)
    filler(buffer, "..keepcache",  &status, 0);

  return 0;
}

static int fused_pcap_releasedir(const char *path, struct fuse_file_info *fileInfo)
{
  struct fusedPcapDirectory_s *dirInfo;
  DIR *fd;

  (void)path;  // should not use if flag_nopath is set

  dirInfo = getDirectory(fileInfo);
  fd = dirInfo->fd;
  if (dirInfo->shortPath)
    free(dirInfo->shortPath);
  free(dirInfo);

  if (closedir(fd) != 0)
    return -errno;
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
  struct fusedPcapInstance_s *instance;
  char *endFile;
  
  if (fileInfo->flags & (O_CREAT | O_WRONLY)) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "open detected O_CREAT or O_WRONLY flags in %x, returning EROFS\n", fileInfo->flags);
    return -EROFS;
  }

  if (isSpecialFile(path)) {
    //return the file's fd
    fileInfo->fh = 43;
    return 0;
  }

  if (reapConfigDirs(path, &shortPath, &fileConfig))
    return -ENOENT;
  if (fusedPcapGlobal.debug)
    printConfigStruct(&fileConfig);

  instance = populateInstance(shortPath, &fileConfig);
  if (!instance)
    return -EMFILE;

  if (separateEndingFile(&shortPath, &endFile)) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "separate ending file detected: %s\n", endFile);
  }

  if (endFile && endFile != shortPath)
    snprintf(instance->endFile, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, endFile);
  if (! shortPath)
    shortPath = "/";
  snprintf(mountPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, shortPath);

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "open calling open for %s\n", mountPath);
  ret = open(mountPath, fileInfo->flags);
  if (ret == -1) {
    clearInstance(instance);
    return -errno;
  }

  // read first few bytes, verify it's a pcap, rewind to beginning of file

  fileInfo->direct_io = 1;
  fileInfo->nonseekable = 1;
  if (fileConfig.keepcache)
    fileInfo->keep_cache = 1;

  if (stat(mountPath, &instance->stData) == -1) {
    clearInstance(instance);
    return -errno;
  }
  instance->stData.st_size = instance->config.filesize;
  instance->fd = ret;
  //NOTE: if strdup fails, this is set to NULL; always verify before dereferencing
  instance->readFile = strdup(mountPath);
  setInstance(fileInfo, instance);

  return 0;
}

static int fused_pcap_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
  off_t offRes;
  ssize_t sizeRes;
  struct fusedPcapInstance_s *instance;
  int clustersize;

  (void)path;  // should not use if flag_nopath is set

  //TODO: finish

  if (fileInfo->fh == 43) {
    strncpy(buffer, "This is my special wonder-file contents...\n", size);
    return strlen(buffer);
  }

  instance = getInstance(fileInfo);
  if (instance == NULL)
    return -EBADF;  // fuse fd passed between pids, or process forked? look up based on name and offset?
  //if (fileEntry->readOffset != offset)
    //EINVAL? offset not suitably aligned

  if (instance->abortEof) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "aborting cluster member %d before read with EOF\n", instance->clusterMember);
    instance->config.filesize = instance->readOffset;
    instance->normalEnding = 1;
    return 0;
  }
  if (instance->abortErr) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "aborting cluster member %d before read with ENOENT\n", instance->clusterMember);
    instance->normalEnding = 1;
    return -ENOENT;  //is this the right error?
  }

  clustersize = instance->config.clustersize;
  if (clustersize > 1) {

    while (! instance->cluster->fullyPopulated) {
      //if (non-blocking)
        //return -EINTR;
      //delay a little or wait for next open event, blocking this read
      usleep(1000000);
      return -EINTR;
    }

    //do (
      //for (i=0; i<instance->config.clustersize; i++) (
        //if (cluster->instance[i]->queue == NULL) {
          //if (clusterIndex->member[i]->readOffset too far behind) {
            //set cluster member to trigger read event (race condition between setting trigger and blocking?)
            //if (non-blocking)
              //return -EINTR;
            //else
              //break;
          //}
        //}
      //}
      //if (i == clustersize)
        //break;
    //} while (wait for next read event, blocking this read)
  }
  
  //offRes = lseek(fileEntry->fd, fileEntry->inputOffset, SEEK_SET);
  offRes = lseek(instance->fd, offset, SEEK_SET);
  if (offRes != offset)
    return -errno;

  //if (instance->config.clustersize == 1) {
    sizeRes = read(instance->fd, buffer, size);
    if (sizeRes == -1)
      return -errno;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "read returned %lli\n", (long long int) sizeRes);

    instance->readOffset += sizeRes;
    instance->outputOffset += sizeRes;
  //}
  //else {
    //send next packet in the queue
    if (instance->queue) {
      if (instance->queue->next == NULL) {
        //get the read mutex
      }
      //sizeRes = instance->queue->size;
      //copy sizeRes from instance->queue->buffer to buffer
      instance->queue->free = instance->free;
      instance->free = instance->queue;
      instance->queue = instance->queue->next;
      if (instance->queue == NULL) {
        //release the read mutex
      }
    }
    else {
      //get the read mutex
      //read more from source file if there are no packets in our queue, blocking if too far ahead
      //chase all queues to the last block
      //reap the free links from all members
      //parse the packets, adding link to member's queue, growing slabs as needed
      //release the read mutex
    }
  //}

  if (sizeRes == 0) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "EOF detected, comparing %s and %s\n", instance->readFile, instance->endFile);

    if (instance->readFile && strcmp(instance->readFile, instance->endFile) == 0) {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "EOF detected on ending file, returning 0 bytes\n");
      instance->normalEnding = 1;
      instance->config.filesize = instance->readOffset;
    }

    if ((clustersize == 1)) { //TODO: && nextFileReady()) || allClusterMembersCurrent()) {
      if (instance->fileEndEof) {
        if (fusedPcapGlobal.debug)
          fprintf(stderr, "setting cluster member %d to abort before next read with EOF\n", instance->clusterMember);
        //TODO: adjust instance's cached stData filesize?
        instance->abortEof = 1;
      }
      else if (instance->fileEndErr) {
        if (fusedPcapGlobal.debug)
          fprintf(stderr, "aborting cluster member %d at EOF before next read\n", instance->clusterMember);
        return -EINVAL;
      }
      else {
        if (fusedPcapGlobal.debug)
          fprintf(stderr, "TODO: close current file, open next, and continue\n");
        //close finished file, cleanup instance fields
        //close(instance->fd);
        //instance->fd = open(nextFilePath, fileEntry->flags);
        //instance->readOffset = 0ll;
        // free readFile string and dup from nextFilePath
        //verify but discard pcap header from new file
        //if (clustersize > 1)
          //flush old cache and reread the new one.
      }
      //return -EINTR;
    }
    else if (0) { //TODO: (! non-blocking)
      //block until more available (or just wait a few and retry) //TODO: figure out how to determine more is available
      // return -EINTR
    }
  }

  return sizeRes;
}

static int fused_pcap_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
  (void)path;  // should not use if flag_nopath is set
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
  struct fusedPcapInstance_s *instance;
  int ret;

  //TODO: finish
  (void)path;  // should not use if flag_nopath is set
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

  if (fileInfo->fh == 43) //TODO
    return 0;

  instance = getInstance(fileInfo);
  if (instance == NULL)
    return -EBADF;  // fuse fd passed between pids, or process forked? look up based on name and offset?
  ret = close(instance->fd);
  clearInstance(instance);

  if (ret == -1)
    return -errno;
  return ret;
}

static int fused_pcap_fsync(const char *path, int dummy, struct fuse_file_info *fileInfo)
{
  (void)path;  // should not use if flag_nopath is set
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

  if (separateEndingFile(&shortPath, &shortPath)) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "ending file detected but ignored\n");
  }

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
  .init        = fused_pcap_init,
  .destroy     = fused_pcap_destroy,
  .getattr     = fused_pcap_getattr,
  .access      = fused_pcap_access,
  .readlink    = fused_pcap_readlink,
  .opendir     = fused_pcap_opendir,
  .readdir     = fused_pcap_readdir,
  .releasedir  = fused_pcap_releasedir,
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
#if FUSE_MAJOR_VERSION > 2 || ( FUSE_MAJOR_VERSION == 2 && FUSE_MINOR_VERSION >= 9 )
  .flag_nopath = 1,
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
  FUSED_PCAP_OPT_KEY_KEEPCACHE,
};

static struct fusedPcapInputs_s {
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
  FUSE_OPT_KEY("keepcache", FUSED_PCAP_OPT_KEY_KEEPCACHE),

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
  case FUSED_PCAP_OPT_KEY_KEEPCACHE:
    fusedPcapConfig.keepcache = 1;
    return 0;
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

  if ((fuse_opt_parse(&fuseArgs, &fusedPcapInputs, fusedPcapOptions, parseMountOptions)) == -1) {
    fprintf(stderr, "%s: invalid arguments\n", argv[0]);
    return 1;
  }
  if (!fusedPcapInputs.help)
  {

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

    // retrieve the system pagesize, verify that it's a power of 2, save it
    fusedPcapGlobal.pageSize = sysconf(_SC_PAGESIZE);
    if (fusedPcapGlobal.pageSize <= 0) {
      fprintf(stderr, "%s: warning: pagesize invalid, assuming 4k\n", argv[0]);
      fusedPcapGlobal.pageSize = 4096;
    }
    else if (fusedPcapGlobal.pageSize & (fusedPcapGlobal.pageSize - 1)) { // more than one bit set?
      fprintf(stderr, "%s: PAGESIZE is not a power of 2\n", argv[0]);
      return 1;
    }

    if (fusedPcapGlobal.debug) {
      fprintf(stderr, "PAGESIZE: %ld\n", fusedPcapGlobal.pageSize);
      printConfigStruct(&fusedPcapConfig);
      fprintf(stderr, "Parameters validated, calling fuse_main()\n");
    }
  }

  openlog(NULL, LOG_PID, LOG_DAEMON);

#if FUSE_VERSION >= 26
  return fuse_main(fuseArgs.argc, fuseArgs.argv, &callbackOperations, NULL);
#else
  return fuse_main(fuseArgs.argc, fuseArgs.argv, &callbackOperations);
#endif
}



