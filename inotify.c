#define _GNU_SOURCE   
#include "libraries_include.h"
#include "enum_ip_inter.h"

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)                                                                           
                                                                                                              
/* logMessage() flags */                                                                                      
#define VB_BASIC 1      /* Basic messages */                                                                  
#define VB_NOISY 2      /* Verbose messages */     
static int verboseMask;

   //Variables para Socket
    int sock = 0, sock_send = 0;
    char hostname[256];
                                                                                  
static int checkCache = 0;                                                                                                                                                                        
static int readBufferSize = 0;   
static FILE *logfp = NULL; //Variable para abrir archivo de Log.

static int inotifyReadCnt = 0;          /* Counts number of read()s from
                                           inotify file descriptor */

static const int INOTIFY_READ_BUF_LEN = (100 * (sizeof(struct inotify_event) + NAME_MAX + 1));

/* Data structures and functions for dealing with the directory pathnames
   provided as command-line arguments. These directories form the roots of
   the trees that we will monitor */
static char **rootDirPaths; /* List of pathnames supplied on command line */
static int numRootDirs;     /* Number of pathnames supplied on command line */
static int ignoreRootDirs;  /* Number of command-line pathnames that
                               we've ceased to monitor */

static struct stat *rootDirStat;
                            /* stat(2) structures for croot directories */

/* Write a log message. The message is sent to none, either, or both of
   stderr and the log file, depending on 'vb_mask' and whether a log file
   has been specified via command-line options . */
static void logMessage(int vb_mask, const char *format, ...)
{
    va_list argList;
    if ((vb_mask == 0) || (vb_mask & verboseMask)) {
	fprintf(logfp,"%s : ",currTimeLog());
        va_start(argList, format);
        vfprintf(logfp, format, argList);
        va_end(argList);
	fprintf(logfp," \n");
    }
}

/***********************************************************************/
/* Display some information about an inotify event. (Used when
   when we are doing verbose logging.) */
static void displayInotifyEvent(struct inotify_event *ev)
{
    logMessage(VB_NOISY, "--->Event Identification -> wd = %d; ", ev->wd);
    if (ev->cookie > 0)
        logMessage(VB_NOISY, "cookie = %4d; ", ev->cookie);
    
    if (ev->mask & IN_ISDIR)
        logMessage(VB_NOISY, "mask = IN_ISDIR ");

    if (ev->mask & IN_CREATE)
        logMessage(VB_NOISY, "mask = IN_CREATE ");

    if (ev->mask & IN_DELETE_SELF)
        logMessage(VB_NOISY, "mask = IN_DELETE_SELF ");

    if (ev->mask & IN_MOVE_SELF)
        logMessage(VB_NOISY, "mask = IN_MOVE_SELF ");
    if (ev->mask & IN_MOVED_FROM)
        logMessage(VB_NOISY, "mask = IN_MOVED_FROM ");
    if (ev->mask & IN_MOVED_TO)
        logMessage(VB_NOISY, "mask = IN_MOVED_TO ");

    if (ev->mask & IN_IGNORED)
        logMessage(VB_NOISY, "mask = IN_IGNORED ");
    if (ev->mask & IN_Q_OVERFLOW)
        logMessage(VB_NOISY, "mask = IN_Q_OVERFLOW ");
    if (ev->mask & IN_UNMOUNT)
        logMessage(VB_NOISY, "mask = IN_UNMOUNT ");
    
    if (ev->mask & IN_ATTRIB)
        logMessage(VB_NOISY, "mask = IN_ATTRIB ");
	//logMessage(VB_NOISY, "\n");

    if (ev->len > 0)
        logMessage(VB_NOISY, "Event Name = %s", ev->name);
}

/***********************************************************************/
/* Data structures and functions for the watch list cache */
/* We use a very simple data structure for caching watched directory
   paths: a dynamically sized array that is searched linearly. Not
   efficient, but our main goal is to demonstrate the use of inotify. */
struct watch {
    int wd;                     /* Watch descriptor (-1 if slot unused) */
    char path[PATH_MAX];        /* Cached pathname */
};

struct watch *wlCache = NULL;   /* Array of cached items */
static int cacheSize = 0;       /* Current size of the array */

/* Deallocate the watch cache */
static void freeCache(void)
{
    free(wlCache);
    cacheSize = 0;
    wlCache = NULL;
}

/* Check that all pathnames in the cache are valid, and refer
   to directories */
static void checkCacheConsistency(void)
{
    int failures, j;
    struct stat sb;

    failures = 0;
    for (j = 0; j < cacheSize; j++) {
        if (wlCache[j].wd >= 0) {
            if (lstat(wlCache[j].path, &sb) == -1) {
                logMessage(0,
                        "checkCacheConsistency: stat: "
                        "[slot = %d; wd = %d] %s: %s\n",
                        j, wlCache[j].wd, wlCache[j].path, strerror(errno));
                failures++;
        } else if (!S_ISDIR(sb.st_mode)) {
            logMessage(0, "checkCacheConsistency: %s is not a directory\n",wlCache[j].path);
                    exit(EXIT_FAILURE);
            }
        }
    }

    if (failures > 0)
        logMessage(VB_NOISY, "checkCacheConsistency: %d failures\n",failures);
}

/* Check whether the cache contains the watch descriptor 'wd'.
   If found, return the slot number, otherwise return -1. */
static int findWatch(int wd)
{
    int j;

    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd == wd)
            return j;

    return -1;
}

/* Find and return the cache slot for the watch descriptor 'wd'.
   The caller expects this watch descriptor to exist.  If it does not,
   there is a problem, which is signaled by the -1 return. */
static int findWatchChecked(int wd)
{
    int slot;

    slot = findWatch(wd);

    if (slot >= 0)
        return slot;

    logMessage(0, "Could not find watch %d\n", wd);
    /* With multiple renamers there are still rare cases where
       the cache is missing entries after a 'Could not find watch'
       event. It looks as though this is because of races with nftw(),
       since the cache is (occasionally) re-created with fewer
       entries than there are objects in the tree(s). Returning
       -1 to our caller identifies that there's a problem, and the
       caller should probably trigger a cache rebuild. */
}

/* Mark a cache entry as unused */
static void markCacheSlotEmpty(int slot)
{
    //logMessage(VB_NOISY,"        markCacheSlotEmpty: slot = %d;  wd = %d; path = %s\n",slot, wlCache[slot].wd, wlCache[slot].path);

    wlCache[slot].wd = -1;
    wlCache[slot].path[0] = '\0';
}

/* Find a free slot in the cache */
static int findEmptyCacheSlot(void)
{
    int j;
    const int ALLOC_INCR = 10;

    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd == -1)
            return j;

    /* No free slot found; resize cache */
    cacheSize += ALLOC_INCR;

    wlCache = realloc(wlCache, cacheSize * sizeof(struct watch));
    if (wlCache == NULL)
        errExit("realloc");

    for (j = cacheSize - ALLOC_INCR; j < cacheSize; j++)
        markCacheSlotEmpty(j);

    return cacheSize - ALLOC_INCR;      /* Return first slot in
                                           newly allocated space */
}

/* Add an item to the cache */
static int addWatchToCache(int wd, const char *pathname)
{
    int slot;

    slot = findEmptyCacheSlot();

    wlCache[slot].wd = wd;
    strncpy(wlCache[slot].path, pathname, PATH_MAX);

    return slot;
}

/* Return the cache slot that corresponds to a particular pathname,
   or -1 if the pathname is not in the cache */
static int pathnameToCacheSlot(const char *pathname)
{
    int j;

    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd >= 0 && strcmp(wlCache[j].path, pathname) == 0)
            return j;

    return -1;
}

/* Is 'pathname' in the watch cache? */
static int pathnameInCache(const char *pathname)
{
    return pathnameToCacheSlot(pathname) >= 0;
}

/* Duplicate the pathnames supplied on the command line, perform
   some sanity checking along the way */
static void copyRootDirPaths(char *argv[])
{
    char **p;
    int j, k;
    struct stat sb;

    p = argv;
    numRootDirs = 0;

    printf("->Backup\n");
    /* Count the number of root paths, and check that the paths are valid */
    for (p = argv; *p != NULL; p++) {
        /* Check that command-line arguments are directories */
        printf("->Valor de p=%s\n",*p);
        if (lstat(*p, &sb) == -1) {
            fprintf(stderr, "lstat() failed on '%s'\n", *p);
            printf("Error lstat()\n");
            exit(EXIT_FAILURE);
        }
        if (! S_ISDIR(sb.st_mode)) {
            fprintf(stderr, "'%s' is not a directory\n", *p);
            printf("Error No es un directorio\n");
            exit(EXIT_FAILURE);
        }
        numRootDirs++;
    }

    /* Create a copy of the root directory pathnames */
    rootDirPaths = calloc(numRootDirs, sizeof(char *));
    if (rootDirPaths == NULL)
        errExit("calloc");

    rootDirStat = calloc(numRootDirs, sizeof(struct stat));
    if (rootDirPaths == NULL)
        errExit("calloc");

    for (j = 0; j < numRootDirs; j++) {
      printf("->Inicia argv[j]=%s\n",argv[j]);
        rootDirPaths[j] = strdup(argv[j]);
        printf("rootDirPaths[j]=%s\n",rootDirPaths[j]);
        if (rootDirPaths[j] == NULL)
            errExit("strdup");
        /* If the same filesystem object appears more than once in the
           command line, this will cause confusion if we later try to zap
           an object from the set of root paths. So, reject such
           duplicates now. Note that we can't just do simple string
           comparisons of the arguments, since different pathname strings
           may refer to the same filesystem object (e.g., "mydir" and
           "./mydir"). So, we use stat() to compare i-node numbers and
           containing device IDs. */
        if (lstat(argv[j], &rootDirStat[j]) == -1)
            errExit("lstat");

        for (k = 0; k < j; k++) {
            if ((rootDirStat[j].st_ino == rootDirStat[k].st_ino) && (rootDirStat[j].st_dev == rootDirStat[k].st_dev)) {
                fprintf(stderr, "Duplicate filesystem objects: %s, %s\n",argv[j], argv[k]);
                exit(EXIT_FAILURE);
            }
        }
    }
    printf("ignoreRootDirs=%d\n",ignoreRootDirs);
    ignoreRootDirs = 0;
}

/* Return the address of the element in 'rootDirPaths' that points
   to a string matching 'path', or NULL if there is no match */
static char ** findRootDirPath(const char *path)
{
    int j;

    for (j = 0; j < numRootDirs; j++)
	//Si rootDirPaths es diferente de NULL y path y rootDirPaths[j] es igual.
        if (rootDirPaths[j] != NULL && strcmp(path, rootDirPaths[j]) == 0)
            return &rootDirPaths[j];

    return NULL;
}

/* Is 'path' one of the pathnames that was listed on the command line? */
static int isRootDirPath(const char *path)
{
    return findRootDirPath(path) != NULL;
}

/* We've ceased to monitor a root directory pathname (probably because it
   was renamed), so zap this pathname from the root path list */
static void zapRootDirPath(const char *path)
{
    char **p;

    printf("zapRootDirPath: %s\n", path);

    p = findRootDirPath(path);
    if (p == NULL) {
        fprintf(stderr, "zapRootDirPath(): path not found!\n");
        exit(EXIT_FAILURE);
    }

    *p = NULL;
    ignoreRootDirs++;
    if (ignoreRootDirs == numRootDirs) {
        fprintf(stderr, "No more root paths left to monitor; bye!\n");
        exit(EXIT_SUCCESS);
    }
}

/***********************************************************************/
/* Below is a function called by nftw() to traverse a directory tree.
   The function adds a watch for each directory in the tree. Each
   successful call to this function should return 0 to indicate to
   nftw() that the tree traversal should continue. */
/* The usual hack for nftw()...  We can't pass arguments to the
   function invoked by nftw(), so we use these global variables to
   exchange information with the function. */
static int dirCnt;      /* Count of directories added to watch list */
static int ifd;         /* Inotify file descriptor */

static int traverseTree(const char *pathname, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
    int wd, slot, flags;

    if (! S_ISDIR(sb->st_mode))
        return 0;               /* Ignore nondirectory files */

    /* Create a watch for this directory */
    flags = IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_ATTRIB;

    if (isRootDirPath(pathname))
        flags |= IN_MOVE_SELF;

    wd = inotify_add_watch(ifd, pathname, flags | IN_ONLYDIR);
    if (wd == -1) {
        /* By the time we come to create a watch, the directory might
           already have been deleted or renamed, in which case we'll get
           an ENOENT error. In that case, we log the error, but
           carry on execution. Other errors are unexpected, and if we
           hit them, we give up. */
        logMessage(VB_BASIC, "inotify_add_watch: %s: %s",pathname, strerror(errno));
        if (errno == ENOENT)
            return 0;
        else
            exit(EXIT_FAILURE);
    }

    if (findWatch(wd) >= 0) {
        /* This watch descriptor is already in the cache;
           nothing more to do. */
        logMessage(VB_BASIC, "WD %d already in cache (%s)", wd, pathname);
        return 0;
    }

    dirCnt++;
    /* Cache information about the watch */
    slot = addWatchToCache(wd, pathname);
    /* Print the name of the current directory */
    logMessage(VB_NOISY, "    traverseTree-> : wd = %d [cache slot: %d]; %s",wd, slot, pathname);
    return 0;
}

/* Add the directory in 'pathname' to the watch list of the inotify
   file descriptor 'inotifyFd'. The process is recursive: watch items
   are also created for all of the subdirectories of 'pathname'.
   Returns number of watches/cache entries added for this subtree. */
static int watchDir(int inotifyFd, const char *pathname)
{
    dirCnt = 0;
    ifd = inotifyFd;
    /* Use FTW_PHYS to avoid following soft links to directories (which
       could lead us in circles) */
    /* By the time we come to process 'pathname', it may already have
       been deleted, so we log errors from nftw(), but keep on going */
    if (nftw(pathname, traverseTree, 20, FTW_PHYS) == -1)
        logMessage(VB_BASIC,
                "nftw: %s: %s (directory probably deleted before we "
                "could watch)", pathname, strerror(errno));
    return dirCnt;
}

/* Add watches and cache entries for a subtree, logging a message
   noting the number entries added. */
static void watchSubtree(int inotifyFd, char *path)
{
    int cnt;
    cnt = watchDir(inotifyFd, path);
    logMessage(VB_BASIC, "    watchSubtree: %s: %d entries added",path, cnt);
}

/***********************************************************************/
/* The directory oldPathPrefix/oldName was renamed to
   newPathPrefix/newName. Fix up cache entries for
   oldPathPrefix/oldName and all of its subdirectories
   to reflect the change. */
static void rewriteCachedPaths(const char *oldPathPrefix, const char *oldName, const char *newPathPrefix, const char *newName)
{
    char fullPath[PATH_MAX], newPrefix[PATH_MAX];
    char newPath[PATH_MAX];
    size_t len;
    int j;

    snprintf(fullPath, sizeof(fullPath), "%s/%s", oldPathPrefix, oldName);
    snprintf(newPrefix, sizeof(newPrefix), "%s/%s", newPathPrefix, newName);
    len = strlen(fullPath);

    logMessage(VB_BASIC, "Rename: %s ==> %s", fullPath, newPrefix);

    for (j = 0; j < cacheSize; j++) {
        if (strncmp(fullPath, wlCache[j].path, len) == 0 &&
                    (wlCache[j].path[len] == '/' ||
                     wlCache[j].path[len] == '\0')) {
            snprintf(newPath, sizeof(newPath), "%s%s", newPrefix,&wlCache[j].path[len]);
            strncpy(wlCache[j].path, newPath, PATH_MAX);
            logMessage(VB_NOISY, "  rewriteCachedPaths -> wd %d [cache slot %d] ==> %s",wlCache[j].wd, j, newPath);
        }
    }
}

/* Zap watches and cache entries for directory 'path' and all of its
   subdirectories. Returns number of entries that we (tried to) zap,
   or -1 if an inotify_rm_watch() call failed. */
static int zapSubtree(int inotifyFd, char *path)
{
    size_t len;
    int j;
    int cnt;
    char *pn;

    logMessage(VB_NOISY, "Zapping subtree: %s", path);

    len = strlen(path);
    /* The argument we receive might be a pointer to a pathname string
       that is actually stored in the cache.  If we zap that pathname
       part way through scanning the whole cache, then chaos results.
       So, create a temporary copy. */
    pn = strdup(path);

    cnt = 0;

    for (j = 0; j < cacheSize; j++) {
        if (wlCache[j].wd >= 0) {
            if (strncmp(pn, wlCache[j].path, len) == 0 &&
                    (wlCache[j].path[len] == '/' ||
                     wlCache[j].path[len] == '\0')) {

                logMessage(VB_NOISY,"    removing watch: wd = %d (%s)",wlCache[j].wd, wlCache[j].path);

                if (inotify_rm_watch(inotifyFd, wlCache[j].wd) == -1) {
                    logMessage(0, "inotify_rm_watch wd = %d (%s): %s",wlCache[j].wd, wlCache[j].path, strerror(errno));

                    /* When we have multiple renamers, sometimes
                       inotify_rm_watch() fails. In this case, we force a
                       cache rebuild by returning -1.
                       (TODO: Is there a better solution?) */
                    cnt = -1;
                    break;
                }

                markCacheSlotEmpty(j);
                cnt++;
            }
        }
    }
    free(pn);
    return cnt;
}

/* When the cache is in an unrecoverable state, we discard the current
   inotify file descriptor ('oldInotifyFd') and create a new one (returned
   as the function result), and zap and rebuild the cache.
   If 'oldInotifyFd' is -1, this is the initial build of the cache, or an
   explicitly requested cache rebuild, so we are a little less verbose,
   and we reset 'reinitCnt'.  */
static int reinitialize(int oldInotifyFd)
{
    int inotifyFd;
    static int reinitCnt;
    int cnt, j;

    if (oldInotifyFd >= 0) {
        close(oldInotifyFd);

        reinitCnt++;
        logMessage(0, "Reinitializing cache and inotify FD (reinitCnt = %d)",reinitCnt);
    } else {
        logMessage(0, "Initializing cache");
        reinitCnt = 0;
    }

    inotifyFd = inotify_init();
    if (inotifyFd == -1)
        errExit("inotify_init");

    logMessage(VB_BASIC, "    new inotifyFd = %d", inotifyFd);

    freeCache();

    for (j = 0; j < numRootDirs; j++)
        if (rootDirPaths[j] != NULL)
            watchSubtree(inotifyFd, rootDirPaths[j]);

    cnt = 0;
    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd >= 0)
            cnt++;

    if (oldInotifyFd >= 0)
        logMessage(0, "Rebuilt cache with %d entries", cnt);

    return inotifyFd;
}

/* Process the next inotify event in the buffer specified by 'buf'
   and 'bufSize'. In most cases, a single event is consumed, but
   if there is an IN_MOVED_FROM+IN_MOVED_TO pair that share a cookie
   value, both events are consumed.
   Returns the number of bytes in the event(s) consumed from 'buf'.  */
static size_t processNextInotifyEvent(int *inotifyFd, char *buf, int bufSize, int firstTry)
{
    char fullPath[PATH_MAX];
    struct inotify_event *ev;
    size_t evLen;
    int evCacheSlot;
    char sendBuff[1025], clearsendBuff[PATH_MAX];    //Sockects
    int sock_inits;
	      int controla1;
	      char todas[PATH_MAX];
    
    struct stat buf_stat;

    ev = (struct inotify_event *) buf;
    
    displayInotifyEvent(ev);
    
    if (ev->wd != -1 && !(ev->mask & IN_IGNORED)) {
                /* IN_Q_OVERFLOW has (ev->wd == -1) */
                /* Skip IN_IGNORED, since it will come after an event
                   that has already zapped the corresponding cache entry */
        /* Cache consistency check; see the discussion
           of "intra-tree" rename() events */
        evCacheSlot = findWatchChecked(ev->wd);
        //Elimina todo el monitor y lo vuelve a inicializar...
        if (evCacheSlot == -1) {
           /* Cache reached an inconsistent state */
           *inotifyFd = reinitialize(*inotifyFd);
           /* Discard all remaining events in current read() buffer */
           return INOTIFY_READ_BUF_LEN;
        }
    }
    
    evLen = sizeof(struct inotify_event) + ev->len;

    if ((ev->mask & IN_ISDIR) && (ev->mask & (IN_CREATE | IN_MOVED_TO))) {
        /* A new subdirectory was created, or a subdirectory was
           renamed into the tree; create watches for it, and all
           of its subdirectories. */
        snprintf(fullPath, sizeof(fullPath), "%s/%s",wlCache[evCacheSlot].path, ev->name);	
        logMessage(VB_BASIC, "Directory creation on wd %d: %s",ev->wd, fullPath);
        /* We only watch the new subtree if it has not already been cached.
           This deals with a race condition:
           * On the one hand, the following steps might occur:
               1. The "child" directory is created.
               2. The "grandchild" directory is created
               3. We receive an IN_CREATE event for the creation of the
                  "child" and create a watch and a cache entry for it.
               4. To handle the possibility that step 2 came before
                  step 3, we recursively walk through the descendants of
                  the "child" directory, adding any subdirectories to
                  the cache.
           * On the other hand, the following steps might occur:
               1. The "child" directory is created.
               3. We receive an IN_CREATE event for the creation of the
                  "child" and create a watch and a cache entry for it.
               3. The "grandchild" directory is created
               4. During the recursive walk through the descendants of
                  the "child" directory, we cache the "grandchild" and
                  add a watch for it.
               5. We receive the IN_CREATE event for the creation of
                  the "grandchild". At this point, we should NOT create
                  a cache entry and watch for the "grandchild" because
                  they already exist. (Creating the watch for the
                  second time is harmless, but adding a second cache
                  for the grandchild would leave the cache in a confused
                  state.) */
        if (!pathnameInCache(fullPath))
            watchSubtree(*inotifyFd, fullPath);

    } else if (ev->mask & IN_DELETE_SELF) {
        /* A directory was deleted. Remove the corresponding item from
           the cache. */
        logMessage(VB_BASIC, "Clearing watchlist item %d (%s)",ev->wd, wlCache[evCacheSlot].path);

        if (isRootDirPath(wlCache[evCacheSlot].path))
            zapRootDirPath(wlCache[evCacheSlot].path);

        markCacheSlotEmpty(evCacheSlot);
            /* No need to remove the watch; that happens automatically */
    } else if ((ev->mask & (IN_MOVED_FROM | IN_ISDIR)) == (IN_MOVED_FROM | IN_ISDIR)) {

        /* We have a "moved from" event. To know how to deal with it, we
           need to determine whether there is a following "moved to"
           event with a matching cookie value (i.e., an "intra-tree"
           rename() where the source and destination are inside our
           monitored trees).  If there is not, then we are dealing
           with a rename() out of our monitored tree(s).

           We assume that if this is an "intra-tree" rename() event, then
           the "moved to" event is the next event in the buffer returned
           by the current read(). (If we are already at the last event in
           this buffer, then we ask our caller to read a bit more, in
           the hope of getting the following IN_MOVED_TO event in the
           next read().)

           In most cases, the assumption holds. However, where multiple
           processes are manipulating the tree, we can can get event
           sequences such as the following:

                 IN_MOVED_FROM (rename(x) by process A)
                         IN_MOVED_FROM (rename(y) by process B)
                         IN_MOVED_TO   (rename(y) by process B)
                 IN_MOVED_TO   (rename(x) by process A)

           In principle, there may be arbitrarily complex variations on
           the above theme. Our assumption that related IN_MOVED_FROM
           and IN_MOVED_TO events are consecutive is broken by such
           scenarios.

           We could try to resolve this issue by extending the window
           we use to search for IN_MOVED_TO events beyond the next item
           in the queue. But this must be done heuristically (e.g.,
           limiting the window to N events or to events read within
           X milliseconds), because sometimes we will have an unmatched
           IN_MOVED_FROM events that result from out-of-tree renames.
           The heuristic approach is therefore unavoidably racy: there
           is always a chance that we will fail to match up an
           IN_MOVED_FROM+IN_MOVED_TO event pair.

           So, this program takes the simple approach of assuming
           that an IN_MOVED_FROM+IN_MOVED_TO pair occupy consecutive
           events in the buffer returned by read().

           When that assumption is wrong (and we therefore fail
           to recognize an intra-tree rename() event), then
           the rename will be treated as separate "moved from" and
           "moved to" events, with the result that some watch items
           and cache entries are zapped and re-created. This causes
           the watch descriptors in our cache to become inconsistent
           with the watch descriptors in as yet unread events,
           because the watches are re-created with different watch;
           descriptor numbers.

           Once such an inconsistency occurs, then, at some later point,
           we will do a lookup for a watch descriptor returned by
           inotify, and find that it is not in our cache. When that
           happens, we reinitialize our cache with a fresh set of watch
           descriptors and re-create the inotify file descriptor, in
           order to bring our cache back into consistency with the
           filesystem. An alternative would be to cache the cookies of
           the (recent) IN_MOVED_FROM events for which which we did not
           find a matching IN_MOVED_TO event, and rebuild our watch
           cache when we find an IN_MOVED_TO event whose cookie matches
           one of the cached cookies. Yet another approach when we
           detect an out-of-tree rename would be to reinitialize the
           cache and create a new inotify file descriptor.
           (TODO: consider the fact that for a rename event, there
           won't be other events for the object between IN_MOVED_FROM
           and IN_MOVED_TO.)

           Rebuilding the watch cache is expensive if the monitored
           tree is large. So, there is a trade-off between how much
           effort we want to go to to avoid cache rebuilds versus
           how much effort we want to devote to matching up
           IN_MOVED_FROM+IN_MOVED_TO event pairs. At the one extreme
           we would do no search ahead for IN_MOVED_TO, with the result
           that every rename() potentially could trigger a cache
           rebuild. Limiting the search window to just the following
           event is a compromise that catches the vast majority of
           intra-tree renames and triggers relatively few cache rebuilds.
         */
        struct inotify_event *nextEv;
        nextEv = (struct inotify_event *) (buf + evLen);
        if (((char *) nextEv < buf + bufSize) &&
                (nextEv->mask & IN_MOVED_TO) &&
                (nextEv->cookie == ev->cookie)) {

            int nextEvCacheSlot;

            /* We have a rename() event. We need to fix up the
               cached pathnames for the corresponding directory
               and all of its subdirectories. */
            nextEvCacheSlot = findWatchChecked(nextEv->wd);

            if (nextEvCacheSlot == -1) {
                /* Cache reached an inconsistent state */
                *inotifyFd = reinitialize(*inotifyFd);
                /* Discard all remaining events in current read() buffer */
                return INOTIFY_READ_BUF_LEN;
            }

            rewriteCachedPaths(wlCache[evCacheSlot].path, ev->name,wlCache[nextEvCacheSlot].path, nextEv->name);

            /* We have also processed the next (IN_MOVED_TO) event,
               so skip over it */
            evLen += sizeof(struct inotify_event) + nextEv->len;

        } else if (((char *) nextEv < buf + bufSize) || !firstTry) {

            /* We got a "moved from" event without an accompanying
               "moved to" event. The directory has been moved
               outside the tree we are monitoring. We need to
               remove the watches and zap the cache entries for
               the moved directory and all of its subdirectories. */
            logMessage(VB_NOISY, "MOVED_OUT: %p %p",wlCache[evCacheSlot].path, ev->name);
            logMessage(VB_NOISY, "firstTry = %d; remaining bytes = %d",firstTry, buf + bufSize - (char *) nextEv);
            snprintf(fullPath, sizeof(fullPath), "%s/%s",wlCache[evCacheSlot].path, ev->name);

            if (zapSubtree(*inotifyFd, fullPath) == -1) {
                /* Cache reached an inconsistent state */
                *inotifyFd = reinitialize(*inotifyFd);
                /* Discard all remaining events in current read() buffer */
                return INOTIFY_READ_BUF_LEN;
            }

        } else {
            logMessage(VB_NOISY, "HANGING IN_MOVED_FROM");
            return -1;  /* Tell our caller to do another read() */
        }

    } else if (ev->mask & IN_Q_OVERFLOW) {
        static int overflowCnt = 0;
        overflowCnt++;
        logMessage(0, "Queue overflow (%d) (inotifyReadCnt = %d)",overflowCnt, inotifyReadCnt);
        /* When the queue overflows, some events are lost, at which
           point we've lost any chance of keeping our cache consistent
           with the state of the filesystem. So, discard this inotify
           file descriptor and create a new one, and zap and rebuild
           the cache. */
        *inotifyFd = reinitialize(*inotifyFd);
        /* Discard all remaining events in current read() buffer */
        evLen = INOTIFY_READ_BUF_LEN;
    } else if (ev->mask & IN_UNMOUNT) {
        /* When a filesystem is unmounted, each of the watches on the
           is dropped, and an unmount and an ignore event are generated.
           There's nothing left for us to monitor, so we just zap the
           corresponding cache entry. */
        logMessage(0, "Filesystem unmounted: %s",wlCache[evCacheSlot].path);
        markCacheSlotEmpty(evCacheSlot);
            /* No need to remove the watch; that happens automatically */
    } else if (ev->mask & IN_MOVE_SELF && isRootDirPath(wlCache[evCacheSlot].path)) {
        /* If the root path moves to a new location in the same
           filesystem, then all cached pathnames become invalid, and we
           have no direct way of knowing the new name of the root path.
           We could in theory find the new name by caching the i-node of
           the root path on start-up and then trying to find a pathname
           that corresponds to that i-node. Instead, we'll keep things
           simple, and just cease monitoring it. */
        logMessage(0, "Root path moved: %s",wlCache[evCacheSlot].path);
        zapRootDirPath(wlCache[evCacheSlot].path);
        if (zapSubtree(*inotifyFd, wlCache[evCacheSlot].path) == -1) {
            /* Cache reached an inconsistent state */
            *inotifyFd = reinitialize(*inotifyFd);
            /* Discard all remaining events in current read() buffer */
            return INOTIFY_READ_BUF_LEN;
        }
    } else if(ev->mask & IN_ATTRIB){
	if(ev->mask & IN_ISDIR){
	  snprintf(fullPath, sizeof(fullPath), "%s/%s",wlCache[evCacheSlot].path, ev->name);
	  stat(fullPath, &buf_stat);
	  if(buf_stat.st_mode & S_IWOTH){
	    struct numera_data ips = get_interfaces();
	    for (sock_inits=1; sock_inits<4; sock_inits++){
	      printf("Intento %d de conexion de Socket...\n",sock_inits);
	      sock = OS_ConnectPort(514,"192.168.221.128");
	      //sock = OS_ConnectPort(514,"22.134.230.24");
	      if( sock > 0 ){
		printf("Conexion Exitosa..\n");
		break;
	      }	    
	    }
	    for(controla1 = 0; controla1 < ips.nInterfaces; controla1++)
	     {
	       strcat(todas, prt_interfaces(controla1));
	       strcat(todas,"|");
	     }
	    snprintf(sendBuff, sizeof(sendBuff),"%s|%s|%sWARN|Write Perm Others Users|%s\r\n",currTime(), hostname, todas, fullPath);
	    sock_send = write(sock, sendBuff, strlen(sendBuff));
	    if( sock_send < 0 )
	      printf("Error al enviar a Socket\n");
	    logMessage(0,"---->Directorio Con Escritura Publica=%s",fullPath);
	    bzero(fullPath,PATH_MAX);
	    strcpy(fullPath, clearsendBuff);
	    bzero(sendBuff,PATH_MAX);
	    strcpy(sendBuff, clearsendBuff);
	    bzero(todas,PATH_MAX);
	    strcpy(todas,clearsendBuff);
	    OS_CloseSocket(sock);
	    OS_CloseSocket(sock_send);
	  }
	}
	else{
	  snprintf(fullPath, sizeof(fullPath), "%s/%s",wlCache[evCacheSlot].path, ev->name);
	  stat(fullPath, &buf_stat);
	  if(buf_stat.st_mode & S_IWOTH){
	    struct numera_data ips = get_interfaces();
	    for (sock_inits=1; sock_inits<4; sock_inits++){
	      printf("Intento %d de conexion de Socket...\n",sock_inits);
	      sock = OS_ConnectPort(514,"192.168.221.128");
	      //sock = OS_ConnectPort(514,"22.134.230.24");
	      if( sock > 0 ){
		printf("Conexion Exitosa..\n");
		break;
	      }	    
	    }
	    for(controla1 = 0; controla1 < ips.nInterfaces; controla1++)
	     {
	       strcat(todas, prt_interfaces(controla1));
	       strcat(todas,"|");
	     }
	    snprintf(sendBuff, sizeof(sendBuff),"%s|%s|%sWARN|Write Perm Others Users|%s\r\n",currTime(), hostname, todas, fullPath);
	    sock_send = write(sock, sendBuff, strlen(sendBuff));
	    if( sock_send < 0 )
	      printf("Error al enviar a Socket\n");
	    logMessage(0,"---->Archivo Con Escritura Publica=%s",fullPath);
	    bzero(fullPath,PATH_MAX);
	    strcpy(fullPath, clearsendBuff);
	    bzero(sendBuff,PATH_MAX);
	    strcpy(sendBuff, clearsendBuff);
	    bzero(todas,PATH_MAX);
	    strcpy(todas,clearsendBuff);
	    OS_CloseSocket(sock);
	    OS_CloseSocket(sock_send);
	  }
	}
    }

    if (checkCache)
        checkCacheConsistency();

    return evLen;
}

static void alarmHandler(int sig)
{
    return;             /* Just interrupt read() */
}

/* Read a block of events from the inotify file descriptor, 'inotifyFd'.
   Process the events relating to directories in the subtree we are
   monitoring, in order to keep our cached view of the subtree in sync
   with the filesystem. */
static void processInotifyEvents(int *inotifyFd)
{
    char buf[INOTIFY_READ_BUF_LEN] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    //char buf[PATH_MAX + sizeof(struct inotify_event) + 1];
    ssize_t numRead, nr;
    char *evp;
    size_t cnt;
    int evLen;
    int firstTry;
    int j;
    struct sigaction sa;

    /* SIGALRM handler is designed simply to interrupt read() */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = alarmHandler;
    sa.sa_flags = 0;
    if (sigaction(SIGALRM, &sa, NULL) == -1)
        errExit("sigaction");

    firstTry = 1;

    /* Read some events from inotify file descriptor */
    cnt = (readBufferSize > 0) ? readBufferSize : INOTIFY_READ_BUF_LEN;
    numRead = read(*inotifyFd, buf, cnt);
    printf("------------>Valor de numRead=%d\n",numRead);
    if (numRead == -1)
        errExit("read");
    if (numRead == 0) {
        fprintf(stderr, "read() from inotify fd returned 0!");
        exit(EXIT_FAILURE);
    }

    inotifyReadCnt++;
    //Imprime los eventos como los va leyendo y los bytes en los enventos.
    //logMessage(VB_NOISY,"\n==========> Read %d: got %zd bytes\n", inotifyReadCnt, numRead);

    /* Process each event in the buffer returned by read() */
    for (evp = buf; evp < buf + numRead - 16; ) {
	printf("\nBusca Valor de evLen....\n");
        evLen = processNextInotifyEvent(inotifyFd, evp, buf + numRead - evp, firstTry);
	printf("==================>Valor de evLen:%d\n",evLen);

        if (evLen > 0) {
            evp += evLen;
            firstTry = 1;
        } else {
            /* We got here because an IN_MOVED_FROM event was found at
               the end of a previously read buffer and that event may be
               part of an "intra-tree" rename(), meaning that we should
               check if there is a subsequent IN_MOVED_TO event with the
               same cookie value. We left that event unprocessed and we
               will now try to read some more events, delaying for a
               short time, to give the associated IN_MOVED_IN event (if
               there is one) a chance to arrive. However, we only want
               to do this once: if the read() below fails to gather
               further events, then when we reprocess the IN_MOVED_FROM
               we should treat it as though this is an out-of-tree
               rename(). Thus, we set 'firstTry' to 0 for the next
               processNextInotifyEvent() call. */
            struct sigaction sa;
            int savedErrno;
            firstTry = 0;

            numRead = buf + numRead - evp;

            /* Shuffle remaining bytes to start of buffer */
            for (j = 0; j < numRead; j++)
                printf("905 -  FOR: Valores J=%d, buf=%s[j], evp=%s[j]\n",j,buf[j],evp[j]);
                buf[j] = evp[j];

            /* Do a read with timeout, to allow next events (if any) to arrive */
            sa.sa_flags = 0;
            sigemptyset(&sa.sa_mask);
            sa.sa_handler = alarmHandler;

            /* Set a timeout for read(). Some rough testing suggests
               that a 2-millisecond timeout is sufficient to ensure
               that, in around 99.8% of cases, we get the IN_MOVED_TO
               event (if there is one) that matched an IN_MOVED_FROM
               event, even in a highly dynamic directory tree. This
               number may, of course, warrant tuning on different
               hardware and in environments with different filesystem
               activity levels. */
            ualarm(2000, 0);

            nr = read(*inotifyFd, buf + numRead, INOTIFY_READ_BUF_LEN - numRead);

            savedErrno = errno; /* In case ualarm() should change errno */
            ualarm(0, 0);       /* Cancel alarm */
            errno = savedErrno;

            if (nr == -1 && errno != EINTR)
                errExit("read");
            if (nr == 0) {
                fprintf(stderr, "read() from inotify fd returned 0!");
                exit(EXIT_FAILURE);
            }

            if (errno != -1) {
                numRead += nr;
                inotifyReadCnt++;
                logMessage(VB_NOISY,"\n==========> SECONDARY Read %d: got %zd bytes",inotifyReadCnt, nr);
            } else {                    /* EINTR */
                logMessage(VB_NOISY,
                       "\n==========> SECONDARY Read got nothing");
            }
            evp = buf;          /* Start again at beginning of buffer */
        }
    }
}

int main(int argc, char *argv[])
{
    fd_set rfds;
    int inotifyFd;
    verboseMask = 2; //Reemplazar por opcion en archivo de configuracion...

    if (optind >= argc){
        printf("Error Inicial\n");
	errExit("argc");
    }
    
    pid_t pid = getpid();
    FILE *fpid = fopen("./iNotify_Agent.pid", "w"); //Se puede Reemplazar por parametro de archivo de configuracion
    if (!fpid){
      perror("Archivo PID Error\n");
      exit(EXIT_FAILURE);
    }
    fprintf(fpid, "%d\n", pid);
    fclose(fpid);
    
    logfp = fopen("./iNotify_Agent.log", "w+"); //Se puede Reemplazar por parametro de archivo de configuracion
    if (logfp == NULL)
	errExit("fopen");
    setbuf(logfp, NULL);
    
    /* Save a copy of the directories on the command line */
    copyRootDirPaths(&argv[optind]);
    /* Create an inotify instance and populate it with entries for
       directory named on command line */
    inotifyFd = reinitialize(-1);
    /* Loop to handle inotify events and keyboard commands */
    fflush(stdout);
    
    gethostname(hostname, sizeof(hostname));
    hostname[sizeof(hostname) - 1] = '\0';
    
    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(inotifyFd, &rfds);
        //if (select(inotifyFd + 1, &rfds, NULL, NULL, NULL) == -1)
            //errExit("select");
        if (FD_ISSET(inotifyFd, &rfds)){
            processInotifyEvents(&inotifyFd);
	}
    }
    exit(EXIT_SUCCESS);
}