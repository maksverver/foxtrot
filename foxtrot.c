#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <pthread.h>
#define FUSE_USE_VERSION 26
#include <fuse/fuse.h>
#include <libsmbclient.h>

/* Definitions */
#define LOGFILE                 "/var/log/foxtrot/foxtrot.log"
#define HOSTSFILE               "/var/cache/foxtrot/hosts.txt"
#define SMB_WORKGROUP           "CAMPUSLAAN 27"
#define SMB_USERNAME            "campus"
#define SMB_PASSWORD            "campus"
#define SMB_MAX_PACKET_LENGTH   65536
#define MAX_PATH                1024

/* Set this to 1 to trace all invocations of FUSE callback functions */
#define TRACE_INVOCATIONS       0


/* Global variables */
static pthread_mutex_t global_mutex;
static struct Server *server_list;
static int server_list_size;
static time_t server_list_mtime;

/* Types */
struct Server
{
    struct Server *next;
    char *name;
};


#define WARN(msg) \
    do { \
        time_t t; time(&t); \
        fprintf(stderr, "%.24s [WARNING] %s (%s:%d)\n", \
                        ctime(&t), msg, __FILE__, __LINE__); \
    } while(0)

#define NOTE(msg) \
    do { \
        time_t t; time(&t); \
        fprintf(stderr, "%.24s [NOTICE] %s (%s:%d)\n", \
                        ctime(&t), msg, __FILE__, __LINE__); \
    } while(0)

static void free_server_list()
{
    struct Server *node, *next;

    node = server_list;
    while (node != NULL)
    {
        next = node->next;
        free(node->name);
        free(node);
        node = next;
    }
    server_list = NULL;
    server_list_size = 0;
}

static void reload_server_list()
{
    FILE *fp;
    char path[MAX_PATH], *p;
    struct Server *server;

    fp = fopen(HOSTSFILE, "rt");
    if (fp == NULL)
    {
        WARN("Cannot open hosts file");
        return;
    }

    free_server_list();

    while (fgets(path, MAX_PATH, fp) != NULL)
    {
        p = strchr(path, '\n');
        if (p == NULL)
        {
            WARN("Truncated line ignored");
            continue;
        }
        *p = '\0';

        /* Allocate new server entry */
        server = malloc(sizeof(struct Server));
        assert(server != NULL);
        server->name = strdup(path);
        assert(server->name != NULL);
        server->next = server_list;
        server_list = server;
        server_list_size += 1;
    }

    fclose(fp);
}

static void update_server_list()
{
    struct stat st;

    if (stat(HOSTSFILE, &st) != 0)
    {
        WARN("Could not stat hosts file");
        return;
    }

    if (st.st_mtime > server_list_mtime)
    {
        NOTE("Reloading the server list");
        reload_server_list();
        server_list_mtime = st.st_mtime;
    }
}

static char *mksmbpath(char *buf, const char *path)
{
    size_t len;

    len = strlen(path);
    if (5 + len + 1 > MAX_PATH) return NULL;
    memcpy(buf, "smb:/", 5);
    memcpy(buf + 5, path, len + 1);

    return buf;
}

static int foxtrot_getattr(const char *path, struct stat *stbuf)
{
    char smbpath[MAX_PATH];
    int result;

#if TRACE_INVOCATIONS
    fprintf(stderr, "getattr path=%s\n", path);
#endif

    memset(stbuf, 0, sizeof(struct stat));

    if (path[0] != '/')
    {
        WARN("Relative path ignored!");
        return -ENOENT;
    }

    if (path[1] == '\0')
    {
        /* Root directory */
        stbuf->st_mode  = S_IFDIR | 0755;
        stbuf->st_nlink = 2 + server_list_size;
        return 0;
    }

    if (strchr(path + 1, '/') == NULL)
    {
        /* Directory in the root */
        stbuf->st_mode  = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        /* The link count is wrong, but retrieving the correct value would make
           listing the root directory very slow! */
        return 0;
    }

    if (mksmbpath(smbpath, path) == NULL)
    {
        WARN("Path too long");
        return -ENOENT;
    }

    pthread_mutex_lock(&global_mutex);
    if (smbc_stat(smbpath, stbuf) == 0) result = 0; else result = -errno;
    pthread_mutex_unlock(&global_mutex);

    return result;
}

static int foxtrot_readdir( const char *path, void *buf, fuse_fill_dir_t filler,
                           off_t offset, struct fuse_file_info *fi )
{
    (void) offset;
    (void) fi;

#if TRACE_INVOCATIONS
    fprintf(stderr, "readdir path=%s\n", path);
#endif

    if (strcmp(path, "/") == 0)
    {
        struct Server *server;

        filler(buf, ".", NULL, 0);
        filler(buf, "..", NULL, 0);

        pthread_mutex_lock(&global_mutex);
        update_server_list();
        for (server = server_list; server != NULL; server = server->next)
        {
            filler(buf, server->name, NULL, 0);
        }
        pthread_mutex_unlock(&global_mutex);
    }
    else
    {
        int dh;
        struct smbc_dirent *de;
        char smbpath[MAX_PATH];

        if (mksmbpath(smbpath, path) == NULL)
        {
            WARN("Path too long");
            return -ENOENT;
        }

        pthread_mutex_lock(&global_mutex);
        dh = smbc_opendir(smbpath);
        if (dh < 0)
        {
            WARN("smbc_opendir failed");
            pthread_mutex_unlock(&global_mutex);
            return -ENOENT;
        }
        while ((de = smbc_readdir(dh)) != NULL)
        {
            switch (de->smbc_type)
            {
            case SMBC_FILE_SHARE:
            case SMBC_DIR:
            case SMBC_FILE:
            case SMBC_LINK:
                filler(buf, de->name, NULL, 0);
            }
        }
        smbc_closedir(dh);
        pthread_mutex_unlock(&global_mutex);
    }

    return 0;
}

static int foxtrot_open(const char *path, struct fuse_file_info *fi)
{
    char smbpath[MAX_PATH];
    int fd;

#if TRACE_INVOCATIONS
    fprintf(stderr, "open path=%s flags=%d\n", path, (int)fi->flags);
#endif

    /* Enforce read-only access for now, since write is not implemented */
    if((fi->flags & 3) != O_RDONLY)
        return -EACCES;

    if (mksmbpath(smbpath, path) == NULL)
    {
        WARN("Path too long");
        return -ENOENT;
    }

    pthread_mutex_lock(&global_mutex);
    fd = smbc_open(smbpath, O_RDONLY, 0644);
    pthread_mutex_unlock(&global_mutex);
    if (fd < 0)
    {
        WARN("smbc_open failed");
        return -fd;
    }
    fi->fh = fd;

    return 0;
}

int foxtrot_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    size_t nread, chunk;
    ssize_t result;

#if TRACE_INVOCATIONS
    fprintf(stderr, "read path=%s fd=%d size=%lld offset=%lld\n",
                    path, (int)fi->fh, (long long)size, (long long)offset);
#else
    (void)path;
#endif

    pthread_mutex_lock(&global_mutex);
    if (smbc_lseek((int)fi->fh, offset, SEEK_SET) == (off_t)-1)
    {
        WARN("smbc_lseek failed");
        pthread_mutex_unlock(&global_mutex);
        return -errno;
    }

    nread = 0;
    while (nread < size)
    {
        chunk = size - nread;
        if (chunk > SMB_MAX_PACKET_LENGTH) chunk = SMB_MAX_PACKET_LENGTH;
        result = smbc_read((int)fi->fh, buf + nread, chunk);
        if (result < 0)
        {
            WARN("smbc_read failed");
            pthread_mutex_unlock(&global_mutex);
            return -errno;
        }
        if (result == 0) break; /* EOF */
        nread += result;
    }
    pthread_mutex_unlock(&global_mutex);

    return (int)nread;
}

int foxtrot_release(const char *path, struct fuse_file_info *fi)
{
    int res;

#if TRACE_INVOCATIONS
    fprintf(stderr, "release path=%s fd=%d\n", path, (int)fi->fh);
#else
    (void)path;
#endif

    res = smbc_close(fi->fh);
    if (res != 0) WARN("smbc_close failed");

    return -res;
}

static void open_logfile()
{
    FILE *fp;

    fp = freopen(LOGFILE, "a+", stderr);
    assert(fp != NULL);
    setlinebuf(stderr);
}

static void get_auth_data(
    const char *srv,
    const char *shr,
    char *wg, int wglen,
    char *un, int unlen,
    char *pw, int pwlen )
{
    (void)srv;
    (void)shr;
    strncpy(wg, SMB_WORKGROUP, wglen);
    strncpy(un, SMB_USERNAME, unlen);
    strncpy(pw, SMB_PASSWORD, pwlen);
}

static void samba_init()
{
    int res;

    res = smbc_init(get_auth_data, 0);
    assert(res == 0);
}

void *foxtrot_init(struct fuse_conn_info *conn)
{
    (void)conn;

    open_logfile();
    NOTE("Foxtrot starting up!");

    samba_init();
    update_server_list();
    pthread_mutex_init(&global_mutex, NULL);

    return NULL;
}

void foxtrot_destroy(void *private_data)
{
    NOTE("Foxtrot shutting down!");

    (void)private_data;
    free_server_list();
    pthread_mutex_destroy(&global_mutex);
}

int main(int argc, char *argv[])
{
    struct fuse_operations ops;

    /* Assign FUSE operations */
    memset(&ops, 0, sizeof(ops));
    ops.getattr = foxtrot_getattr;
    ops.readdir = foxtrot_readdir;
    ops.open    = foxtrot_open;
    ops.read    = foxtrot_read;
    ops.release = foxtrot_release;
    ops.init    = foxtrot_init;
    ops.destroy = foxtrot_destroy;

    return fuse_main(argc, argv, &ops, NULL);
}
