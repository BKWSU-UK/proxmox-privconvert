/*
 * privconvert - Convert Proxmox LXC containers between privileged and unprivileged modes
 * 
 * This program reads the Proxmox LXC configuration, extracts filesystem paths,
 * and converts UIDs/GIDs with proper ACL handling.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <sys/acl.h>
#include <acl/libacl.h>
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>

#define MAX_PATHS 64
#define MAX_LINE 4096
#define MAX_PATH_LEN 2048
#define UID_GID_OFFSET 100000
#define MAX_UID_GID 200000

/* Global variables for nftw callback */
static int g_offset = 0;
static uint64_t g_files_processed = 0;
static uint64_t g_errors = 0;

/* Hash table for tracking processed inodes */
#define INODE_HASH_SIZE 65536
typedef struct inode_entry {
    dev_t dev;
    ino_t ino;
    struct inode_entry *next;
} inode_entry_t;

static inode_entry_t *inode_table[INODE_HASH_SIZE] = {NULL};

/* Hash function for inode tracking */
static unsigned int inode_hash(dev_t dev, ino_t ino) {
    return (unsigned int)((dev ^ ino) % INODE_HASH_SIZE);
}

/* Check if inode has been seen */
static int inode_seen(dev_t dev, ino_t ino) {
    unsigned int hash = inode_hash(dev, ino);
    inode_entry_t *entry = inode_table[hash];
    
    while (entry) {
        if (entry->dev == dev && entry->ino == ino) {
            return 1;
        }
        entry = entry->next;
    }
    return 0;
}

/* Mark inode as seen */
static void inode_mark_seen(dev_t dev, ino_t ino) {
    unsigned int hash = inode_hash(dev, ino);
    inode_entry_t *entry = malloc(sizeof(inode_entry_t));
    if (!entry) {
        fprintf(stderr, "Failed to allocate memory for inode tracking\n");
        return;
    }
    entry->dev = dev;
    entry->ino = ino;
    entry->next = inode_table[hash];
    inode_table[hash] = entry;
}

/* Free inode table */
static void free_inode_table(void) {
    for (int i = 0; i < INODE_HASH_SIZE; i++) {
        inode_entry_t *entry = inode_table[i];
        while (entry) {
            inode_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        inode_table[i] = NULL;
    }
}

/* Shift ACL entries */
static int shift_acl(const char *path, acl_type_t type, int offset) {
    acl_t acl;
    acl_entry_t entry;
    int entry_id;
    int needs_update = 0;
    
    acl = acl_get_file(path, type);
    if (!acl) {
        if (errno == ENOTSUP || errno == ENOSYS) {
            /* ACLs not supported on this filesystem */
            return 0;
        }
        return -1;
    }
    
    /* Iterate through ACL entries */
    entry_id = ACL_FIRST_ENTRY;
    while (acl_get_entry(acl, entry_id, &entry) == 1) {
        entry_id = ACL_NEXT_ENTRY;
        acl_tag_t tag;
        
        if (acl_get_tag_type(entry, &tag) == -1) {
            acl_free(acl);
            return -1;
        }
        
        /* Only shift USER and GROUP entries */
        if (tag == ACL_USER || tag == ACL_GROUP) {
            void *qualifier = acl_get_qualifier(entry);
            if (qualifier) {
                uid_t *id = (uid_t *)qualifier;
                uid_t old_id = *id;
                uid_t new_id;
                
                /* Validate new ID - handle unsigned arithmetic carefully */
                if (offset < 0) {
                    if (old_id < (uid_t)(-offset)) {
                        fprintf(stderr, "Error: UID/GID would become negative\n");
                        acl_free(qualifier);
                        acl_free(acl);
                        return -1;
                    }
                    new_id = old_id - (uid_t)(-offset);
                } else {
                    new_id = old_id + (uid_t)offset;
                    if (new_id > MAX_UID_GID) {
                        fprintf(stderr, "Error: UID/GID would exceed %d\n", MAX_UID_GID);
                        acl_free(qualifier);
                        acl_free(acl);
                        return -1;
                    }
                }
                
                *id = new_id;
                if (acl_set_qualifier(entry, id) == -1) {
                    acl_free(qualifier);
                    acl_free(acl);
                    return -1;
                }
                needs_update = 1;
                acl_free(qualifier);
            }
        }
    }
    
    /* Apply updated ACL if needed */
    if (needs_update) {
        if (acl_set_file(path, type, acl) == -1) {
            acl_free(acl);
            return -1;
        }
    }
    
    acl_free(acl);
    return 0;
}

/* Process a single file/directory */
static int process_file(const char *fpath, const struct stat *sb,
                       int typeflag, struct FTW *ftwbuf) {
    (void)sb;       /* Unused - we call lstat ourselves */
    (void)typeflag; /* Unused - we check file type via stat */
    (void)ftwbuf;   /* Unused - we don't need traversal info */
    struct stat st;
    uid_t new_uid;
    gid_t new_gid;
    
    /* Get file stats without following symlinks */
    if (lstat(fpath, &st) == -1) {
        fprintf(stderr, "Error stating %s: %s\n", fpath, strerror(errno));
        g_errors++;
        return 0; /* Continue traversal */
    }
    
    /* Check if we've already processed this inode */
    if (inode_seen(st.st_dev, st.st_ino)) {
        return 0; /* Skip hardlinks we've already processed */
    }
    inode_mark_seen(st.st_dev, st.st_ino);
    
    /* Calculate new UIDs/GIDs - handle unsigned arithmetic carefully */
    if (g_offset < 0) {
        /* Converting to privileged - check for underflow */
        if (st.st_uid < (uid_t)(-g_offset) || st.st_gid < (gid_t)(-g_offset)) {
            fprintf(stderr, "Error: %s already privileged or not a container\n", fpath);
            g_errors++;
            return 1; /* Stop traversal */
        }
        new_uid = st.st_uid - (uid_t)(-g_offset);
        new_gid = st.st_gid - (gid_t)(-g_offset);
    } else {
        /* Converting to unprivileged - check for overflow */
        new_uid = st.st_uid + (uid_t)g_offset;
        new_gid = st.st_gid + (gid_t)g_offset;
        if (new_uid > MAX_UID_GID || new_gid > MAX_UID_GID) {
            fprintf(stderr, "Error: %s already unprivileged\n", fpath);
            g_errors++;
            return 1; /* Stop traversal */
        }
    }
    
    /* Change ownership */
    if (lchown(fpath, new_uid, new_gid) == -1) {
        fprintf(stderr, "Error changing ownership of %s: %s\n", fpath, strerror(errno));
        g_errors++;
        return 0; /* Continue anyway */
    }
    
    /* For non-symlinks, restore mode and update ACLs */
    if (!S_ISLNK(st.st_mode)) {
        /* Restore mode (chown may strip setuid/setgid) */
        if (chmod(fpath, st.st_mode) == -1) {
            fprintf(stderr, "Warning: could not restore mode for %s: %s\n", 
                    fpath, strerror(errno));
        }
        
        /* Update access ACL */
        if (shift_acl(fpath, ACL_TYPE_ACCESS, g_offset) == -1) {
            if (errno != ENOTSUP && errno != ENOSYS) {
                fprintf(stderr, "Warning: could not update ACL for %s: %s\n", 
                        fpath, strerror(errno));
            }
        }
        
        /* Update default ACL for directories */
        if (S_ISDIR(st.st_mode)) {
            if (shift_acl(fpath, ACL_TYPE_DEFAULT, g_offset) == -1) {
                if (errno != ENOTSUP && errno != ENOSYS) {
                    fprintf(stderr, "Warning: could not update default ACL for %s: %s\n", 
                            fpath, strerror(errno));
                }
            }
        }
    }
    
    g_files_processed++;
    if (g_files_processed % 1000 == 0) {
        printf("\rProcessed %"PRIu64" items...", g_files_processed);
        fflush(stdout);
    }
    
    return 0; /* Continue traversal */
}

/* Convert a filesystem path */
static int convert_path(const char *path, int offset) {
    struct stat st;
    
    printf("\nConverting: %s\n", path);
    
    /* Check if path exists */
    if (stat(path, &st) == -1) {
        fprintf(stderr, "Error: Path %s does not exist: %s\n", path, strerror(errno));
        return -1;
    }
    
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: Path %s is not a directory\n", path);
        return -1;
    }
    
    g_offset = offset;
    g_files_processed = 0;
    g_errors = 0;
    
    /* Walk the directory tree */
    if (nftw(path, process_file, 64, FTW_PHYS | FTW_MOUNT) == -1) {
        fprintf(stderr, "\nError walking directory tree: %s\n", strerror(errno));
        return -1;
    }
    
    printf("\rProcessed %"PRIu64" files (errors: %"PRIu64")    \n", 
           g_files_processed, g_errors);
    
    return g_errors > 0 ? -1 : 0;
}

/* Parse a storage specification and convert to actual path */
static int parse_storage_path(const char *storage_spec, char *path_out, size_t path_len) {
    /* Check if it's a ZFS volume (format: pool:subvol) or directory (starts with /) */
    if (storage_spec[0] == '/') {
        /* Direct directory path */
        snprintf(path_out, path_len, "%s", storage_spec);
        return 0;
    } else {
        /* Assume ZFS format: pool:subvol -> /pool/subvol */
        char pool[256], subvol[512];
        if (sscanf(storage_spec, "%255[^:]:%511s", pool, subvol) == 2) {
            snprintf(path_out, path_len, "/%s/%s", pool, subvol);
            return 0;
        }
    }
    
    fprintf(stderr, "Error: Could not parse storage specification: %s\n", storage_spec);
    return -1;
}

/* Extract storage specification from config line */
static int extract_storage_spec(const char *line, char *spec_out, size_t spec_len) {
    const char *start = strchr(line, ':');
    if (!start) return -1;
    start++; /* Skip the colon */
    
    /* Skip whitespace */
    while (*start && isspace(*start)) start++;
    
    /* Extract up to comma or end of line */
    const char *end = strchr(start, ',');
    size_t len;
    if (end) {
        len = end - start;
    } else {
        len = strlen(start);
        /* Remove trailing whitespace */
        while (len > 0 && isspace(start[len-1])) len--;
    }
    
    if (len >= spec_len) {
        fprintf(stderr, "Error: Storage specification too long\n");
        return -1;
    }
    
    strncpy(spec_out, start, len);
    spec_out[len] = '\0';
    
    return 0;
}

/* Read config file and extract paths */
static int read_config(const char *config_path, char paths[][MAX_PATH_LEN], 
                      int *num_paths, int *current_unprivileged) {
    FILE *fp;
    char line[MAX_LINE];
    
    *num_paths = 0;
    *current_unprivileged = -1;
    
    fp = fopen(config_path, "r");
    if (!fp) {
        fprintf(stderr, "Error opening config file %s: %s\n", 
                config_path, strerror(errno));
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        /* Remove trailing newline */
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';
        
        /* Stop at snapshot sections (lines starting with '[') */
        if (line[0] == '[') {
            break;
        }
        
        /* Check for unprivileged flag */
        if (strncmp(line, "unprivileged:", 13) == 0) {
            char *value = line + 13;
            while (*value && isspace(*value)) value++;
            *current_unprivileged = atoi(value);
            continue;
        }
        
        /* Check for rootfs or mp entries */
        if (strncmp(line, "rootfs:", 7) == 0 || 
            (strncmp(line, "mp", 2) == 0 && strchr(line, ':'))) {
            
            char storage_spec[512];
            char temp_path[MAX_PATH_LEN];
            
            if (extract_storage_spec(line, storage_spec, sizeof(storage_spec)) == 0) {
                if (*num_paths >= MAX_PATHS) {
                    fprintf(stderr, "Error: Too many mount points\n");
                    fclose(fp);
                    return -1;
                }
                
                if (parse_storage_path(storage_spec, temp_path, MAX_PATH_LEN) == 0) {
                    /* Check for duplicates */
                    int is_duplicate = 0;
                    for (int i = 0; i < *num_paths; i++) {
                        if (strcmp(paths[i], temp_path) == 0) {
                            is_duplicate = 1;
                            break;
                        }
                    }
                    
                    /* Only add if not a duplicate */
                    if (!is_duplicate) {
                        strncpy(paths[*num_paths], temp_path, MAX_PATH_LEN);
                        paths[*num_paths][MAX_PATH_LEN - 1] = '\0';
                        (*num_paths)++;
                    }
                }
            }
        }
    }
    
    fclose(fp);
    
    if (*current_unprivileged == -1) {
        fprintf(stderr, "Warning: Could not find 'unprivileged' flag in config\n");
    }
    
    return 0;
}

/* Update the unprivileged flag in the config file */
static int update_config(const char *config_path, int new_unprivileged) {
    FILE *fp_in, *fp_out;
    char line[MAX_LINE];
    char temp_path[MAX_PATH_LEN + 8]; /* +8 for ".tmp" and safety */
    int updated = 0;
    
    /* Create temporary file */
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", config_path);
    if (strlen(config_path) > MAX_PATH_LEN - 5) {
        fprintf(stderr, "Error: Config path too long\n");
        return -1;
    }
    
    fp_in = fopen(config_path, "r");
    if (!fp_in) {
        fprintf(stderr, "Error opening config file for reading: %s\n", strerror(errno));
        return -1;
    }
    
    fp_out = fopen(temp_path, "w");
    if (!fp_out) {
        fprintf(stderr, "Error creating temporary file: %s\n", strerror(errno));
        fclose(fp_in);
        return -1;
    }
    
    /* Copy file, updating unprivileged flag in main section only */
    int in_snapshot = 0;
    while (fgets(line, sizeof(line), fp_in)) {
        /* Detect snapshot sections */
        if (line[0] == '[') {
            /* If we haven't updated yet and entering snapshots, add it now */
            if (!updated && !in_snapshot) {
                fprintf(fp_out, "unprivileged: %d\n", new_unprivileged);
                updated = 1;
            }
            in_snapshot = 1;
            fputs(line, fp_out);
        } else if (!in_snapshot && strncmp(line, "unprivileged:", 13) == 0) {
            /* Update unprivileged flag in main section */
            fprintf(fp_out, "unprivileged: %d\n", new_unprivileged);
            updated = 1;
        } else {
            fputs(line, fp_out);
        }
    }
    
    /* If unprivileged flag wasn't found and no snapshots, add it at the end */
    if (!updated) {
        fprintf(fp_out, "unprivileged: %d\n", new_unprivileged);
    }
    
    fclose(fp_in);
    fclose(fp_out);
    
    /* Replace original with temporary */
    if (rename(temp_path, config_path) == -1) {
        fprintf(stderr, "Error replacing config file: %s\n", strerror(errno));
        unlink(temp_path);
        return -1;
    }
    
    return 0;
}

/* Check if container is running */
static int is_container_running(int container_id) {
    char path[512];
    DIR *dir;
    
    /* Check multiple cgroup locations for running container */
    /* Try cgroup v2 first (modern systems) */
    snprintf(path, sizeof(path), "/sys/fs/cgroup/lxc.monitor.%d", container_id);
    dir = opendir(path);
    if (dir) {
        closedir(dir);
        return 1;
    }
    
    /* Try cgroup v1 systemd path */
    snprintf(path, sizeof(path), "/sys/fs/cgroup/systemd/lxc/%d", container_id);
    dir = opendir(path);
    if (dir) {
        closedir(dir);
        return 1;
    }
    
    /* Try alternative cgroup v1 path */
    snprintf(path, sizeof(path), "/sys/fs/cgroup/lxc/%d", container_id);
    dir = opendir(path);
    if (dir) {
        closedir(dir);
        return 1;
    }
    
    /* Check if pct status command works (Proxmox-specific) */
    snprintf(path, sizeof(path), "pct status %d 2>/dev/null | grep -q 'status: running'", container_id);
    if (system(path) == 0) {
        return 1;
    }
    
    /* Check for lock file */
    snprintf(path, sizeof(path), "/var/lock/lxc/var/lib/lxc/%d", container_id);
    if (access(path, F_OK) == 0) {
        return 1;
    }
    
    return 0;
}

/* Print usage */
static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <container_number> <privileged|unprivileged>\n", prog);
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s 111 unprivileged   # Convert container 111 to unprivileged\n", prog);
    fprintf(stderr, "  %s 111 privileged     # Convert container 111 to privileged\n", prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    char config_path[MAX_PATH_LEN];
    char paths[MAX_PATHS][MAX_PATH_LEN];
    int num_paths;
    int current_unprivileged;
    int target_unprivileged;
    int offset;
    int container_num;
    
    /* Check arguments */
    if (argc != 3) {
        usage(argv[0]);
    }
    
    /* Parse container number */
    container_num = atoi(argv[1]);
    if (container_num <= 0) {
        fprintf(stderr, "Error: Invalid container number: %s\n", argv[1]);
        usage(argv[0]);
    }
    
    /* Parse target mode */
    if (strcmp(argv[2], "unprivileged") == 0) {
        target_unprivileged = 1;
        offset = UID_GID_OFFSET;
    } else if (strcmp(argv[2], "privileged") == 0) {
        target_unprivileged = 0;
        offset = -UID_GID_OFFSET;
    } else {
        fprintf(stderr, "Error: Mode must be 'privileged' or 'unprivileged'\n");
        usage(argv[0]);
    }
    
    /* Check if container is running */
    if (is_container_running(container_num)) {
        fprintf(stderr, "Error: Container %d is currently running!\n", container_num);
        fprintf(stderr, "Please stop the container before conversion:\n");
        fprintf(stderr, "  pct stop %d\n", container_num);
        return 1;
    }
    
    /* Construct config path */
    snprintf(config_path, sizeof(config_path), "/etc/pve/lxc/%d.conf", container_num);
    
    /* Read configuration */
    printf("Reading configuration from: %s\n", config_path);
    if (read_config(config_path, paths, &num_paths, &current_unprivileged) == -1) {
        return 1;
    }
    
    if (num_paths == 0) {
        fprintf(stderr, "Error: No filesystems found in configuration\n");
        return 1;
    }
    
    printf("Found %d filesystem(s) to convert\n", num_paths);
    for (int i = 0; i < num_paths; i++) {
        printf("  [%d] %s\n", i+1, paths[i]);
    }
    
    /* Check current state */
    if (current_unprivileged != -1) {
        printf("\nCurrent state: %s\n", current_unprivileged ? "unprivileged" : "privileged");
        printf("Target state:  %s\n", target_unprivileged ? "unprivileged" : "privileged");
        
        if (current_unprivileged == target_unprivileged) {
            printf("\nContainer is already in the target state!\n");
            return 0;
        }
    }
    
    printf("UID/GID offset: %+d\n", offset);
    
    /* Require confirmation */
    printf("\nWARNING: This operation will modify file ownership.\n");
    printf("Make sure the container is stopped!\n");
    printf("\nProceed? [y/N] ");
    fflush(stdout);
    
    char answer[10];
    if (!fgets(answer, sizeof(answer), stdin) || 
        (answer[0] != 'y' && answer[0] != 'Y')) {
        printf("Aborted.\n");
        return 0;
    }
    
    /* Check if running as root */
    if (geteuid() != 0) {
        fprintf(stderr, "\nError: This program must be run as root\n");
        return 1;
    }
    
    /* Convert each filesystem */
    int overall_result = 0;
    for (int i = 0; i < num_paths; i++) {
        if (convert_path(paths[i], offset) == -1) {
            fprintf(stderr, "Error converting %s\n", paths[i]);
            overall_result = 1;
        }
    }
    
    if (overall_result != 0) {
        fprintf(stderr, "\nConversion completed with errors.\n");
        fprintf(stderr, "NOT updating configuration file.\n");
        free_inode_table();
        return 1;
    }
    
    /* Update configuration file */
    printf("\nUpdating configuration file...\n");
    if (update_config(config_path, target_unprivileged) == -1) {
        fprintf(stderr, "Error updating configuration file\n");
        free_inode_table();
        return 1;
    }
    
    printf("\n✓ Conversion completed successfully!\n");
    printf("Container %d is now %s\n", container_num, 
           target_unprivileged ? "unprivileged" : "privileged");
    
    free_inode_table();
    return 0;
}
