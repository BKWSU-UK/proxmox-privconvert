# proxmox-privconvert

Fast C program to convert Proxmox LXC containers between privileged and unprivileged modes.

## Features

- **Fast**: Written in C with optimized file traversal
- **Safe**: Tracks inodes to handle hardlinks correctly
- **Complete**: Handles UIDs, GIDs, ACLs, and special permissions (setuid/setgid)
- **Automatic**: Reads Proxmox LXC config files directly
- **Standalone**: Statically compiled with no runtime dependencies
- **Smart**: Supports both ZFS and directory-based storage

## Building

### Requirements

- GCC compiler
- libacl development files (`libacl1-dev` on Debian/Ubuntu)

### Compile

```bash
make
```

This produces a statically-linked `privconvert` executable with no runtime dependencies.

For a dynamically-linked version (development):
```bash
make dynamic
```

## Usage

**Important**: Always stop the container before conversion!

```bash
# Convert container 111 to unprivileged mode
./privconvert 111 unprivileged

# Convert container 111 to privileged mode
./privconvert 111 privileged
```

The program will:
1. Read `/etc/pve/lxc/<container>.conf`
2. Extract all filesystem paths (rootfs and mount points) from the main config
3. Ignore snapshot sections (preserves snapshots unchanged)
4. Deduplicate filesystem paths automatically
5. Handle both ZFS volumes and directory paths
6. Convert all UIDs/GIDs by ±100000
7. Update ACLs (both access and default)
8. Preserve setuid/setgid bits
9. Update the `unprivileged` flag in the main config section only

## How It Works

### UID/GID Conversion

- **To unprivileged**: Adds 100000 to all UIDs/GIDs
- **To privileged**: Subtracts 100000 from all UIDs/GIDs

### Path Detection

- **ZFS volumes**: `pool:subvol-name` → `/pool/subvol-name`
- **Directories**: Direct paths like `/var/lib/lxc/...`

### Snapshot Handling

- Automatically detects and stops at snapshot sections in config files
- Only processes the current/active container configuration
- Updates `unprivileged` flag in main section only
- Preserves all snapshot data unchanged
- Deduplicates paths to avoid processing filesystems multiple times

### Safety Features

- **Detects running containers** - refuses to run if container is active
- **Confirms before making changes** - interactive prompt with state display
- **Tracks inodes** - handles hardlinks correctly (only processes each file once)
- **Validates ranges** - ensures UIDs/GIDs stay in valid ranges
- **Preserves permissions** - maintains file permissions and special bits (setuid/setgid)
- **Updates ACLs** - handles both access and default ACLs correctly

## Installation

```bash
sudo make install
```

This installs to `/usr/local/bin/privconvert`.

## Example

### Successful Conversion

```bash
$ sudo ./privconvert 111 unprivileged
Reading configuration from: /etc/pve/lxc/111.conf
Found 2 filesystem(s) to convert
  [1] /Proxmox-LXC-1-ZFS/subvol-111-disk-0
  [2] /Proxmox-LXC-1-ZFS/subvol-111-disk-1

Current state: privileged
Target state:  unprivileged
UID/GID offset: +100000

WARNING: This operation will modify file ownership.
Make sure the container is stopped!

Proceed? [y/N] y

Converting: /Proxmox-LXC-1-ZFS/subvol-111-disk-0
Processed 15234 files (errors: 0)

Converting: /Proxmox-LXC-1-ZFS/subvol-111-disk-1
Processed 523 files (errors: 0)

Updating configuration file...

✓ Conversion completed successfully!
Container 111 is now unprivileged
```

### Running Container Protection

```bash
$ sudo ./privconvert 111 unprivileged
Error: Container 111 is currently running!
Please stop the container before conversion:
  pct stop 111
```

