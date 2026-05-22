# Disk Forensics

## Trigger

Load when presented with: raw disk images (.dd, .img, .raw, .iso), forensic image formats (.E01, .AFF, .S01), virtual disk files (.vmdk, .vhd, .qcow2, .ova), filesystem images (ext2/3/4, XFS, BTRFS, ZFS, FAT16/32, NTFS, HFS+, APFS), archive files with embedded filesystems, or challenges involving deleted files, encrypted volumes, partition recovery, or data carving.

## Attack Surface

Evidence characteristics: block-level device images, filesystem type determines tool selection, OS version and architecture affect artifact locations, endianness of filesystem metadata, presence/absence of journaling impacts recovery reliability, sector size (512 vs 4096), partition table type (MBR vs GPT), and whether the image is a full disk or single partition. Encrypted volumes (LUKS, TrueCrypt, VeraCrypt, BitLocker) present additional extraction layers.

## Decision Tree

1. Identify image type: `file disk.img` and `xxd disk.img | head`
2. Check partition table: `fdisk -l disk.img`, `gdisk -l disk.img`, `testdisk disk.img`
3. Try loop mount: `sudo mount -o loop,ro disk.img /mnt` or `kpartx -av disk.img`
4. List files including deleted: `fls -r -d image.dd`
5. Extract by inode: `icat image.dd <inode> > recovered`
6. Carve deleted files: `photorec image.dd` or `foremost -i image.dd`
7. If encrypted: identify volume type, recover key from memory, or brute-force
8. If filesystem metadata damaged: manual inode parsing, block-level extraction

## Techniques

### Filesystem Mounting and Inspection

```bash
# Loop mount with read-only
sudo mount -o loop,ro disk.img /mnt/evidence

# Auto-detect partition mapping
kpartx -av disk.img
sudo mount /dev/mapper/loop0p1 /mnt/evidence

# Sleuth Kit file listing
fls -r -d image.dd              # Recursive, include deleted
icat image.dd <inode> > file    # Extract file by inode
istat image.dd <inode>          # Inode metadata

# Timeline analysis
ils -m image.dd > body.txt
mactime -b body.txt > timeline.csv
```

### VM and Virtual Disk Analysis

```bash
# OVA is TAR archive
tar -xvf machine.ova

# 7z reads VMDK directly (no mount)
7z l disk.vmdk | head -100
7z x disk.vmdk -oextracted "Windows/System32/config/SAM" -r

# VMware snapshot conversion
vmss2core -W snapshot.vmss snapshot.vmem    # creates memory.dmp
```

### Deleted File Recovery

```bash
# Sleuth Kit (preserves file boundaries)
fls -r -d fat16.img              # Shows deleted entries with *
icat fat16.img 4 > recovered.png # Extract by inode

# Carving (ignores filesystem)
photorec image.dd
foremost -i image.dd -o carved/
scalpel image.dd -o carved/

# FAT: deletion marks first byte as 0xE5, clusters as free
# Ext2/3/4: run fsck to reconnect orphaned inodes
e2fsck -y disk.img               # Reconnects orphaned inodes to /lost+found
sudo mount -o loop disk.img /mnt
ls /mnt/lost+found/              # Recovered inodes with numeric names

# Alternative: debugfs interactive exploration
debugfs disk.img
debugfs: lsdel                   # List deleted inodes
debugfs: dump <inode> /tmp/out   # Extract by inode
```

### BTRFS Snapshot Recovery

```bash
# List subvolumes including snapshots
sudo losetup /dev/loop0 disk.img
sudo btrfs subvolume list /dev/loop0

# Mount backup subvolume
sudo mount -o subvol=@backup /dev/loop0 /mnt/backup

# Alternative: mount by subvolume ID
sudo mount -o subvolid=257 /dev/loop0 /mnt/backup
```

### FAT16 Free Space Data Recovery

```python
import struct
with open("disk.img", "rb") as f:
    boot = f.read(512)
    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    sectors_per_cluster = boot[13]
    reserved_sectors = struct.unpack_from("<H", boot, 14)[0]
    num_fats = boot[16]
    sectors_per_fat = struct.unpack_from("<H", boot, 22)[0]
    root_entries = struct.unpack_from("<H", boot, 17)[0]
    cluster_size = bytes_per_sector * sectors_per_cluster
    fat_start = reserved_sectors * bytes_per_sector
    data_start = fat_start + (num_fats * sectors_per_fat * bytes_per_sector)
    f.seek(fat_start)
    fat = f.read(sectors_per_fat * bytes_per_sector)
    free_data = b""
    for cluster in range(2, len(fat) // 2):
        entry = struct.unpack_from("<H", fat, cluster * 2)[0]
        if entry == 0x0000:
            offset = data_start + (cluster - 2) * cluster_size
            f.seek(offset)
            free_data += f.read(cluster_size)
    if b"CTF{" in free_data:
        idx = free_data.index(b"CTF{")
        print(free_data[idx:idx+100])
```

### NTFS Alternate Data Streams

```bash
# List ADS on mounted NTFS
getfattr -R -n ntfs.streams.list /mnt/ntfs/

# From raw image with Sleuth Kit
fls -r ntfs_image.dd | grep ":"     # ADS entries contain ":"
istat ntfs_image.dd 66               # Show all attributes for inode
icat ntfs_image.dd 66-128-4 > hidden # Extract ADS by full address
```

### APFS Snapshot Historical Recovery

```python
import struct, subprocess
with open("apfs_partition.img", "rb") as f:
    mm = f.read()
pos = 0
snaps = []
while True:
    idx = mm.find(b"APSB", pos)
    if idx < 0:
        break
    xid = struct.unpack_from("<Q", mm, idx - 16)[0]
    blk = (idx - 32) // 4096
    snaps.append((xid, blk))
    pos = idx + 1
# Read inode across all snapshot XIDs
for xid, blk in sorted(set(snaps)):
    out = subprocess.check_output(
        ["icat", "-f", "apfs", "-P", "apfs", "-B", str(blk),
         "apfs_partition.img", "449414"])
    print(f"XID {xid}: {out[:64]}")
```

### RAID 5 XOR Recovery

```python
with open('disk1.img', 'rb') as f: disk1 = f.read()
with open('disk3.img', 'rb') as f: disk3 = f.read()
disk2 = bytes(a ^ b for a, b in zip(disk1, disk3))
with open('disk2.img', 'wb') as f: f.write(disk2)
losetup /dev/loop0 disk1.img && losetup /dev/loop1 disk2.img && losetup /dev/loop2 disk3.img
mdadm --create /dev/md0 --level=5 --raid-devices=3 /dev/loop0 /dev/loop1 /dev/loop2
```

### LUKS Master Key from Memory

```bash
aeskeyfind memory.elf               # Detect AES key schedules
echo "deadbeef..." | xxd -r -p > master.key
cryptsetup luksAddKey --master-key-file master.key /dev/mapper/volume
```

### ZIP Repair and Cracking

```python
import struct
with open('broken.zip', 'rb') as f:
    data = bytearray(f.read())
# Fix Local File Header filename length
lfh = data.index(b'PK\x03\x04')
struct.pack_into('<H', data, lfh + 26, 8)
cde = data.index(b'PK\x01\x02')
struct.pack_into('<H', data, cde + 28, 8)
with open('fixed.zip', 'wb') as f:
    f.write(data)

# ZipCrypto known-plaintext attack
bkcrack -C secret.zip -c target.txt -p plaintext.txt
bkcrack -C secret.zip -k <k0> <k1> <k2> -d decrypted.bin
```

### XFS Reconstruction from Corrupted Metadata

```bash
# Extract file from known inode extent
dd if=disk.img bs=4096 skip=104333 count=256 of=recovered.jpg

# Use xfs_db for interactive analysis
xfs_db -r disk.img
xfs_db> inode <num>
xfs_db> print
```

### Deleted .git Recovery from FAT

```bash
fls -r disk.img | grep '\*'            # List deleted entries
icat disk.img 5 > HEAD                  # Extract deleted inodes
icat disk.img 6 > config
mkdir -p recovered/.git/objects/ab/
git fsck --full                          # Find dangling commits
git log --all                            # Show all commits
```

### Git Repository Hidden History

```bash
git reflog --all                         # Find squashed commits
git fsck --unreachable --no-reflogs      # Orphaned objects
git show <commit-hash>                   # Inspect each
```

## Bypass

When standard tools fail: manually parse filesystem structures using struct from raw bytes, repair corrupted superblocks by reconstructing from known-good values, compute filesystem checksums (Fletcher4 for ZFS, CRC32 for XZ headers), use `testdisk` for partition table reconstruction, carve via magic bytes when filesystem is destroyed, extract via block-level access when metadata is corrupted, decompress multiple layers recursively (nested matryoshka extraction), handle anti-carving measures like null-byte interleaving by extracting only even-positioned bytes.

## Verification

Confirm by: flag text found in recovered files, image renders correctly (.png, .jpg), archive extracts (zip, tar, 7z), encrypted volume mounts successfully, git repository yields commits with flag, file matches expected hash, data structure decodes to human-readable content.

## Pitfalls

Assuming the filesystem type from the file extension rather than `file` output. Forgetting to mount read-only (`-o ro`). Not checking for alternate subvolumes/snapshots (BTRFS, APFS, ZFS). Overlooking NTFS alternate data streams (check with `fls -r | grep ":"`). Running fsck without `-y` flag. Assuming deleted files are unrecoverable (clusters marked free but data persists). Not verifying file carving results (false positives from magic byte collisions). Ignoring partition table (attempting to mount the whole disk instead of the partition). Forgetting to check for multiple layers of nesting or compression. Timestamp timezone interpretation errors. Not checking git reflog for rewritten history.
