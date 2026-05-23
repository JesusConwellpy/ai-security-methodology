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
9. If exFAT: parse VBR for cluster bitmap offset, enumerate directory entries (including deleted 0xE5-marked), scan free cluster bitmap for residual data in unallocated clusters
10. If ReFS: parse VBR at offset 0 for object ID tables, walk B+ tree metadata for directory/file entries, extract from integrity stream checkpoints
11. If F2FS: locate superblock at offset 1024, extract NAT for inode-to-block mapping, scan SIT for segment utilization, replay checkpoint area for recent inode updates

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
    root_dir_sectors = ((root_entries * 32) + bytes_per_sector - 1) // bytes_per_sector
    total_sectors = struct.unpack_from("<H", boot, 19)[0]
    if total_sectors == 0:
        total_sectors = struct.unpack_from("<I", boot, 32)[0]
    data_start = fat_start + (num_fats * sectors_per_fat * bytes_per_sector) + (root_dir_sectors * bytes_per_sector)
    f.seek(fat_start)
    fat = f.read(sectors_per_fat * bytes_per_sector)
    data_sectors = total_sectors - reserved_sectors - (num_fats * sectors_per_fat) - root_dir_sectors
    data_clusters = data_sectors // sectors_per_cluster
    free_data = b""
    for cluster in range(2, 2 + data_clusters):
        entry = struct.unpack_from("<H", fat, cluster * 2)[0]
        if entry == 0x0000:
            offset = data_start + (cluster - 2) * cluster_size
            f.seek(offset)
            free_data += f.read(cluster_size)
    if b"CTF{" in free_data:
        idx = free_data.index(b"CTF{")
        print(free_data[idx:idx+100])
```

### exFAT Directory Entry and Deleted File Recovery

```bash
# Identify exFAT filesystem
file disk.img
# Parse VBR for key parameters
python3 << 'EOF'
import struct
with open("disk.img", "rb") as f:
    vbr = f.read(512)
# exFAT VBR at sector 0 (signature at offset 3: "EXFAT   ")
bytes_per_sector = struct.unpack_from("<I", vbr, 108)[0]
sectors_per_cluster = vbr[116]
cluster_size = bytes_per_sector * sectors_per_cluster
num_fats = vbr[117]
fat_offset = struct.unpack_from("<I", vbr, 80)[0]
fat_length = struct.unpack_from("<I", vbr, 84)[0]
cluster_heap = struct.unpack_from("<I", vbr, 88)[0]
root_cluster = struct.unpack_from("<I", vbr, 96)[0]
print(f"Cluster size: {cluster_size}, Root cluster: {root_cluster}, FAT at: {fat_offset}")
EOF

# List directory entries including deleted
fls -r -d exfat.img

# Scan free cluster bitmap for residual data
python3 << 'EOF'
import struct
with open("disk.img", "rb") as f:
    vbr = f.read(512)
    bps = struct.unpack_from("<I", vbr, 108)[0]
    spc = vbr[116]
    cs = bps * spc
    bmp_off = struct.unpack_from("<I", vbr, 80)[0] + struct.unpack_from("<I", vbr, 84)[0]
    bmp_len = (struct.unpack_from("<I", vbr, 92)[0] + 7) // 8
    f.seek(bmp_off * bps)
    bitmap = f.read(bmp_len)
    data_start = struct.unpack_from("<I", vbr, 88)[0] * bps
    free_clusters = [i for i in range(len(bitmap) * 8) if not (bitmap[i // 8] >> (i % 8)) & 1]
    for c in free_clusters[:20]:
        f.seek(data_start + c * cs)
        data = f.read(min(cs, 4096))
        if b"CTF{" in data or b"flag" in data:
            print(f"Cluster {c}: {data[:200]}")
EOF

# Sleuth Kit extraction of exFAT
icat exfat.img <inode> > recovered.bin
```

### ReFS B+ Tree Structure Analysis

```bash
# Identify ReFS partition
dd if=disk.img bs=512 count=1 | xxd | grep -q "ReFS" && echo "ReFS detected"

# Parse ReFS VBR, walk B+ tree metadata
python3 << 'EOF'
import struct
with open("disk.img", "rb") as f:
    vbr = f.read(512)
signature = vbr[3:7]
if signature != b"ReFS":
    print("Not ReFS"); exit(1)
bytes_per_sector = struct.unpack_from("<H", vbr, 11)[0]
sectors_per_cluster = vbr[13]
cluster_size = bytes_per_sector * sectors_per_cluster
obj_id_table_cluster = struct.unpack_from("<I", vbr, 0x30)[0]
integrity_enabled = vbr[0x38] & 1
print(f"Cluster: {cluster_size}, Object ID table at cluster: {obj_id_table_cluster}")
f.seek(obj_id_table_cluster * cluster_size)
page = f.read(cluster_size)
page_magic = page[:4]
entry_count = struct.unpack_from("<H", page, 8)[0]
for i in range(entry_count):
    entry = page[0x30 + i * 0x38:0x30 + (i + 1) * 0x38]
    obj_id = struct.unpack_from("<Q", entry, 0)[0]
    file_ref = struct.unpack_from("<Q", entry, 8)[0]
    print(f"Object ID: {obj_id}, File reference: {file_ref}")
EOF

# Integrity stream checkpoint scan for data recovery
python3 << 'EOF'
import struct
with open("disk.img", "rb") as f:
    data = f.read()
for ckpt_marker in [b"CKPT", b"CHKPT"]:
    pos = 0
    while True:
        idx = data.find(ckpt_marker, pos)
        if idx < 0:
            break
        seq = struct.unpack_from("<I", data, idx + 4)[0]
        print(f"Checkpoint at offset {idx}, sequence {seq}")
        pos = idx + 1
EOF
```

### F2FS Flash Filesystem Checkpoint Recovery

```bash
# Identify F2FS superblock at offset 1024
dd if=disk.img bs=1024 skip=1 count=1 | xxd | head -4
# F2FS magic at offset 0: "\x10\x20\xF5\xF2"

# Parse superblock, NAT, SIT structures
python3 << 'EOF'
import struct
with open("disk.img", "rb") as f:
    f.seek(1024)
    sb = f.read(512)
magic = struct.unpack_from("<I", sb, 0)[0]
if magic != 0xF2F52010:
    print("Not F2FS"); exit(1)
log_blocksize = struct.unpack_from("<I", sb, 16)[0]
block_size = 1 << log_blocksize
segment_count = struct.unpack_from("<I", sb, 24)[0]
nat_blkaddr = struct.unpack_from("<I", sb, 68)[0]
sit_blkaddr = struct.unpack_from("<I", sb, 76)[0]
main_blkaddr = struct.unpack_from("<I", sb, 100)[0]
print(f"Block: {block_size}, Segments: {segment_count}, NAT: {nat_blkaddr}, SIT: {sit_blkaddr}")

# Read NAT entries (inode -> block mapping)
f.seek(nat_blkaddr * block_size)
nat_block = f.read(block_size)
for i in range(min(20, (block_size - 8) // 9)):
    # NAT entry format: node_id(4) + node_ino(4) + version(1) = 9 bytes packed
    entry = nat_block[8 + i * 9:8 + (i + 1) * 9]
    node_id, node_ino, version = struct.unpack_from('<IBI', entry, 0)
    if node_ino:
        print(f"Inode {node_ino} at node_id {node_id}, version={version}")

# Scan SIT for segment utilization
f.seek(sit_blkaddr * block_size)
sit_entries = struct.unpack_from("<" + "I" * (block_size // 4), f.read(block_size))
valid_blocks = [i for i, v in enumerate(sit_entries) if v & 0x1FFF]
print(f"Segments with valid data: {len(valid_blocks)}")
EOF

# Mount F2FS image (requires kernel module)
sload.f2fs disk.img /mnt/f2fs
ls /mnt/f2fs

# Checkpoint-based recovery for crashed filesystem
fsck.f2fs disk.img
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
```

```bash
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
