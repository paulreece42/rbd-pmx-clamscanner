# RBD ClamAV Scanner for Proxmox VMs

A Python tool that scans Proxmox virtual machines for malware using ClamAV by mounting Ceph RBD snapshots. The scanner creates read-only snapshots of VM disks, maps them via RBD, and scans the filesystems without affecting running VMs.

## Features

- **Non-intrusive scanning**: Scans VMs via read-only snapshots without requiring VM shutdown
- **Automatic snapshot management**: Creates and cleans up snapshots automatically
- **LVM support**: Detects and activates LVM volumes inside VM disks
- **Multiple filesystem support**: ext2/3/4, XFS, NTFS, and vfat
- **Flexible filtering**: Scan specific VMs, exclude VMs, or filter by node
- **Detailed reports**: Generates timestamped scan reports for each disk
- **Robust error handling**: Continues scanning other VMs/disks on failures
- **Resource cleanup**: Always unmaps RBD devices and deletes snapshots, even on errors

## Requirements

### System Dependencies

```bash
# Debian/Ubuntu
apt install ceph-common clamav-daemon lvm2 ntfs-3g

# RHEL/Rocky/AlmaLinux
dnf install ceph-common clamav clamd lvm2 ntfs-3g
```

Required system tools:
- `rbd` - Ceph RBD client for mapping block devices
- `clamdscan` - ClamAV daemon scanner
- `lvm2` - LVM tools (pvscan, vgchange, lvs, pvs)
- `ntfs-3g` - NTFS filesystem support
- `lsblk`, `blkid`, `mount` - Standard Linux utilities

### Python Dependencies

```bash
pip install -r requirements.txt
```

Only requires `proxmoxer` for Proxmox API communication.

## Installation

```bash
git clone <repository-url>
cd rbdclamscan
pip install -r requirements.txt
```

Ensure the ClamAV daemon is running:

```bash
systemctl enable --now clamav-daemon
# or
systemctl enable --now clamd@scan
```

## Configuration

Configuration can be provided via CLI arguments, environment variables, or a config file. Priority order (highest to lowest):

1. CLI arguments
2. Environment variables
3. Config file

### CLI Arguments

```
Usage: rbdclamscan.py [OPTIONS]

Options:
  -c, --config FILE      Path to config file
  --host HOST            Proxmox host (hostname or IP)
  --user USER            Proxmox user (format: user@realm)
  --token-name NAME      API token name
  --token-value VALUE    API token value
  --ceph-user USER       Ceph client user for RBD mapping (default: admin)
  --report-dir DIR       Directory for scan reports (default: /var/log/rbdclamscan)
  --vmid VMID            Scan specific VM(s) - can be repeated
  --exclude-vmid VMID    Exclude VM(s) from scan - can be repeated
  --node NODE            Scan VMs on specific node(s) - can be repeated
  --verify-ssl           Verify SSL certificates (default: disabled)
  -v, --verbose          Enable verbose/debug logging
```

### Environment Variables

```bash
export PROXMOX_HOST=proxmox.example.com
export PROXMOX_USER=scanner@pve
export PROXMOX_TOKEN_NAME=clamscan
export PROXMOX_TOKEN_VALUE=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export CEPH_USER=admin
export CLAMSCAN_REPORT_DIR=/var/log/rbdclamscan/reports
```

### Config File

Create a config file (e.g., `/etc/rbdclamscan/config.ini`):

```ini
[rbdclamscan]
proxmox_host = proxmox.example.com
proxmox_user = scanner@pve
proxmox_token_name = clamscan
proxmox_token_value = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ceph_user = admin
report_dir = /var/log/rbdclamscan/reports
snapshot_name = clamscan

# Optional filters (comma-separated)
# include_vmids = 100,101,102
# exclude_vmids = 999
# include_nodes = pve1,pve2
```

See `config.ini.example` for a template.

## Proxmox API Token Setup

Create an API token for the scanner with minimal required permissions:

### Via Proxmox UI

1. Navigate to **Datacenter** > **Permissions** > **API Tokens**
2. Click **Add**
3. Select user (e.g., `scanner@pve`)
4. Enter token ID (e.g., `clamscan`)
5. Uncheck **Privilege Separation** to inherit user permissions
6. Copy the displayed token value (shown only once)

### Via CLI

```bash
# Create a dedicated user (optional)
pveum user add scanner@pve

# Create the API token
pveum user token add scanner@pve clamscan --privsep=0

# Grant required permissions
pveum aclmod / -user scanner@pve -role PVEAuditor
pveum aclmod /vms -user scanner@pve -role PVEVMAdmin
```

### Required Permissions

- `VM.Audit` - Read VM configuration
- `VM.Snapshot` - Create and delete snapshots

## Usage

### Scan All VMs

```bash
./rbdclamscan.py --config /etc/rbdclamscan/config.ini
```

### Scan Specific VMs

```bash
./rbdclamscan.py --config /etc/rbdclamscan/config.ini --vmid 100 --vmid 101
```

### Scan VMs on Specific Nodes

```bash
./rbdclamscan.py --config /etc/rbdclamscan/config.ini --node pve1 --node pve2
```

### Exclude VMs from Scan

```bash
./rbdclamscan.py --config /etc/rbdclamscan/config.ini --exclude-vmid 999
```

### Verbose Output

```bash
./rbdclamscan.py --config /etc/rbdclamscan/config.ini --verbose
```

### Using Environment Variables

```bash
export PROXMOX_HOST=proxmox.example.com
export PROXMOX_USER=scanner@pve
export PROXMOX_TOKEN_NAME=clamscan
export PROXMOX_TOKEN_VALUE=your-token-value

./rbdclamscan.py --vmid 100
```

## How It Works

The scanner follows this workflow for each VM:

```
1. Create Proxmox snapshot "clamscan"
   └── Ensures consistent disk state

2. For each RBD disk in VM config:
   ├── Map RBD snapshot read-only
   │   └── rbd map --read-only pool/image@clamscan
   │
   ├── Discover partitions (lsblk)
   │
   └── For each partition:
       ├── If LVM: activate VG, process each LV
       ├── Mount filesystem read-only
       ├── Run clamdscan --fdpass --multiscan
       ├── Save report to report_dir
       └── Unmount filesystem

   └── Unmap RBD device

3. Delete Proxmox snapshot "clamscan"
```

### Supported Disk Configurations

- **Disk interfaces**: scsi, virtio, ide, sata
- **Storage format**: Ceph RBD (pool:vm-XXX-disk-N)
- **Partition schemes**: MBR, GPT
- **Volume managers**: LVM2
- **Filesystems**: ext2, ext3, ext4, XFS, NTFS, vfat

### Mount Options

Filesystems are mounted read-only with recovery disabled:

| Filesystem | Mount Options |
|------------|---------------|
| ext2/3/4   | `ro,noload,norecovery` |
| XFS        | `ro,norecovery` |
| NTFS       | `ro` (via ntfs-3g) |
| vfat       | `ro` |

## Reports

Scan reports are saved to the configured report directory with the naming format:

```
{vm_name}_{disk}_{timestamp}.log
```

Example: `webserver_scsi0_rbd0p1_20240115_143022.log`

Report contents:
```
VM: webserver
Disk: scsi0_rbd0p1
Timestamp: 20240115_143022
Mount Point: /tmp/rbdclamscan_12345__dev_rbd0p1
------------------------------------------------------------
/tmp/rbdclamscan_12345__dev_rbd0p1/etc/passwd: OK
/tmp/rbdclamscan_12345__dev_rbd0p1/var/www/malware.php: Eicar-Test-Signature FOUND
...
```

### Exit Codes

ClamAV scan results:
- `0` - No infections found
- `1` - Infections found
- `2` - Scanner error

## Verification

### Test Proxmox Connection

```bash
./rbdclamscan.py --config /etc/rbdclamscan/config.ini --verbose 2>&1 | head -20
```

### Test Single VM

```bash
./rbdclamscan.py --config /etc/rbdclamscan/config.ini --vmid 100 --verbose
```

### Verify Cleanup

After scanning, verify no resources are left behind:

```bash
# Check for mapped RBD devices (should be empty)
rbd showmapped

# Check for leftover mount points
mount | grep rbdclamscan

# Check for activated VGs from scanned VMs
vgs
```

### Test with EICAR

To test malware detection, place the EICAR test file in a VM before scanning:

```bash
# Inside the VM
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
```

Then run the scanner - it should detect the test file.

## Scheduling

### Systemd Timer

Create `/etc/systemd/system/rbdclamscan.service`:

```ini
[Unit]
Description=RBD ClamAV Scanner for Proxmox VMs
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/rbdclamscan.py --config /etc/rbdclamscan/config.ini
```

Create `/etc/systemd/system/rbdclamscan.timer`:

```ini
[Unit]
Description=Weekly RBD ClamAV Scan

[Timer]
OnCalendar=Sun 02:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer:

```bash
systemctl enable --now rbdclamscan.timer
```

### Cron

```bash
# Weekly scan on Sunday at 2 AM
0 2 * * 0 /usr/local/bin/rbdclamscan.py --config /etc/rbdclamscan/config.ini >> /var/log/rbdclamscan/cron.log 2>&1
```

## Troubleshooting

### "rbd: map failed: Operation not permitted"

Ensure the Ceph client user has read access to the pool:

```bash
ceph auth caps client.admin mon 'allow r' osd 'allow r pool=your-pool'
```

### "clamdscan: Can't connect to clamd"

Start the ClamAV daemon:

```bash
systemctl start clamav-daemon
# or
systemctl start clamd@scan
```

### "Permission denied" mounting filesystems

The scanner must run as root to map RBD devices and mount filesystems.

### Snapshot creation fails

Verify the API token has `VM.Snapshot` permission:

```bash
pveum user permissions scanner@pve --path /vms/100
```

### LVM volumes not detected

Ensure LVM tools are installed and the `lvm2-lvmetad` service is running:

```bash
systemctl start lvm2-lvmetad
```

## Testing

Run the test suite:

```bash
pip install pytest pytest-cov
pytest test_rbdclamscan.py -v --cov=rbdclamscan
```

Current coverage: **98%**

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         VMScanner                                │
│                    (Main Orchestrator)                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ ProxmoxClient│  │  RBDManager  │  │  PartitionDiscovery    │ │
│  │              │  │              │  │                        │ │
│  │ - list_vms() │  │ - map_snap() │  │ - discover_partitions()│ │
│  │ - get_config │  │ - unmap()    │  │ - get_filesystem_type()│ │
│  │ - snapshot() │  │              │  │                        │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │  LVMManager  │  │ MountManager │  │     ClamScanner        │ │
│  │              │  │              │  │                        │ │
│  │ - activate() │  │ - mount()    │  │ - scan()               │ │
│  │ - deactivate │  │ - unmount()  │  │ - save_report()        │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## License

MIT License
