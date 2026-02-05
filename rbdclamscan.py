#!/usr/bin/env python3
"""
RBD ClamAV Scanner for Proxmox VMs

Scans Proxmox VMs via Ceph RBD snapshots using ClamAV.
"""

import argparse
import configparser
import json
import logging
import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from proxmoxer import ProxmoxAPI

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration from CLI args, environment variables, or config file."""

    proxmox_host: str
    proxmox_user: str
    proxmox_token_name: str
    proxmox_token_value: str
    ceph_user: str = "admin"
    report_dir: str = "/var/log/rbdclamscan"
    snapshot_name: str = "clamscan"
    include_vmids: list[int] = field(default_factory=list)
    exclude_vmids: list[int] = field(default_factory=list)
    include_nodes: list[str] = field(default_factory=list)
    verify_ssl: bool = False

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "Config":
        """Build config from CLI args, falling back to env vars and config file."""
        config_data = {}

        # Load from config file if provided
        if args.config and os.path.exists(args.config):
            parser = configparser.ConfigParser()
            parser.read(args.config)
            if "rbdclamscan" in parser:
                section = parser["rbdclamscan"]
                config_data = {
                    "proxmox_host": section.get("proxmox_host"),
                    "proxmox_user": section.get("proxmox_user"),
                    "proxmox_token_name": section.get("proxmox_token_name"),
                    "proxmox_token_value": section.get("proxmox_token_value"),
                    "ceph_user": section.get("ceph_user", "admin"),
                    "report_dir": section.get("report_dir", "/var/log/rbdclamscan"),
                    "snapshot_name": section.get("snapshot_name", "clamscan"),
                }
                if section.get("include_vmids"):
                    config_data["include_vmids"] = [
                        int(x.strip()) for x in section["include_vmids"].split(",")
                    ]
                if section.get("exclude_vmids"):
                    config_data["exclude_vmids"] = [
                        int(x.strip()) for x in section["exclude_vmids"].split(",")
                    ]
                if section.get("include_nodes"):
                    config_data["include_nodes"] = [
                        x.strip() for x in section["include_nodes"].split(",")
                    ]

        # Override with environment variables
        env_mapping = {
            "PROXMOX_HOST": "proxmox_host",
            "PROXMOX_USER": "proxmox_user",
            "PROXMOX_TOKEN_NAME": "proxmox_token_name",
            "PROXMOX_TOKEN_VALUE": "proxmox_token_value",
            "CEPH_USER": "ceph_user",
            "CLAMSCAN_REPORT_DIR": "report_dir",
        }
        for env_var, config_key in env_mapping.items():
            if os.environ.get(env_var):
                config_data[config_key] = os.environ[env_var]

        # Override with CLI arguments
        if args.host:
            config_data["proxmox_host"] = args.host
        if args.user:
            config_data["proxmox_user"] = args.user
        if args.token_name:
            config_data["proxmox_token_name"] = args.token_name
        if args.token_value:
            config_data["proxmox_token_value"] = args.token_value
        if args.ceph_user:
            config_data["ceph_user"] = args.ceph_user
        if args.report_dir:
            config_data["report_dir"] = args.report_dir
        if args.vmid:
            config_data["include_vmids"] = args.vmid
        if args.exclude_vmid:
            config_data["exclude_vmids"] = args.exclude_vmid
        if args.node:
            config_data["include_nodes"] = args.node
        if args.verify_ssl:
            config_data["verify_ssl"] = args.verify_ssl

        # Validate required fields
        required = ["proxmox_host", "proxmox_user", "proxmox_token_name", "proxmox_token_value"]
        missing = [f for f in required if not config_data.get(f)]
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")

        return cls(
            proxmox_host=config_data["proxmox_host"],
            proxmox_user=config_data["proxmox_user"],
            proxmox_token_name=config_data["proxmox_token_name"],
            proxmox_token_value=config_data["proxmox_token_value"],
            ceph_user=config_data.get("ceph_user", "admin"),
            report_dir=config_data.get("report_dir", "/var/log/rbdclamscan"),
            snapshot_name=config_data.get("snapshot_name", "clamscan"),
            include_vmids=config_data.get("include_vmids", []),
            exclude_vmids=config_data.get("exclude_vmids", []),
            include_nodes=config_data.get("include_nodes", []),
            verify_ssl=config_data.get("verify_ssl", False),
        )


class ProxmoxClient:
    """Wraps proxmoxer for API operations."""

    def __init__(self, config: Config):
        self.config = config
        self.api = ProxmoxAPI(
            config.proxmox_host,
            user=config.proxmox_user,
            token_name=config.proxmox_token_name,
            token_value=config.proxmox_token_value,
            verify_ssl=config.verify_ssl,
        )

    def list_vms(self) -> list[dict]:
        """List all QEMU VMs in the cluster."""
        resources = self.api.cluster.resources.get(type="vm")
        return [r for r in resources if r.get("type") == "qemu"]

    def get_vm_config(self, node: str, vmid: int) -> dict:
        """Get VM configuration."""
        return self.api.nodes(node).qemu(vmid).config.get()

    def create_snapshot(self, node: str, vmid: int, snapname: str) -> str:
        """Create a VM snapshot, returns task UPID."""
        return self.api.nodes(node).qemu(vmid).snapshot.post(snapname=snapname)

    def delete_snapshot(self, node: str, vmid: int, snapname: str) -> str:
        """Delete a VM snapshot, returns task UPID."""
        return self.api.nodes(node).qemu(vmid).snapshot(snapname).delete()

    def wait_for_task(self, node: str, upid: str, timeout: int = 300) -> bool:
        """Poll task status until completion."""
        start = time.time()
        while time.time() - start < timeout:
            status = self.api.nodes(node).tasks(upid).status.get()
            if status.get("status") == "stopped":
                return status.get("exitstatus") == "OK"
            time.sleep(1)
        raise TimeoutError(f"Task {upid} did not complete within {timeout}s")


class RBDManager:
    """Context manager for RBD mapping."""

    def __init__(self, ceph_user: str):
        self.ceph_user = ceph_user
        self.mapped_device: Optional[str] = None

    @contextmanager
    def map_snapshot(self, pool: str, image: str, snapshot: str):
        """Map RBD snapshot read-only and yield device path."""
        device = None
        try:
            cmd = [
                "rbd",
                "map",
                "--read-only",
                "--name",
                f"client.{self.ceph_user}",
                f"{pool}/{image}@{snapshot}",
            ]
            logger.debug(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            device = result.stdout.strip()
            logger.info(f"Mapped {pool}/{image}@{snapshot} to {device}")

            # Probe for partitions after mapping
            self._probe_partitions(device)

            yield device
        finally:
            if device:
                self._unmap(device)

    def _probe_partitions(self, device: str):
        """Probe device for partitions."""
        # Try partprobe first
        try:
            cmd = ["partprobe", device]
            logger.debug(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fall back to blockdev --rereadpt
            try:
                cmd = ["blockdev", "--rereadpt", device]
                logger.debug(f"Running: {' '.join(cmd)}")
                subprocess.run(cmd, capture_output=True, text=True, check=False)
            except FileNotFoundError:
                pass

        # Wait for udev to settle
        try:
            cmd = ["udevadm", "settle", "--timeout=5"]
            logger.debug(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            time.sleep(1)  # Fallback if udevadm not available

    def _unmap(self, device: str):
        """Unmap RBD device."""
        try:
            cmd = ["rbd", "unmap", device]
            logger.debug(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"Unmapped {device}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unmap {device}: {e.stderr}")


class PartitionDiscovery:
    """Discovers partitions on block devices."""

    def discover_partitions(self, device: str) -> list[dict]:
        """Use lsblk to discover partitions."""
        cmd = ["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,SIZE,MOUNTPOINT", device]
        logger.debug(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)

        partitions = []
        for dev in data.get("blockdevices", []):
            # Check children (partitions)
            for child in dev.get("children", []):
                if child.get("type") == "part":
                    part_name = child.get("name")
                    partitions.append(
                        {
                            "device": f"/dev/{part_name}",
                            "fstype": child.get("fstype"),
                            "size": child.get("size"),
                        }
                    )
            # If no children, check if device itself has a filesystem or is LVM
            if not dev.get("children"):
                fstype = dev.get("fstype")
                # If lsblk didn't detect fstype, try blkid
                if not fstype:
                    fstype = self.get_filesystem_type(device)
                if fstype:
                    partitions.append(
                        {
                            "device": device,
                            "fstype": fstype,
                            "size": dev.get("size"),
                        }
                    )

        return partitions

    def get_filesystem_type(self, device: str) -> Optional[str]:
        """Get filesystem type using blkid."""
        cmd = ["blkid", "-s", "TYPE", "-o", "value", device]
        logger.debug(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        return None


class LVMManager:
    """Context manager for LVM activation."""

    def __init__(self):
        self.activated_vgs: list[str] = []

    @contextmanager
    def scan_and_activate(self, device: str):
        """Scan for PVs and activate VGs, yield LV paths."""
        vg_name = None
        vg_uuid = None
        try:
            # Scan for physical volumes
            cmd = ["pvscan", "--cache", device]
            logger.debug(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.debug(f"pvscan failed on {device}: {result.stderr.strip()}")
                # Continue anyway - pvs might still work

            # Get VG name and UUID from the device
            cmd = ["pvs", "--noheadings", "-o", "vg_name,vg_uuid", device]
            logger.debug(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.debug(f"pvs failed on {device} (exit {result.returncode}): {result.stderr.strip()}")
                logger.debug(f"Device {device} is not a valid LVM physical volume")
                yield []
                return

            output = result.stdout.strip()

            if not output:
                logger.debug(f"No VG found on {device}")
                yield []
                return

            parts = output.split()
            if len(parts) >= 2:
                vg_name = parts[0]
                vg_uuid = parts[1]
            elif len(parts) == 1:
                vg_name = parts[0]

            if not vg_name:
                logger.debug(f"No VG found on {device}")
                yield []
                return

            logger.debug(f"Found VG {vg_name} (UUID: {vg_uuid}) on {device}")

            # Check if VG is already active (name conflict with host)
            # Use vgchange with --select to target by UUID if available
            if vg_uuid:
                cmd = ["vgchange", "-ay", "--select", f"vg_uuid={vg_uuid}"]
            else:
                cmd = ["vgchange", "-ay", vg_name]

            logger.debug(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning(f"vgchange failed: {result.stderr}, trying with --partial")
                # Try with --partial for incomplete VGs (common with snapshots)
                if vg_uuid:
                    cmd = ["vgchange", "-ay", "--partial", "--select", f"vg_uuid={vg_uuid}"]
                else:
                    cmd = ["vgchange", "-ay", "--partial", vg_name]
                logger.debug(f"Running: {' '.join(cmd)}")
                subprocess.run(cmd, capture_output=True, text=True, check=True)

            self.activated_vgs.append(vg_name)
            logger.info(f"Activated VG {vg_name}")

            # Wait for device nodes to be created
            self._wait_for_udev()

            # List LVs - use select by UUID if available for accuracy
            if vg_uuid:
                cmd = ["lvs", "--noheadings", "-o", "lv_path", "--select", f"vg_uuid={vg_uuid}"]
            else:
                cmd = ["lvs", "--noheadings", "-o", "lv_path", vg_name]
            logger.debug(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lv_paths = [p.strip() for p in result.stdout.strip().split("\n") if p.strip()]
            logger.info(f"Found LVs: {lv_paths}")

            # Verify LV device nodes exist
            valid_lv_paths = []
            for lv_path in lv_paths:
                if os.path.exists(lv_path):
                    valid_lv_paths.append(lv_path)
                else:
                    # Try to find via /dev/mapper
                    mapper_name = lv_path.replace("/dev/", "").replace("/", "-")
                    mapper_path = f"/dev/mapper/{mapper_name}"
                    if os.path.exists(mapper_path):
                        valid_lv_paths.append(mapper_path)
                    else:
                        logger.warning(f"LV device node not found: {lv_path}")

            yield valid_lv_paths

        finally:
            if vg_name and vg_name in self.activated_vgs:
                self._deactivate_vg(vg_name)

    def _wait_for_udev(self):
        """Wait for udev to create device nodes."""
        try:
            cmd = ["udevadm", "settle", "--timeout=5"]
            logger.debug(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            time.sleep(1)

    def _deactivate_vg(self, vg_name: str):
        """Deactivate a VG."""
        try:
            cmd = ["vgchange", "-an", vg_name]
            logger.debug(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.activated_vgs.remove(vg_name)
            logger.info(f"Deactivated VG {vg_name}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to deactivate VG {vg_name}: {e.stderr}")

    def deactivate_all(self):
        """Deactivate all activated VGs."""
        for vg_name in list(self.activated_vgs):
            self._deactivate_vg(vg_name)


class MountManager:
    """Context manager for filesystem mounting."""

    SUPPORTED_FS = {"ext2", "ext3", "ext4", "xfs", "vfat", "ntfs"}
    SKIP_FS = {"swap", "LVM2_member"}

    def __init__(self):
        self.mount_points: list[str] = []

    @contextmanager
    def mount(self, device: str, fstype: str):
        """Mount filesystem read-only, yield mount point."""
        if fstype in self.SKIP_FS:
            logger.debug(f"Skipping {fstype} filesystem on {device}")
            yield None
            return

        if fstype not in self.SUPPORTED_FS:
            logger.warning(f"Unsupported filesystem {fstype} on {device}")
            yield None
            return

        mount_point = None
        try:
            # Create temporary mount point
            mount_point = f"/tmp/rbdclamscan_{os.getpid()}_{device.replace('/', '_')}"
            os.makedirs(mount_point, exist_ok=True)

            # Build mount command based on filesystem type
            cmd = ["mount"]
            if fstype == "ntfs":
                cmd.extend(["-t", "ntfs-3g", "-o", "ro"])
            elif fstype in ("ext2", "ext3", "ext4"):
                cmd.extend(["-o", "ro,noload,norecovery"])
            elif fstype == "xfs":
                cmd.extend(["-o", "ro,norecovery"])
            elif fstype == "vfat":
                cmd.extend(["-o", "ro"])
            else:
                cmd.extend(["-o", "ro"])

            cmd.extend([device, mount_point])
            logger.debug(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.mount_points.append(mount_point)
            logger.info(f"Mounted {device} ({fstype}) at {mount_point}")

            yield mount_point

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to mount {device}: {e.stderr}")
            yield None

        finally:
            if mount_point and mount_point in self.mount_points:
                self._unmount(mount_point)

    def _unmount(self, mount_point: str):
        """Unmount filesystem."""
        try:
            cmd = ["umount", mount_point]
            logger.debug(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.mount_points.remove(mount_point)
            logger.info(f"Unmounted {mount_point}")

            # Clean up mount point directory
            try:
                os.rmdir(mount_point)
            except OSError:
                pass

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unmount {mount_point}: {e.stderr}")

    def unmount_all(self):
        """Unmount all mounted filesystems."""
        for mp in list(self.mount_points):
            self._unmount(mp)


class ClamScanner:
    """Runs ClamAV scans."""

    def __init__(self, report_dir: str):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def scan(self, mountpoint: str, vm_name: str, disk_name: str) -> Path:
        """Run clamdscan on mountpoint and save report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.report_dir / f"{vm_name}_{disk_name}_{timestamp}.log"

        cmd = ["clamdscan", "--fdpass", "--multiscan", mountpoint]
        logger.info(f"Scanning {mountpoint} for {vm_name}/{disk_name}")
        logger.debug(f"Running: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)

        # Write report
        with open(report_path, "w") as f:
            f.write(f"VM: {vm_name}\n")
            f.write(f"Disk: {disk_name}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Mount Point: {mountpoint}\n")
            f.write("-" * 60 + "\n")
            f.write(result.stdout)
            if result.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(result.stderr)

        if result.returncode == 0:
            logger.info(f"Scan complete (clean): {report_path}")
        elif result.returncode == 1:
            logger.warning(f"Scan complete (INFECTED): {report_path}")
        else:
            logger.error(f"Scan error (exit {result.returncode}): {report_path}")

        return report_path


class VMScanner:
    """Main orchestrator for VM scanning."""

    def __init__(self, config: Config):
        self.config = config
        self.proxmox = ProxmoxClient(config)
        self.rbd = RBDManager(config.ceph_user)
        self.partition_discovery = PartitionDiscovery()
        self.lvm = LVMManager()
        self.mount = MountManager()
        self.scanner = ClamScanner(config.report_dir)

    def _parse_disk_config(self, disk_value: str) -> Optional[tuple[str, str]]:
        """Parse Proxmox disk config to extract pool and image."""
        # Format: pool-name:vm-XXX-disk-N,size=...
        match = re.match(r"^([^:]+):([^,]+)", disk_value)
        if match:
            return match.group(1), match.group(2)
        return None

    def _get_rbd_disks(self, vm_config: dict) -> list[tuple[str, str, str]]:
        """Extract RBD disks from VM config. Returns list of (disk_key, pool, image)."""
        disks = []
        for key, value in vm_config.items():
            # Look for scsi*, virtio*, ide*, sata* disks
            if re.match(r"^(scsi|virtio|ide|sata)\d+$", key) and isinstance(value, str):
                parsed = self._parse_disk_config(value)
                if parsed:
                    pool, image = parsed
                    disks.append((key, pool, image))
        return disks

    def _should_scan_vm(self, vm: dict) -> bool:
        """Check if VM should be scanned based on filters."""
        vmid = vm.get("vmid")
        node = vm.get("node")

        if self.config.include_vmids and vmid not in self.config.include_vmids:
            return False
        if vmid in self.config.exclude_vmids:
            return False
        if self.config.include_nodes and node not in self.config.include_nodes:
            return False
        return True

    def _scan_partition(self, device: str, fstype: Optional[str], vm_name: str, disk_name: str):
        """Scan a single partition."""
        if not fstype:
            fstype = self.partition_discovery.get_filesystem_type(device)

        if fstype == "LVM2_member":
            # Handle LVM
            with self.lvm.scan_and_activate(device) as lv_paths:
                for lv_path in lv_paths:
                    lv_fstype = self.partition_discovery.get_filesystem_type(lv_path)
                    lv_name = lv_path.split("/")[-1]
                    self._scan_filesystem(lv_path, lv_fstype, vm_name, f"{disk_name}_{lv_name}")
        else:
            self._scan_filesystem(device, fstype, vm_name, disk_name)

    def _scan_filesystem(
        self, device: str, fstype: Optional[str], vm_name: str, disk_name: str
    ):
        """Mount and scan a filesystem."""
        if not fstype or fstype in MountManager.SKIP_FS:
            logger.debug(f"Skipping {device} (fstype: {fstype})")
            return

        with self.mount.mount(device, fstype) as mount_point:
            if mount_point:
                self.scanner.scan(mount_point, vm_name, disk_name)

    def scan_vm(self, vm: dict):
        """Scan a single VM."""
        vmid = vm.get("vmid")
        node = vm.get("node")
        vm_name = vm.get("name", f"vm-{vmid}")

        logger.info(f"Processing VM {vmid} ({vm_name}) on {node}")

        # Get VM config
        try:
            vm_config = self.proxmox.get_vm_config(node, vmid)
        except Exception as e:
            logger.error(f"Failed to get config for VM {vmid}: {e}")
            return

        # Get RBD disks
        disks = self._get_rbd_disks(vm_config)
        if not disks:
            logger.info(f"No RBD disks found for VM {vmid}")
            return

        logger.info(f"Found {len(disks)} RBD disk(s) for VM {vmid}")

        # Create snapshot
        try:
            upid = self.proxmox.create_snapshot(node, vmid, self.config.snapshot_name)
            if not self.proxmox.wait_for_task(node, upid):
                logger.error(f"Snapshot creation failed for VM {vmid}")
                return
            logger.info(f"Created snapshot '{self.config.snapshot_name}' for VM {vmid}")
        except Exception as e:
            logger.error(f"Failed to create snapshot for VM {vmid}: {e}")
            return

        try:
            # Process each disk
            for disk_key, pool, image in disks:
                logger.info(f"Processing disk {disk_key}: {pool}/{image}")
                try:
                    with self.rbd.map_snapshot(pool, image, self.config.snapshot_name) as device:
                        # Discover partitions
                        partitions = self.partition_discovery.discover_partitions(device)
                        logger.info(f"Found {len(partitions)} partition(s) on {device}")

                        for part in partitions:
                            try:
                                self._scan_partition(
                                    part["device"],
                                    part["fstype"],
                                    vm_name,
                                    f"{disk_key}_{part['device'].split('/')[-1]}",
                                )
                            except Exception as e:
                                logger.error(f"Error scanning partition {part['device']}: {e}")
                                continue

                except Exception as e:
                    logger.error(f"Error processing disk {disk_key}: {e}")
                    continue

        finally:
            # Always try to delete snapshot
            try:
                upid = self.proxmox.delete_snapshot(node, vmid, self.config.snapshot_name)
                if self.proxmox.wait_for_task(node, upid):
                    logger.info(f"Deleted snapshot '{self.config.snapshot_name}' for VM {vmid}")
                else:
                    logger.error(f"Snapshot deletion failed for VM {vmid}")
            except Exception as e:
                logger.error(f"Failed to delete snapshot for VM {vmid}: {e}")

    def scan_all(self):
        """Scan all VMs matching filters."""
        logger.info("Fetching VM list from Proxmox...")
        vms = self.proxmox.list_vms()
        logger.info(f"Found {len(vms)} total VMs")

        vms_to_scan = [vm for vm in vms if self._should_scan_vm(vm)]
        logger.info(f"Will scan {len(vms_to_scan)} VMs after applying filters")

        for vm in vms_to_scan:
            try:
                self.scan_vm(vm)
            except Exception as e:
                logger.error(f"Error scanning VM {vm.get('vmid')}: {e}")
                continue


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Scan Proxmox VMs via Ceph RBD snapshots using ClamAV"
    )
    parser.add_argument(
        "--config", "-c", help="Config file path", metavar="FILE"
    )
    parser.add_argument("--host", help="Proxmox host")
    parser.add_argument("--user", help="Proxmox user (user@realm)")
    parser.add_argument("--token-name", help="API token name")
    parser.add_argument("--token-value", help="API token value")
    parser.add_argument(
        "--ceph-user",
        help="Ceph client user for RBD mapping (default: admin)",
    )
    parser.add_argument("--report-dir", help="Report directory")
    parser.add_argument(
        "--vmid",
        type=int,
        action="append",
        help="Scan specific VM(s) (repeatable)",
    )
    parser.add_argument(
        "--exclude-vmid",
        type=int,
        action="append",
        help="Exclude VM(s) (repeatable)",
    )
    parser.add_argument(
        "--node", action="append", help="Scan VMs on specific node(s)"
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose logging"
    )
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        config = Config.from_args(args)
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    logger.info(f"Proxmox host: {config.proxmox_host}")
    logger.info(f"Report directory: {config.report_dir}")

    scanner = VMScanner(config)
    scanner.scan_all()

    logger.info("Scan complete")


if __name__ == "__main__":
    main()
