"""Unit tests for rbdclamscan.py"""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from rbdclamscan import (
    ClamScanner,
    Config,
    LVMManager,
    MountManager,
    PartitionDiscovery,
    ProxmoxClient,
    RBDManager,
    VMScanner,
    main,
    parse_args,
)


# =============================================================================
# Config Tests
# =============================================================================
class TestConfig:
    """Tests for Config dataclass."""

    def make_args(self, **kwargs):
        """Create argparse.Namespace with defaults."""
        defaults = {
            "config": None,
            "host": None,
            "user": None,
            "token_name": None,
            "token_value": None,
            "ceph_user": None,
            "report_dir": None,
            "vmid": None,
            "exclude_vmid": None,
            "node": None,
            "verify_ssl": False,
            "verbose": False,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_from_args_cli_only(self):
        """Test config from CLI arguments only."""
        args = self.make_args(
            host="pve.example.com",
            user="root@pam",
            token_name="mytoken",
            token_value="secret123",
            ceph_user="cephuser",
            report_dir="/tmp/reports",
            vmid=[100, 101],
            exclude_vmid=[999],
            node=["pve1"],
            verify_ssl=True,
        )
        config = Config.from_args(args)

        assert config.proxmox_host == "pve.example.com"
        assert config.proxmox_user == "root@pam"
        assert config.proxmox_token_name == "mytoken"
        assert config.proxmox_token_value == "secret123"
        assert config.ceph_user == "cephuser"
        assert config.report_dir == "/tmp/reports"
        assert config.include_vmids == [100, 101]
        assert config.exclude_vmids == [999]
        assert config.include_nodes == ["pve1"]
        assert config.verify_ssl is True

    def test_from_args_env_vars(self):
        """Test config from environment variables."""
        args = self.make_args()
        env = {
            "PROXMOX_HOST": "env.example.com",
            "PROXMOX_USER": "envuser@pve",
            "PROXMOX_TOKEN_NAME": "envtoken",
            "PROXMOX_TOKEN_VALUE": "envsecret",
            "CEPH_USER": "envceph",
            "CLAMSCAN_REPORT_DIR": "/env/reports",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            config = Config.from_args(args)

        assert config.proxmox_host == "env.example.com"
        assert config.proxmox_user == "envuser@pve"
        assert config.proxmox_token_name == "envtoken"
        assert config.proxmox_token_value == "envsecret"
        assert config.ceph_user == "envceph"
        assert config.report_dir == "/env/reports"

    def test_from_args_config_file(self):
        """Test config from config file."""
        config_content = """
[rbdclamscan]
proxmox_host = file.example.com
proxmox_user = fileuser@pve
proxmox_token_name = filetoken
proxmox_token_value = filesecret
ceph_user = fileceph
report_dir = /file/reports
snapshot_name = mysnapshot
include_vmids = 100, 101, 102
exclude_vmids = 999
include_nodes = pve1, pve2
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            args = self.make_args(config=config_path)
            config = Config.from_args(args)

            assert config.proxmox_host == "file.example.com"
            assert config.proxmox_user == "fileuser@pve"
            assert config.proxmox_token_name == "filetoken"
            assert config.proxmox_token_value == "filesecret"
            assert config.ceph_user == "fileceph"
            assert config.report_dir == "/file/reports"
            assert config.snapshot_name == "mysnapshot"
            assert config.include_vmids == [100, 101, 102]
            assert config.exclude_vmids == [999]
            assert config.include_nodes == ["pve1", "pve2"]
        finally:
            os.unlink(config_path)

    def test_from_args_priority_cli_over_env(self):
        """Test that CLI args override env vars."""
        args = self.make_args(
            host="cli.example.com",
            user="cliuser@pve",
            token_name="clitoken",
            token_value="clisecret",
        )
        env = {
            "PROXMOX_HOST": "env.example.com",
            "PROXMOX_USER": "envuser@pve",
            "PROXMOX_TOKEN_NAME": "envtoken",
            "PROXMOX_TOKEN_VALUE": "envsecret",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            config = Config.from_args(args)

        assert config.proxmox_host == "cli.example.com"
        assert config.proxmox_user == "cliuser@pve"

    def test_from_args_missing_required(self):
        """Test error when required fields missing."""
        args = self.make_args(host="pve.example.com")
        with pytest.raises(ValueError, match="Missing required configuration"):
            Config.from_args(args)

    def test_from_args_defaults(self):
        """Test default values."""
        args = self.make_args(
            host="pve.example.com",
            user="root@pam",
            token_name="mytoken",
            token_value="secret",
        )
        config = Config.from_args(args)

        assert config.ceph_user == "admin"
        assert config.report_dir == "/var/log/rbdclamscan"
        assert config.snapshot_name == "clamscan"
        assert config.include_vmids == []
        assert config.exclude_vmids == []
        assert config.include_nodes == []
        assert config.verify_ssl is False

    def test_from_args_nonexistent_config_file(self):
        """Test that nonexistent config file is ignored."""
        args = self.make_args(
            config="/nonexistent/path/config.ini",
            host="pve.example.com",
            user="root@pam",
            token_name="mytoken",
            token_value="secret",
        )
        config = Config.from_args(args)
        assert config.proxmox_host == "pve.example.com"


# =============================================================================
# ProxmoxClient Tests
# =============================================================================
class TestProxmoxClient:
    """Tests for ProxmoxClient class."""

    @pytest.fixture
    def config(self):
        return Config(
            proxmox_host="pve.example.com",
            proxmox_user="root@pam",
            proxmox_token_name="mytoken",
            proxmox_token_value="secret",
        )

    @pytest.fixture
    def mock_api(self):
        with mock.patch("rbdclamscan.ProxmoxAPI") as mock_cls:
            yield mock_cls.return_value

    def test_init(self, config, mock_api):
        """Test ProxmoxClient initialization."""
        client = ProxmoxClient(config)
        assert client.config == config

    def test_list_vms(self, config, mock_api):
        """Test listing VMs."""
        mock_api.cluster.resources.get.return_value = [
            {"vmid": 100, "type": "qemu", "node": "pve1"},
            {"vmid": 101, "type": "qemu", "node": "pve1"},
            {"vmid": 200, "type": "lxc", "node": "pve1"},  # Should be filtered
        ]
        client = ProxmoxClient(config)
        vms = client.list_vms()

        assert len(vms) == 2
        assert all(vm["type"] == "qemu" for vm in vms)
        mock_api.cluster.resources.get.assert_called_once_with(type="vm")

    def test_get_vm_config(self, config, mock_api):
        """Test getting VM config."""
        mock_api.nodes.return_value.qemu.return_value.config.get.return_value = {
            "scsi0": "pool:vm-100-disk-0,size=32G"
        }
        client = ProxmoxClient(config)
        vm_config = client.get_vm_config("pve1", 100)

        assert "scsi0" in vm_config
        mock_api.nodes.assert_called_with("pve1")

    def test_create_snapshot(self, config, mock_api):
        """Test creating snapshot."""
        mock_api.nodes.return_value.qemu.return_value.snapshot.post.return_value = (
            "UPID:pve1:000..."
        )
        client = ProxmoxClient(config)
        upid = client.create_snapshot("pve1", 100, "clamscan")

        assert upid == "UPID:pve1:000..."
        mock_api.nodes.return_value.qemu.return_value.snapshot.post.assert_called_with(
            snapname="clamscan"
        )

    def test_delete_snapshot(self, config, mock_api):
        """Test deleting snapshot."""
        mock_api.nodes.return_value.qemu.return_value.snapshot.return_value.delete.return_value = (
            "UPID:pve1:001..."
        )
        client = ProxmoxClient(config)
        upid = client.delete_snapshot("pve1", 100, "clamscan")

        assert upid == "UPID:pve1:001..."

    def test_wait_for_task_success(self, config, mock_api):
        """Test waiting for task completion."""
        mock_api.nodes.return_value.tasks.return_value.status.get.return_value = {
            "status": "stopped",
            "exitstatus": "OK",
        }
        client = ProxmoxClient(config)
        result = client.wait_for_task("pve1", "UPID:test")

        assert result is True

    def test_wait_for_task_failure(self, config, mock_api):
        """Test task failure."""
        mock_api.nodes.return_value.tasks.return_value.status.get.return_value = {
            "status": "stopped",
            "exitstatus": "ERROR",
        }
        client = ProxmoxClient(config)
        result = client.wait_for_task("pve1", "UPID:test")

        assert result is False

    def test_wait_for_task_timeout(self, config, mock_api):
        """Test task timeout."""
        mock_api.nodes.return_value.tasks.return_value.status.get.return_value = {
            "status": "running"
        }
        client = ProxmoxClient(config)

        with mock.patch("rbdclamscan.time.sleep"):
            with mock.patch("rbdclamscan.time.time", side_effect=[0, 0, 301]):
                with pytest.raises(TimeoutError):
                    client.wait_for_task("pve1", "UPID:test", timeout=300)


# =============================================================================
# RBDManager Tests
# =============================================================================
class TestRBDManager:
    """Tests for RBDManager class."""

    def test_map_snapshot_success(self):
        """Test successful RBD mapping."""
        manager = RBDManager("admin")
        mock_result = mock.Mock()
        mock_result.stdout = "/dev/rbd0\n"

        with mock.patch("subprocess.run", return_value=mock_result) as mock_run:
            with manager.map_snapshot("pool", "image", "snap") as device:
                assert device == "/dev/rbd0"
                mock_run.assert_any_call(
                    [
                        "rbd",
                        "map",
                        "--read-only",
                        "--name",
                        "client.admin",
                        "pool/image@snap",
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )

            # Verify unmap was called on exit
            unmap_call = mock.call(
                ["rbd", "unmap", "/dev/rbd0"],
                capture_output=True,
                text=True,
                check=True,
            )
            assert unmap_call in mock_run.call_args_list

    def test_map_snapshot_probes_partitions(self):
        """Test that partition probing happens after mapping."""
        manager = RBDManager("admin")
        mock_result = mock.Mock()
        mock_result.stdout = "/dev/rbd0\n"

        with mock.patch("subprocess.run", return_value=mock_result) as mock_run:
            with manager.map_snapshot("pool", "image", "snap"):
                # Verify partprobe was called
                partprobe_call = mock.call(
                    ["partprobe", "/dev/rbd0"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                assert partprobe_call in mock_run.call_args_list

    def test_map_snapshot_fallback_to_blockdev(self):
        """Test fallback to blockdev when partprobe fails."""
        manager = RBDManager("admin")
        mock_result = mock.Mock()
        mock_result.stdout = "/dev/rbd0\n"

        call_count = [0]

        def run_side_effect(cmd, **kwargs):
            call_count[0] += 1
            if cmd[0] == "partprobe":
                raise subprocess.CalledProcessError(1, cmd)
            return mock_result

        with mock.patch("subprocess.run", side_effect=run_side_effect) as mock_run:
            with manager.map_snapshot("pool", "image", "snap"):
                # Verify blockdev --rereadpt was called after partprobe failed
                blockdev_call = mock.call(
                    ["blockdev", "--rereadpt", "/dev/rbd0"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert blockdev_call in mock_run.call_args_list

    def test_map_snapshot_cleanup_on_exception(self):
        """Test RBD unmap happens even on exception."""
        manager = RBDManager("admin")
        mock_result = mock.Mock()
        mock_result.stdout = "/dev/rbd0\n"

        with mock.patch("subprocess.run", return_value=mock_result) as mock_run:
            with pytest.raises(RuntimeError):
                with manager.map_snapshot("pool", "image", "snap"):
                    raise RuntimeError("Test error")

            # Verify unmap was still called
            unmap_call = mock.call(
                ["rbd", "unmap", "/dev/rbd0"],
                capture_output=True,
                text=True,
                check=True,
            )
            assert unmap_call in mock_run.call_args_list

    def test_unmap_failure_logged(self):
        """Test that unmap failures are logged but don't raise."""
        manager = RBDManager("admin")
        mock_map_result = mock.Mock()
        mock_map_result.stdout = "/dev/rbd0\n"

        def run_side_effect(cmd, **kwargs):
            if cmd[0] == "rbd" and cmd[1] == "unmap":
                raise subprocess.CalledProcessError(1, cmd, stderr="unmap error")
            return mock_map_result

        with mock.patch("subprocess.run", side_effect=run_side_effect):
            # Should not raise even though unmap fails
            with manager.map_snapshot("pool", "image", "snap"):
                pass

    def test_custom_ceph_user(self):
        """Test using custom Ceph user."""
        manager = RBDManager("myuser")
        mock_result = mock.Mock()
        mock_result.stdout = "/dev/rbd0\n"

        with mock.patch("subprocess.run", return_value=mock_result) as mock_run:
            with manager.map_snapshot("pool", "image", "snap"):
                pass

            mock_run.assert_any_call(
                [
                    "rbd",
                    "map",
                    "--read-only",
                    "--name",
                    "client.myuser",
                    "pool/image@snap",
                ],
                capture_output=True,
                text=True,
                check=True,
            )


# =============================================================================
# PartitionDiscovery Tests
# =============================================================================
class TestPartitionDiscovery:
    """Tests for PartitionDiscovery class."""

    def test_discover_partitions_with_children(self):
        """Test discovering partitions on a device."""
        discovery = PartitionDiscovery()
        lsblk_output = json.dumps(
            {
                "blockdevices": [
                    {
                        "name": "rbd0",
                        "type": "disk",
                        "fstype": None,
                        "size": "32G",
                        "mountpoint": None,
                        "children": [
                            {
                                "name": "rbd0p1",
                                "type": "part",
                                "fstype": "vfat",
                                "size": "512M",
                                "mountpoint": None,
                            },
                            {
                                "name": "rbd0p2",
                                "type": "part",
                                "fstype": "ext4",
                                "size": "31.5G",
                                "mountpoint": None,
                            },
                        ],
                    }
                ]
            }
        )
        mock_result = mock.Mock()
        mock_result.stdout = lsblk_output

        with mock.patch("subprocess.run", return_value=mock_result):
            partitions = discovery.discover_partitions("/dev/rbd0")

        assert len(partitions) == 2
        assert partitions[0]["device"] == "/dev/rbd0p1"
        assert partitions[0]["fstype"] == "vfat"
        assert partitions[1]["device"] == "/dev/rbd0p2"
        assert partitions[1]["fstype"] == "ext4"

    def test_discover_partitions_no_children(self):
        """Test device with no partitions (direct filesystem)."""
        discovery = PartitionDiscovery()
        lsblk_output = json.dumps(
            {
                "blockdevices": [
                    {
                        "name": "rbd0",
                        "type": "disk",
                        "fstype": "ext4",
                        "size": "32G",
                        "mountpoint": None,
                    }
                ]
            }
        )
        mock_result = mock.Mock()
        mock_result.stdout = lsblk_output

        with mock.patch("subprocess.run", return_value=mock_result):
            partitions = discovery.discover_partitions("/dev/rbd0")

        assert len(partitions) == 1
        assert partitions[0]["device"] == "/dev/rbd0"
        assert partitions[0]["fstype"] == "ext4"

    def test_discover_partitions_empty(self):
        """Test device with no filesystems detected by lsblk or blkid."""
        discovery = PartitionDiscovery()
        lsblk_output = json.dumps(
            {
                "blockdevices": [
                    {
                        "name": "rbd0",
                        "type": "disk",
                        "fstype": None,
                        "size": "32G",
                        "mountpoint": None,
                    }
                ]
            }
        )

        def run_side_effect(cmd, **kwargs):
            result = mock.Mock()
            if cmd[0] == "lsblk":
                result.stdout = lsblk_output
            elif cmd[0] == "blkid":
                result.returncode = 2  # blkid returns 2 when no fs found
                result.stdout = ""
            return result

        with mock.patch("subprocess.run", side_effect=run_side_effect):
            partitions = discovery.discover_partitions("/dev/rbd0")

        assert len(partitions) == 0

    def test_discover_partitions_lvm_whole_disk(self):
        """Test device with LVM on whole disk (no partition table)."""
        discovery = PartitionDiscovery()
        lsblk_output = json.dumps(
            {
                "blockdevices": [
                    {
                        "name": "rbd0",
                        "type": "disk",
                        "fstype": None,  # lsblk might not detect LVM
                        "size": "32G",
                        "mountpoint": None,
                    }
                ]
            }
        )

        def run_side_effect(cmd, **kwargs):
            result = mock.Mock()
            if cmd[0] == "lsblk":
                result.stdout = lsblk_output
            elif cmd[0] == "blkid":
                result.returncode = 0
                result.stdout = "LVM2_member\n"  # blkid detects LVM
            return result

        with mock.patch("subprocess.run", side_effect=run_side_effect):
            partitions = discovery.discover_partitions("/dev/rbd0")

        assert len(partitions) == 1
        assert partitions[0]["device"] == "/dev/rbd0"
        assert partitions[0]["fstype"] == "LVM2_member"

    def test_get_filesystem_type_success(self):
        """Test getting filesystem type."""
        discovery = PartitionDiscovery()
        mock_result = mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = "ext4\n"

        with mock.patch("subprocess.run", return_value=mock_result):
            fstype = discovery.get_filesystem_type("/dev/rbd0p1")

        assert fstype == "ext4"

    def test_get_filesystem_type_failure(self):
        """Test getting filesystem type when blkid fails."""
        discovery = PartitionDiscovery()
        mock_result = mock.Mock()
        mock_result.returncode = 2
        mock_result.stdout = ""

        with mock.patch("subprocess.run", return_value=mock_result):
            fstype = discovery.get_filesystem_type("/dev/rbd0p1")

        assert fstype is None


# =============================================================================
# LVMManager Tests
# =============================================================================
class TestLVMManager:
    """Tests for LVMManager class."""

    def test_scan_and_activate_success(self):
        """Test successful LVM scan and activation."""
        manager = LVMManager()

        def run_side_effect(cmd, **kwargs):
            result = mock.Mock()
            result.returncode = 0
            if cmd[0] == "pvs":
                result.stdout = "  myvg abc-123-uuid\n"
            elif cmd[0] == "lvs":
                result.stdout = "  /dev/myvg/root\n  /dev/myvg/swap\n"
            elif cmd[0] == "udevadm":
                result.stdout = ""
            else:
                result.stdout = ""
            return result

        with mock.patch("subprocess.run", side_effect=run_side_effect) as mock_run:
            with mock.patch("os.path.exists", return_value=True):
                with manager.scan_and_activate("/dev/rbd0p2") as lv_paths:
                    assert lv_paths == ["/dev/myvg/root", "/dev/myvg/swap"]
                    assert "myvg" in manager.activated_vgs

            # Verify deactivation
            deactivate_call = mock.call(
                ["vgchange", "-an", "myvg"],
                capture_output=True,
                text=True,
                check=True,
            )
            assert deactivate_call in mock_run.call_args_list

    def test_scan_and_activate_with_uuid(self):
        """Test LVM activation uses VG UUID when available."""
        manager = LVMManager()

        def run_side_effect(cmd, **kwargs):
            result = mock.Mock()
            result.returncode = 0
            if cmd[0] == "pvs":
                result.stdout = "  myvg abc-123-uuid\n"
            elif cmd[0] == "vgchange" and "--select" in cmd:
                # Verify UUID-based selection
                assert "vg_uuid=abc-123-uuid" in cmd
                result.stdout = ""
            elif cmd[0] == "lvs" and "--select" in cmd:
                assert "vg_uuid=abc-123-uuid" in cmd
                result.stdout = "  /dev/myvg/root\n"
            else:
                result.stdout = ""
            return result

        with mock.patch("subprocess.run", side_effect=run_side_effect):
            with mock.patch("os.path.exists", return_value=True):
                with manager.scan_and_activate("/dev/rbd0p2") as lv_paths:
                    assert lv_paths == ["/dev/myvg/root"]

    def test_scan_and_activate_partial_vg(self):
        """Test activation with --partial when regular activation fails."""
        manager = LVMManager()
        call_count = [0]

        def run_side_effect(cmd, **kwargs):
            result = mock.Mock()
            result.returncode = 0
            if cmd[0] == "pvs":
                result.stdout = "  myvg abc-uuid\n"
            elif cmd[0] == "vgchange" and "-ay" in cmd:
                if "--partial" not in cmd:
                    # First attempt fails
                    result.returncode = 5
                    result.stderr = "VG is partial"
                else:
                    # Second attempt with --partial succeeds
                    result.returncode = 0
                    result.stdout = ""
            elif cmd[0] == "lvs":
                result.stdout = "  /dev/myvg/root\n"
            else:
                result.stdout = ""
            return result

        with mock.patch("subprocess.run", side_effect=run_side_effect):
            with mock.patch("os.path.exists", return_value=True):
                with manager.scan_and_activate("/dev/rbd0p2") as lv_paths:
                    assert lv_paths == ["/dev/myvg/root"]

    def test_scan_and_activate_no_vg(self):
        """Test when no VG found on device."""
        manager = LVMManager()

        def run_side_effect(cmd, **kwargs):
            result = mock.Mock()
            result.returncode = 0
            if cmd[0] == "pvs":
                result.stdout = "  \n"  # Empty VG name
            else:
                result.stdout = ""
            return result

        with mock.patch("subprocess.run", side_effect=run_side_effect):
            with manager.scan_and_activate("/dev/rbd0p2") as lv_paths:
                assert lv_paths == []

    def test_scan_and_activate_pvs_fails(self):
        """Test when pvs command fails (device not a valid PV)."""
        manager = LVMManager()

        def run_side_effect(cmd, **kwargs):
            result = mock.Mock()
            result.stderr = ""
            if cmd[0] == "pvscan":
                result.returncode = 0
                result.stdout = ""
            elif cmd[0] == "pvs":
                result.returncode = 5  # LVM error code
                result.stdout = ""
                result.stderr = "Device not found"
            else:
                result.returncode = 0
                result.stdout = ""
            return result

        with mock.patch("subprocess.run", side_effect=run_side_effect):
            # Should not raise, just return empty list
            with manager.scan_and_activate("/dev/rbd0p5") as lv_paths:
                assert lv_paths == []

    def test_scan_and_activate_lv_device_node_fallback(self):
        """Test fallback to /dev/mapper when LV path doesn't exist."""
        manager = LVMManager()

        def run_side_effect(cmd, **kwargs):
            result = mock.Mock()
            result.returncode = 0
            if cmd[0] == "pvs":
                result.stdout = "  myvg uuid123\n"
            elif cmd[0] == "lvs":
                result.stdout = "  /dev/myvg/root\n"
            else:
                result.stdout = ""
            return result

        def exists_side_effect(path):
            # /dev/myvg/root doesn't exist, but /dev/mapper/myvg-root does
            return path == "/dev/mapper/myvg-root"

        with mock.patch("subprocess.run", side_effect=run_side_effect):
            with mock.patch("os.path.exists", side_effect=exists_side_effect):
                with manager.scan_and_activate("/dev/rbd0p2") as lv_paths:
                    assert lv_paths == ["/dev/mapper/myvg-root"]

    def test_deactivate_vg_failure(self):
        """Test VG deactivation failure is logged."""
        manager = LVMManager()
        manager.activated_vgs = ["myvg"]

        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "vgchange", stderr="error"),
        ):
            # Should not raise
            manager._deactivate_vg("myvg")

    def test_deactivate_all(self):
        """Test deactivating all VGs."""
        manager = LVMManager()
        manager.activated_vgs = ["vg1", "vg2"]

        with mock.patch("subprocess.run") as mock_run:
            manager.deactivate_all()

        assert mock_run.call_count == 2
        assert manager.activated_vgs == []


# =============================================================================
# MountManager Tests
# =============================================================================
class TestMountManager:
    """Tests for MountManager class."""

    def test_mount_ext4(self):
        """Test mounting ext4 filesystem."""
        manager = MountManager()

        with mock.patch("subprocess.run") as mock_run:
            with mock.patch("os.makedirs"):
                with manager.mount("/dev/rbd0p1", "ext4") as mount_point:
                    assert mount_point is not None
                    assert "rbdclamscan" in mount_point

                    # Check mount command
                    mount_call = mock_run.call_args_list[0]
                    assert "ro,noload,norecovery" in mount_call[0][0]

    def test_mount_descriptive_path(self):
        """Test mount path includes VM name and disk name."""
        manager = MountManager()

        with mock.patch("subprocess.run") as mock_run:
            with mock.patch("os.makedirs"):
                with mock.patch("random.randint", return_value=12345):
                    with manager.mount("/dev/rbd0p1", "ext4", "webserver", "scsi0_rbd0p1") as mount_point:
                        assert mount_point == "/tmp/rbdclamscan_webserver_scsi0_rbd0p1_12345"

    def test_mount_sanitizes_vm_name(self):
        """Test mount path sanitizes special characters in VM name."""
        manager = MountManager()

        with mock.patch("subprocess.run") as mock_run:
            with mock.patch("os.makedirs"):
                with mock.patch("random.randint", return_value=99999):
                    with manager.mount("/dev/rbd0p1", "ext4", "web/server:test", "scsi0") as mount_point:
                        # Special chars should be replaced with underscores
                        assert mount_point == "/tmp/rbdclamscan_web_server_test_scsi0_99999"

    def test_mount_ntfs(self):
        """Test mounting NTFS filesystem."""
        manager = MountManager()

        with mock.patch("subprocess.run") as mock_run:
            with mock.patch("os.makedirs"):
                with manager.mount("/dev/rbd0p1", "ntfs") as mount_point:
                    assert mount_point is not None

                    # Check mount command uses ntfs-3g
                    mount_call = mock_run.call_args_list[0]
                    assert "ntfs-3g" in mount_call[0][0]

    def test_mount_xfs(self):
        """Test mounting XFS filesystem."""
        manager = MountManager()

        with mock.patch("subprocess.run") as mock_run:
            with mock.patch("os.makedirs"):
                with manager.mount("/dev/rbd0p1", "xfs") as mount_point:
                    assert mount_point is not None

                    mount_call = mock_run.call_args_list[0]
                    assert "ro,norecovery" in mount_call[0][0]

    def test_mount_vfat(self):
        """Test mounting vfat filesystem."""
        manager = MountManager()

        with mock.patch("subprocess.run") as mock_run:
            with mock.patch("os.makedirs"):
                with manager.mount("/dev/rbd0p1", "vfat") as mount_point:
                    assert mount_point is not None

                    mount_call = mock_run.call_args_list[0]
                    cmd = mount_call[0][0]
                    assert "-o" in cmd
                    ro_index = cmd.index("-o") + 1
                    assert cmd[ro_index] == "ro"

    def test_mount_skip_swap(self):
        """Test swap is skipped."""
        manager = MountManager()

        with mock.patch("subprocess.run") as mock_run:
            with manager.mount("/dev/rbd0p1", "swap") as mount_point:
                assert mount_point is None
                mock_run.assert_not_called()

    def test_mount_skip_lvm2_member(self):
        """Test LVM2_member is skipped."""
        manager = MountManager()

        with mock.patch("subprocess.run") as mock_run:
            with manager.mount("/dev/rbd0p1", "LVM2_member") as mount_point:
                assert mount_point is None
                mock_run.assert_not_called()

    def test_mount_unsupported_fs(self):
        """Test unsupported filesystem."""
        manager = MountManager()

        with mock.patch("subprocess.run") as mock_run:
            with manager.mount("/dev/rbd0p1", "btrfs") as mount_point:
                assert mount_point is None
                mock_run.assert_not_called()

    def test_mount_failure(self):
        """Test mount failure yields None."""
        manager = MountManager()

        with mock.patch("os.makedirs"):
            with mock.patch(
                "subprocess.run",
                side_effect=subprocess.CalledProcessError(1, "mount", stderr="error"),
            ):
                with manager.mount("/dev/rbd0p1", "ext4") as mount_point:
                    assert mount_point is None

    def test_unmount_failure_logged(self):
        """Test unmount failure is logged but doesn't raise."""
        manager = MountManager()
        manager.mount_points = ["/tmp/test"]

        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "umount", stderr="busy"),
        ):
            # Should not raise
            manager._unmount("/tmp/test")

    def test_unmount_all(self):
        """Test unmounting all filesystems."""
        manager = MountManager()
        manager.mount_points = ["/tmp/mp1", "/tmp/mp2"]

        with mock.patch("subprocess.run"):
            with mock.patch("os.rmdir"):
                manager.unmount_all()

        assert manager.mount_points == []

    def test_unmount_cleans_directory(self):
        """Test mount point directory is cleaned up."""
        manager = MountManager()
        manager.mount_points = ["/tmp/test_mp"]

        with mock.patch("subprocess.run"):
            with mock.patch("os.rmdir") as mock_rmdir:
                manager._unmount("/tmp/test_mp")
                mock_rmdir.assert_called_once_with("/tmp/test_mp")


# =============================================================================
# ClamScanner Tests
# =============================================================================
class TestClamScanner:
    """Tests for ClamScanner class."""

    def test_scan_clean(self, tmp_path):
        """Test scan with clean result."""
        scanner = ClamScanner(str(tmp_path))
        mock_result = mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = "/mnt/test: OK\n"
        mock_result.stderr = ""

        with mock.patch("subprocess.run", return_value=mock_result):
            report_path = scanner.scan("/mnt/test", "testvm", "scsi0")

        assert report_path.exists()
        content = report_path.read_text()
        assert "VM: testvm" in content
        assert "Disk: scsi0" in content
        assert "/mnt/test: OK" in content

    def test_scan_infected(self, tmp_path):
        """Test scan with infection found."""
        scanner = ClamScanner(str(tmp_path))
        mock_result = mock.Mock()
        mock_result.returncode = 1
        mock_result.stdout = "/mnt/test/virus.exe: Eicar-Test-Signature FOUND\n"
        mock_result.stderr = ""

        with mock.patch("subprocess.run", return_value=mock_result):
            report_path = scanner.scan("/mnt/test", "testvm", "scsi0")

        assert report_path.exists()
        content = report_path.read_text()
        assert "FOUND" in content

    def test_scan_error(self, tmp_path):
        """Test scan with error."""
        scanner = ClamScanner(str(tmp_path))
        mock_result = mock.Mock()
        mock_result.returncode = 2
        mock_result.stdout = ""
        mock_result.stderr = "clamd not running"

        with mock.patch("subprocess.run", return_value=mock_result):
            report_path = scanner.scan("/mnt/test", "testvm", "scsi0")

        assert report_path.exists()
        content = report_path.read_text()
        assert "STDERR" in content
        assert "clamd not running" in content

    def test_creates_report_dir(self, tmp_path):
        """Test report directory is created."""
        report_dir = tmp_path / "subdir" / "reports"
        scanner = ClamScanner(str(report_dir))

        assert report_dir.exists()


# =============================================================================
# VMScanner Tests
# =============================================================================
class TestVMScanner:
    """Tests for VMScanner class."""

    @pytest.fixture
    def config(self):
        return Config(
            proxmox_host="pve.example.com",
            proxmox_user="root@pam",
            proxmox_token_name="mytoken",
            proxmox_token_value="secret",
            report_dir="/tmp/reports",
        )

    @pytest.fixture
    def mock_proxmox_api(self):
        with mock.patch("rbdclamscan.ProxmoxAPI"):
            yield

    def test_parse_disk_config(self, config, mock_proxmox_api):
        """Test parsing disk config string."""
        scanner = VMScanner(config)

        result = scanner._parse_disk_config("pool-name:vm-100-disk-0,size=32G")
        assert result == ("pool-name", "vm-100-disk-0")

        result = scanner._parse_disk_config("ceph:vm-100-disk-0")
        assert result == ("ceph", "vm-100-disk-0")

        result = scanner._parse_disk_config("invalid")
        assert result is None

    def test_get_rbd_disks(self, config, mock_proxmox_api):
        """Test extracting RBD disks from VM config."""
        scanner = VMScanner(config)
        vm_config = {
            "scsi0": "pool:vm-100-disk-0,size=32G",
            "scsi1": "pool:vm-100-disk-1,size=64G",
            "virtio0": "pool:vm-100-disk-2,size=16G",
            "ide2": "none,media=cdrom",  # Should be ignored
            "memory": 4096,  # Not a disk
            "net0": "virtio=...",  # Not a disk
        }

        disks = scanner._get_rbd_disks(vm_config)

        assert len(disks) == 3
        disk_keys = [d[0] for d in disks]
        assert "scsi0" in disk_keys
        assert "scsi1" in disk_keys
        assert "virtio0" in disk_keys

    def test_should_scan_vm_no_filters(self, config, mock_proxmox_api):
        """Test VM filtering with no filters."""
        scanner = VMScanner(config)
        vm = {"vmid": 100, "node": "pve1"}

        assert scanner._should_scan_vm(vm) is True

    def test_should_scan_vm_include_vmids(self, config, mock_proxmox_api):
        """Test VM filtering with include_vmids."""
        config.include_vmids = [100, 101]
        scanner = VMScanner(config)

        assert scanner._should_scan_vm({"vmid": 100, "node": "pve1"}) is True
        assert scanner._should_scan_vm({"vmid": 102, "node": "pve1"}) is False

    def test_should_scan_vm_exclude_vmids(self, config, mock_proxmox_api):
        """Test VM filtering with exclude_vmids."""
        config.exclude_vmids = [999]
        scanner = VMScanner(config)

        assert scanner._should_scan_vm({"vmid": 100, "node": "pve1"}) is True
        assert scanner._should_scan_vm({"vmid": 999, "node": "pve1"}) is False

    def test_should_scan_vm_include_nodes(self, config, mock_proxmox_api):
        """Test VM filtering with include_nodes."""
        config.include_nodes = ["pve1", "pve2"]
        scanner = VMScanner(config)

        assert scanner._should_scan_vm({"vmid": 100, "node": "pve1"}) is True
        assert scanner._should_scan_vm({"vmid": 100, "node": "pve3"}) is False

    def test_scan_vm_no_disks(self, config, mock_proxmox_api, tmp_path):
        """Test scanning VM with no RBD disks."""
        config.report_dir = str(tmp_path)
        scanner = VMScanner(config)
        scanner.proxmox.get_vm_config = mock.Mock(return_value={"memory": 4096})

        vm = {"vmid": 100, "node": "pve1", "name": "testvm"}
        scanner.scan_vm(vm)

        # Should not raise, just log and return

    def test_scan_vm_get_config_fails(self, config, mock_proxmox_api, tmp_path):
        """Test scanning VM when get_config fails."""
        config.report_dir = str(tmp_path)
        scanner = VMScanner(config)
        scanner.proxmox.get_vm_config = mock.Mock(side_effect=Exception("API error"))

        vm = {"vmid": 100, "node": "pve1", "name": "testvm"}
        scanner.scan_vm(vm)

        # Should not raise, just log and return

    def test_scan_vm_snapshot_creation_fails(self, config, mock_proxmox_api, tmp_path):
        """Test scanning VM when snapshot creation fails."""
        config.report_dir = str(tmp_path)
        scanner = VMScanner(config)
        scanner.proxmox.get_vm_config = mock.Mock(
            return_value={"scsi0": "pool:vm-100-disk-0,size=32G"}
        )
        scanner.proxmox.create_snapshot = mock.Mock(side_effect=Exception("Snapshot error"))

        vm = {"vmid": 100, "node": "pve1", "name": "testvm"}
        scanner.scan_vm(vm)

        # Should not raise

    def test_scan_vm_snapshot_task_fails(self, config, mock_proxmox_api, tmp_path):
        """Test scanning VM when snapshot task fails."""
        config.report_dir = str(tmp_path)
        scanner = VMScanner(config)
        scanner.proxmox.get_vm_config = mock.Mock(
            return_value={"scsi0": "pool:vm-100-disk-0,size=32G"}
        )
        scanner.proxmox.create_snapshot = mock.Mock(return_value="UPID:test")
        scanner.proxmox.wait_for_task = mock.Mock(return_value=False)

        vm = {"vmid": 100, "node": "pve1", "name": "testvm"}
        scanner.scan_vm(vm)

        # Should not raise

    def test_scan_vm_full_flow(self, config, mock_proxmox_api, tmp_path):
        """Test full VM scanning flow."""
        config.report_dir = str(tmp_path)
        scanner = VMScanner(config)

        # Mock proxmox
        scanner.proxmox.get_vm_config = mock.Mock(
            return_value={"scsi0": "pool:vm-100-disk-0,size=32G"}
        )
        scanner.proxmox.create_snapshot = mock.Mock(return_value="UPID:snap")
        scanner.proxmox.delete_snapshot = mock.Mock(return_value="UPID:del")
        scanner.proxmox.wait_for_task = mock.Mock(return_value=True)

        # Mock RBD
        rbd_cm = mock.MagicMock()
        rbd_cm.__enter__ = mock.Mock(return_value="/dev/rbd0")
        rbd_cm.__exit__ = mock.Mock(return_value=False)
        scanner.rbd.map_snapshot = mock.Mock(return_value=rbd_cm)

        # Mock partition discovery
        scanner.partition_discovery.discover_partitions = mock.Mock(
            return_value=[{"device": "/dev/rbd0p1", "fstype": "ext4", "size": "32G"}]
        )

        # Mock mount
        mount_cm = mock.MagicMock()
        mount_cm.__enter__ = mock.Mock(return_value="/tmp/mount")
        mount_cm.__exit__ = mock.Mock(return_value=False)
        scanner.mount.mount = mock.Mock(return_value=mount_cm)

        # Mock scanner
        scanner.scanner.scan = mock.Mock(return_value=Path("/tmp/report.log"))

        vm = {"vmid": 100, "node": "pve1", "name": "testvm"}
        scanner.scan_vm(vm)

        # Verify calls
        scanner.proxmox.create_snapshot.assert_called_once()
        scanner.proxmox.delete_snapshot.assert_called_once()
        scanner.rbd.map_snapshot.assert_called_once_with("pool", "vm-100-disk-0", "clamscan")
        scanner.scanner.scan.assert_called_once()

    def test_scan_vm_default_name(self, config, mock_proxmox_api, tmp_path):
        """Test VM uses default name when name not provided."""
        config.report_dir = str(tmp_path)
        scanner = VMScanner(config)
        scanner.proxmox.get_vm_config = mock.Mock(return_value={"memory": 4096})

        vm = {"vmid": 100, "node": "pve1"}  # No name
        scanner.scan_vm(vm)

        # Should use "vm-100" as default name

    def test_scan_all(self, config, mock_proxmox_api, tmp_path):
        """Test scanning all VMs."""
        config.report_dir = str(tmp_path)
        scanner = VMScanner(config)

        scanner.proxmox.list_vms = mock.Mock(
            return_value=[
                {"vmid": 100, "node": "pve1", "name": "vm1"},
                {"vmid": 101, "node": "pve1", "name": "vm2"},
            ]
        )
        scanner.scan_vm = mock.Mock()

        scanner.scan_all()

        assert scanner.scan_vm.call_count == 2

    def test_scan_all_with_filter(self, config, mock_proxmox_api, tmp_path):
        """Test scanning with VM filter."""
        config.report_dir = str(tmp_path)
        config.include_vmids = [100]
        scanner = VMScanner(config)

        scanner.proxmox.list_vms = mock.Mock(
            return_value=[
                {"vmid": 100, "node": "pve1", "name": "vm1"},
                {"vmid": 101, "node": "pve1", "name": "vm2"},
            ]
        )
        scanner.scan_vm = mock.Mock()

        scanner.scan_all()

        assert scanner.scan_vm.call_count == 1

    def test_scan_all_handles_errors(self, config, mock_proxmox_api, tmp_path):
        """Test scan_all continues after VM error."""
        config.report_dir = str(tmp_path)
        scanner = VMScanner(config)

        scanner.proxmox.list_vms = mock.Mock(
            return_value=[
                {"vmid": 100, "node": "pve1", "name": "vm1"},
                {"vmid": 101, "node": "pve1", "name": "vm2"},
            ]
        )
        scanner.scan_vm = mock.Mock(side_effect=[Exception("Error"), None])

        scanner.scan_all()

        # Should have tried both VMs
        assert scanner.scan_vm.call_count == 2

    def test_scan_partition_lvm(self, config, mock_proxmox_api, tmp_path):
        """Test scanning LVM partition."""
        config.report_dir = str(tmp_path)
        scanner = VMScanner(config)

        # Mock LVM
        lvm_cm = mock.MagicMock()
        lvm_cm.__enter__ = mock.Mock(return_value=["/dev/vg/root"])
        lvm_cm.__exit__ = mock.Mock(return_value=False)
        scanner.lvm.scan_and_activate = mock.Mock(return_value=lvm_cm)

        # Mock filesystem discovery
        scanner.partition_discovery.get_filesystem_type = mock.Mock(return_value="ext4")

        # Mock mount and scan
        mount_cm = mock.MagicMock()
        mount_cm.__enter__ = mock.Mock(return_value="/tmp/mount")
        mount_cm.__exit__ = mock.Mock(return_value=False)
        scanner.mount.mount = mock.Mock(return_value=mount_cm)
        scanner.scanner.scan = mock.Mock(return_value=Path("/tmp/report.log"))

        scanner._scan_partition("/dev/rbd0p2", "LVM2_member", "testvm", "scsi0")

        scanner.lvm.scan_and_activate.assert_called_once_with("/dev/rbd0p2")
        scanner.scanner.scan.assert_called_once()

    def test_scan_filesystem_skip_none(self, config, mock_proxmox_api, tmp_path):
        """Test scanning skips None filesystem."""
        config.report_dir = str(tmp_path)
        scanner = VMScanner(config)
        scanner.scanner.scan = mock.Mock()

        scanner._scan_filesystem("/dev/rbd0p1", None, "testvm", "scsi0")

        scanner.scanner.scan.assert_not_called()

    def test_scan_filesystem_skip_swap(self, config, mock_proxmox_api, tmp_path):
        """Test scanning skips swap."""
        config.report_dir = str(tmp_path)
        scanner = VMScanner(config)
        scanner.scanner.scan = mock.Mock()

        scanner._scan_filesystem("/dev/rbd0p1", "swap", "testvm", "scsi0")

        scanner.scanner.scan.assert_not_called()


# =============================================================================
# CLI Tests
# =============================================================================
class TestCLI:
    """Tests for CLI functions."""

    def test_parse_args_defaults(self):
        """Test default argument values."""
        with mock.patch("sys.argv", ["rbdclamscan"]):
            args = parse_args()

        assert args.config is None
        assert args.host is None
        assert args.verbose is False
        assert args.verify_ssl is False

    def test_parse_args_all_options(self):
        """Test all CLI options."""
        with mock.patch(
            "sys.argv",
            [
                "rbdclamscan",
                "--config",
                "/etc/clamscan.ini",
                "--host",
                "pve.example.com",
                "--user",
                "root@pam",
                "--token-name",
                "mytoken",
                "--token-value",
                "secret",
                "--ceph-user",
                "cephuser",
                "--report-dir",
                "/tmp/reports",
                "--vmid",
                "100",
                "--vmid",
                "101",
                "--exclude-vmid",
                "999",
                "--node",
                "pve1",
                "--verify-ssl",
                "--verbose",
            ],
        ):
            args = parse_args()

        assert args.config == "/etc/clamscan.ini"
        assert args.host == "pve.example.com"
        assert args.user == "root@pam"
        assert args.token_name == "mytoken"
        assert args.token_value == "secret"
        assert args.ceph_user == "cephuser"
        assert args.report_dir == "/tmp/reports"
        assert args.vmid == [100, 101]
        assert args.exclude_vmid == [999]
        assert args.node == ["pve1"]
        assert args.verify_ssl is True
        assert args.verbose is True

    def test_main_missing_config(self):
        """Test main exits on missing config."""
        with mock.patch("sys.argv", ["rbdclamscan"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 1

    def test_main_success(self, tmp_path):
        """Test successful main execution."""
        with mock.patch(
            "sys.argv",
            [
                "rbdclamscan",
                "--host",
                "pve.example.com",
                "--user",
                "root@pam",
                "--token-name",
                "mytoken",
                "--token-value",
                "secret",
                "--report-dir",
                str(tmp_path),
            ],
        ):
            with mock.patch("rbdclamscan.VMScanner") as mock_scanner:
                main()

        mock_scanner.return_value.scan_all.assert_called_once()

    def test_main_verbose(self, tmp_path):
        """Test verbose logging is enabled."""
        with mock.patch(
            "sys.argv",
            [
                "rbdclamscan",
                "--host",
                "pve.example.com",
                "--user",
                "root@pam",
                "--token-name",
                "mytoken",
                "--token-value",
                "secret",
                "--report-dir",
                str(tmp_path),
                "--verbose",
            ],
        ):
            with mock.patch("rbdclamscan.VMScanner"):
                with mock.patch("logging.getLogger") as mock_logger:
                    main()

        mock_logger.return_value.setLevel.assert_called()


# =============================================================================
# Integration-style Tests
# =============================================================================
class TestIntegration:
    """Integration-style tests for complex scenarios."""

    def test_scan_vm_snapshot_cleanup_on_error(self, tmp_path):
        """Test snapshot is deleted even when scan fails."""
        config = Config(
            proxmox_host="pve.example.com",
            proxmox_user="root@pam",
            proxmox_token_name="mytoken",
            proxmox_token_value="secret",
            report_dir=str(tmp_path),
        )

        with mock.patch("rbdclamscan.ProxmoxAPI"):
            scanner = VMScanner(config)

        scanner.proxmox.get_vm_config = mock.Mock(
            return_value={"scsi0": "pool:vm-100-disk-0,size=32G"}
        )
        scanner.proxmox.create_snapshot = mock.Mock(return_value="UPID:snap")
        scanner.proxmox.delete_snapshot = mock.Mock(return_value="UPID:del")
        scanner.proxmox.wait_for_task = mock.Mock(return_value=True)

        # Make RBD mapping fail
        scanner.rbd.map_snapshot = mock.Mock(side_effect=Exception("RBD error"))

        vm = {"vmid": 100, "node": "pve1", "name": "testvm"}
        scanner.scan_vm(vm)

        # Snapshot should still be deleted
        scanner.proxmox.delete_snapshot.assert_called_once()

    def test_scan_partition_fstype_discovery(self, tmp_path):
        """Test fstype discovery when not provided."""
        config = Config(
            proxmox_host="pve.example.com",
            proxmox_user="root@pam",
            proxmox_token_name="mytoken",
            proxmox_token_value="secret",
            report_dir=str(tmp_path),
        )

        with mock.patch("rbdclamscan.ProxmoxAPI"):
            scanner = VMScanner(config)

        scanner.partition_discovery.get_filesystem_type = mock.Mock(return_value="ext4")

        mount_cm = mock.MagicMock()
        mount_cm.__enter__ = mock.Mock(return_value="/tmp/mount")
        mount_cm.__exit__ = mock.Mock(return_value=False)
        scanner.mount.mount = mock.Mock(return_value=mount_cm)
        scanner.scanner.scan = mock.Mock(return_value=Path("/tmp/report.log"))

        # Pass None as fstype
        scanner._scan_partition("/dev/rbd0p1", None, "testvm", "scsi0")

        scanner.partition_discovery.get_filesystem_type.assert_called_once_with("/dev/rbd0p1")
        scanner.scanner.scan.assert_called_once()
