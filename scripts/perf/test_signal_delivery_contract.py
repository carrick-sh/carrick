"""No guests, Docker, forks, or external commands: protocol negative controls."""
import argparse
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import signal_delivery_contract as driver

IMAGE = "example.test/arm@sha256:" + "a" * 64
LINE = "wfi-signal rounds=200 eintr=200 handled=200 wake_p50_us=12.5 wake_max_us=40.0\n"


def sample(line=LINE):
    return {"exit_code": 0, "stdout": line, "stderr": ""}


def embed(line=LINE):
    record = {"image": IMAGE, "exit_code": 0, "signal": None, "stdout": line,
              "stderr": "", "idle_exits": 200, "wfi_entries": 201}
    return sample("running 1 test\n" + f"test {driver.TEST} ... ok\n" +
                  driver.PREFIX + json.dumps(record) + "\n" +
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 9 filtered out\n")


class ProtocolTests(unittest.TestCase):
    def test_valid_native_and_embed(self):
        self.assertEqual(driver.parse_sample(sample()), driver.parse_sample(embed(), IMAGE))

    def test_bad_metrics(self):
        for line in ["", LINE + LINE, LINE.replace(" wake_p50_us=12.5", ""),
                     LINE.replace("wake_p50_us=12.5", "wake_p50_us=12.5 wake_p50_us=12.5")]:
            with self.subTest(line=line), self.assertRaises(driver.Rejected):
                driver.parse_sample(sample(line))
        for key in ["rounds", "eintr", "handled", "wake_p50_us", "wake_max_us"]:
            for value in ["0", "nan", "inf", "-inf", "-1", "garbage"]:
                import re
                line = re.sub(rf"{key}=[^\s]+", f"{key}={value}", LINE)
                with self.subTest(key=key, value=value), self.assertRaises(driver.Rejected):
                    driver.parse_sample(sample(line))
        for key in ["rounds", "eintr", "handled"]:
            with self.subTest(key=key), self.assertRaises(driver.Rejected):
                driver.parse_sample(sample(LINE.replace(f"{key}=200", f"{key}=199")))

    def test_test_protocol_fail_closed(self):
        good = embed()
        for old, new in [("running 1 test", "running 0 tests"),
                         ("1 passed; 0 failed", "0 passed; 1 failed"),
                         ("0 ignored", "1 ignored"),
                         (f"test {driver.TEST} ... ok", "test other ... ok"),
                         ('"idle_exits": 200', '"idle_exits": 199'),
                         ('"wfi_entries": 201', '"wfi_entries": 0'),
                         ('"exit_code": 0', '"exit_code": 1'),
                         ('"signal": null', '"signal": 9'),
                         (IMAGE, IMAGE + "bad")]:
            bad = copy.deepcopy(good)
            bad["stdout"] = bad["stdout"].replace(old, new)
            with self.subTest(old=old), self.assertRaises(driver.Rejected):
                driver.parse_sample(bad, IMAGE)
        for body in [good["stdout"].replace(driver.PREFIX, "missing "),
                     good["stdout"] + driver.PREFIX + "{}\n"]:
            with self.assertRaises(driver.Rejected):
                driver.parse_sample(sample(body), IMAGE)
        for result in [sample(), embed()]:
            result["exit_code"] = 1
            with self.assertRaises(driver.Rejected):
                driver.parse_sample(result, IMAGE if "running" in result["stdout"] else None)

    def test_minimum_and_real_paired_aggregation(self):
        pairs = [{"carrick": {"wake_p50_us": i + 1.0},
                  "docker": {"wake_p50_us": 10.0}} for i in range(20)]
        with self.assertRaises(driver.Rejected):
            driver.aggregate(pairs[:19])
        self.assertEqual(driver.aggregate(pairs)["ratio"], 1.05)
        pairs[0]["carrick"]["wake_p50_us"] = 1000
        self.assertEqual(driver.aggregate(pairs)["ratio"], 1.15)
        for pair in pairs:
            pair["carrick"]["wake_p50_us"] = 30
        self.assertFalse(driver.aggregate(pairs)["passed"])

    def test_identity_drift(self):
        expected = {"binary_sha256": "a", "fixture_sha256": "b"}
        driver.check_identity(expected, expected.copy())
        for key in expected:
            with self.subTest(key=key), self.assertRaises(driver.Rejected):
                driver.check_identity(expected, dict(expected, **{key: "changed"}))

    def test_image_pin(self):
        driver.pinned(IMAGE)
        for image in ["ubuntu:latest", "foo@sha256:abc", IMAGE + " "]:
            with self.assertRaises(driver.Rejected):
                driver.pinned(image)


class LeaseTests(unittest.TestCase):
    @patch.dict("os.environ", {"CARRICK_HOST_LEASE_SOCKET": "/mock/socket",
                              "CARRICK_HOST_LEASE_SCOPE_FD": "9"})
    def test_actual_gate_protocol_and_negative_controls(self):
        from types import SimpleNamespace
        identity = {"dev": 1, "ino": 2, "mode": "gate", "scope": {"dev": 3, "ino": 4}}
        for mutation, accepted in [({}, True), ({"mode": "carrick"}, False),
                                   ({"mode": "docker"}, False), ({"ino": 8}, False),
                                   ({"scope": None}, False),
                                   ({"scope": {"dev": 3, "ino": 99}}, False),
                                   ({"broker": {"host": "remote"}}, False)]:
            reply = dict(identity, **mutation)
            with self.subTest(reply=reply), patch("signal_delivery_contract.socket.socket") as sock, patch("signal_delivery_contract.Path.stat", return_value=SimpleNamespace(st_dev=1, st_ino=2)), patch("signal_delivery_contract.os.fstat", return_value=SimpleNamespace(st_dev=3, st_ino=4, st_mode=driver.stat.S_IFIFO)), patch("signal_delivery_contract.fcntl.fcntl", return_value=driver.os.O_WRONLY):
                sock.return_value.__enter__.return_value.recv.side_effect = [json.dumps(reply).encode(), b""]
                if accepted:
                    self.assertEqual(driver.gate_identity(), reply)
                else:
                    with self.assertRaises(driver.Rejected):
                        driver.gate_identity()


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.driver = driver.Driver(argparse.Namespace(binary="/unused", xtask="/unused",
                                   image=IMAGE, output=str(Path(self.temp.name) / "evidence")))

    @patch.dict("os.environ", {"CARRICK_RUN_ID": "signal-unit", "CARRICK_HOST_LEASE_SCOPE_FD": "9"})
    def test_command_nonzero_keeps_logs_without_external_execution(self):
        with patch("signal_delivery_contract.subprocess.Popen") as spawn:
            spawn.return_value.wait.return_value = 7
            with self.assertRaises(driver.Rejected):
                self.driver.command(["mock-child"])
        record = json.loads((self.driver.output / "0001.json").read_text())
        self.assertEqual(record["exit_code"], 7)
        self.assertEqual(record["command"], ["mock-child"])
        self.assertTrue((self.driver.output / "0001.stdout").exists())
        self.assertTrue((self.driver.output / "0001.stderr").exists())
        self.assertEqual(spawn.call_args.kwargs["pass_fds"], (9,))

    @patch.dict("os.environ", {"CARRICK_RUN_ID": "signal-unit", "CARRICK_HOST_LEASE_SCOPE_FD": "9"})
    def test_timeout_records_exit_and_kills_only_child_group(self):
        with patch("signal_delivery_contract.subprocess.Popen") as spawn, patch("signal_delivery_contract.os.killpg") as kill:
            spawn.return_value.pid = 1234
            spawn.return_value.returncode = -9
            spawn.return_value.wait.side_effect = [driver.subprocess.TimeoutExpired("mock", 1), -9]
            with self.assertRaises(driver.subprocess.TimeoutExpired):
                self.driver.command(["mock-child"], timeout=1)
        kill.assert_called_once_with(1234, driver.signal.SIGKILL)
        record = json.loads((self.driver.output / "0001.json").read_text())
        self.assertEqual(record["exit_code"], -9)
        self.assertTrue(record["interrupted"])

    @patch.dict("os.environ", {"CARRICK_RUN_ID": "signal-unit"})
    def test_pair_order_and_cleanup_with_mocked_execution(self):
        commands = []

        def command(argv, **kwargs):
            commands.append(argv)
            if argv[0] == "/unused":
                return embed()
            if argv[:2] == ["docker", "run"]:
                return sample()
            if argv[:2] == ["docker", "ps"]:
                return sample("")
            return sample("remaining carrick procs = 0\n")

        with patch.object(self.driver, "identity", return_value={}), patch.object(self.driver, "command", side_effect=command):
            self.driver.pair("warmup", {})
            self.driver.pair("pair-000", {})
        self.assertEqual(len(self.driver.report["warmup_excluded"]), 1)
        self.assertEqual(len(self.driver.report["pairs"]), 1)
        self.assertEqual([a[0] for a in commands], ["/unused", "sudo", "docker", "docker"] * 2)
        self.assertIn("--show-output", commands[0])
        self.assertIn(IMAGE, commands[2])
        self.assertIn("wfi-signal", commands[2])

    @patch.dict("os.environ", {"CARRICK_RUN_ID": "signal-unit"})
    def test_bad_carrick_stops_before_docker_and_preserves_raw(self):
        result = embed()
        result["exit_code"] = 7
        with patch.object(self.driver, "identity", return_value={}), patch.object(self.driver, "cleanup_carrick") as cleanup, patch.object(self.driver, "command", return_value=result) as command:
            with self.assertRaises(driver.Rejected):
                self.driver.pair("pair-000", {})
        cleanup.assert_called_once()
        command.assert_called_once()
        self.assertEqual(self.driver.report["pairs"][0]["carrick_raw"]["exit_code"], 7)

    def test_cleanup_failure_rejected(self):
        for result in [sample("remaining carrick procs = 1"),
                       sample("pass 1: killing 1 procs\nremaining carrick procs = 0")]:
            with patch.dict("os.environ", {"CARRICK_RUN_ID": "unit"}), patch.object(self.driver, "command", return_value=result), self.assertRaises(driver.Rejected):
                self.driver.cleanup_carrick()

    @patch.dict("os.environ", {"CARRICK_RUN_ID": "signal-unit"})
    def test_docker_cleanup_failure_rejected(self):
        def command(argv, **kwargs):
            if argv[0] == "/unused":
                return embed()
            if argv[:2] == ["docker", "ps"]:
                return sample("leftover-id")
            return sample()
        with patch.object(self.driver, "identity", return_value={}), patch.object(self.driver, "cleanup_carrick"), patch.object(self.driver, "command", side_effect=command) as command:
            with self.assertRaises(driver.Rejected):
                self.driver.pair("pair-000", {})
        self.assertEqual(command.call_args.args[0], ["docker", "rm", "-f", "signal-unit-pair-000"])


if __name__ == "__main__":
    unittest.main()
