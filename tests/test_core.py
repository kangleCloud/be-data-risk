import json
from pathlib import Path
import tempfile
import unittest
from risk.tailer import FileTailer, SourceError, checkpoint_json, restore_checkpoint
from risk.config import load_config
class TailerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'sample.log'

    def reader(self, **kwargs):
        reader = FileTailer(self.path, **kwargs)
        self.addCleanup(reader.close)
        return reader

    def test_partial_restart(self):
        self.path.write_bytes(b'one\ntw')
        reader = self.reader()
        first = reader.prepare()
        reader.acknowledge(first)
        checkpoint = reader.checkpoint
        self.assertIsNone(reader.prepare())
        reader.close()
        with self.path.open('ab') as stream:
            stream.write(b'o\n')
        resumed = self.reader(checkpoint=checkpoint)
        self.assertEqual(resumed.prepare().raw, b'two\n')

    def test_failure_replay_and_stale_ack(self):
        self.path.write_bytes(b'one\n')
        reader = self.reader()
        candidate = reader.prepare()
        self.assertIs(reader.prepare(), candidate)
        self.assertEqual(reader.checkpoint.offset, 0)
        reader.acknowledge(candidate)
        with self.assertRaises(RuntimeError):
            reader.acknowledge(candidate)

    def test_rename_rotation(self):
        self.path.write_bytes(b'old\n')
        reader = self.reader()
        first = reader.prepare()
        self.path.rename(self.path.with_suffix('.1'))
        self.path.write_bytes(b'new\n')
        reader.acknowledge(first)
        rotation = reader.prepare()
        self.assertEqual(rotation.reason, 'SOURCE_ROTATED')
        reader.acknowledge(rotation)
        self.assertEqual(reader.prepare().raw, b'new\n')

    def test_restart_renamed_inode(self):
        self.path.write_bytes(b'old\nmore\n')
        reader = self.reader()
        reader.acknowledge(reader.prepare())
        checkpoint = reader.checkpoint
        reader.close()
        self.path.rename(self.path.with_suffix('.1'))
        self.path.write_bytes(b'new\n')
        self.assertEqual(self.reader(checkpoint=checkpoint).prepare().raw, b'more\n')

    def test_truncation(self):
        self.path.write_bytes(b'long line\n')
        reader = self.reader()
        reader.acknowledge(reader.prepare())
        self.path.write_bytes(b'x\n')
        change = reader.prepare()
        self.assertEqual(change.reason, 'SOURCE_TRUNCATED')
        reader.acknowledge(change)
        self.assertEqual(reader.prepare().raw, b'x\n')

    def test_oversized_and_half_line(self):
        self.path.write_bytes(b'123456789')
        reader = self.reader(max_line_bytes=4)
        self.assertIsNone(reader.prepare())
        with self.path.open('ab') as stream:
            stream.write(b'\nOK\n')
        candidate = reader.prepare()
        self.assertEqual(candidate.reason, 'LINE_TOO_LONG')
        self.assertIsNone(candidate.raw)
        reader.acknowledge(candidate)
        self.assertEqual(reader.prepare().raw, b'OK\n')

    def test_lost_checkpoint_file_fails_closed(self):
        self.path.write_bytes(b'one\n')
        reader = self.reader()
        reader.acknowledge(reader.prepare())
        checkpoint = reader.checkpoint
        reader.close()
        self.path.unlink()
        self.path.write_bytes(b'new\n')
        # inode reuse is possible; use a definitely absent identity.
        from dataclasses import replace
        with self.assertRaises(RuntimeError):
            self.reader(checkpoint=replace(checkpoint, inode=-1)).prepare()


if __name__ == '__main__':
    unittest.main()

class ConfigTest(unittest.TestCase):
    def test_safe_defaults(self):
        from risk.config import load_config
        config = load_config('examples/config.example.json')
        self.assertEqual(config.sources, ())
        self.assertIsNone(config.privacy.source('8.8.8.8'))

    def test_invalid_config(self):
        from risk.config import load_config
        cases = [{'sources': [{'alias': 'secret/path', 'path': '/tmp/sample'}]},
                 {'sources': [{'alias': 'sample', 'path': 'relative'}]},
                 {'directPeerTrusted': 'true'}, {'maxLineBytes': True}, {'password': 'secret'}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            for value in cases:
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    load_config(path)
