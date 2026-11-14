#!/usr/bin/env python3
"""Verify cone-mode sparse paths for directory and individual-file source locks."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('fetch_sources', Path(__file__).resolve().parents[1] / 'tools/fetch-sources.py')
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


class SourceFetchTest(unittest.TestCase):
    def test_sparse_paths_are_repository_relative(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'deps/linux'
            required = directory / 'include/net/example.h'
            required.parent.mkdir(parents=True)
            required.write_text('fixture')
            source = {'commit': 'locked', 'paths': ['/include/', '/net/core/skbuff.c'],
                      'required': ['include/net/example.h']}
            with patch.object(fetch, 'ROOT', root), patch.object(fetch, 'git', side_effect=['locked', '']), \
                    patch.object(fetch.subprocess, 'run') as run:
                fetch.resolve('linux', source, False)
            self.assertEqual(run.call_args.args[0], ['git', '-C', str(directory), 'sparse-checkout', 'add',
                                                     '--skip-checks', 'include', 'net/core/skbuff.c'])


if __name__ == '__main__':
    unittest.main()
