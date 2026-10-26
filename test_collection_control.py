#!/usr/bin/env python3
"""Offline tests of the WSL controller; never attach to MTGA or use Windows py.exe."""
import argparse
from datetime import datetime, timezone
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import collection_control as ctl


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.reference = self.root / ctl.DEFAULT_REFERENCE
        self.files = ctl.required_paths(self.root, self.reference, False, False)
        for path in self.files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture', encoding='utf-8')
        self.args = argparse.Namespace(action='run', reference=ctl.DEFAULT_REFERENCE,
                                       scan_only=False, no_brawl=False, dry_run=False)

    def tearDown(self):
        self.tmp.cleanup()

    def stub_step(self, title, argv, logfile):
        logfile.write_text(f'PASS: {title}\n', encoding='utf-8')
        dest = logfile.parent
        if logfile.name == '01-extraction.log':
            (dest / 'collection_snapshot.json').write_text(json.dumps({
                'runs': [{'records': [{'card_id': 42, 'quantity': 2}]}],
                'status': 'candidate_unconfirmed',
                'reference_changes': {'newly_owned': [], 'no_longer_present': [],
                                      'quantity_changed': [{'card_id': 42}]},
            }), encoding='utf-8')
        elif logfile.name == '03-resolution.log':
            (dest / 'resolved_collection_snapshot.json').write_text(json.dumps({
                'summary': {'owned_arena_ids': 1, 'recorded_owned_copies': 2,
                            'unresolved_arena_ids': 0, 'arena_db_verified_identity_only': 0},
            }), encoding='utf-8')
        elif logfile.name == '05-brawl-audit.log':
            (dest / 'brawl_readiness.json').write_text(json.dumps({
                'summary': {'owned_arena_ids': 1, 'unique_eligible_commander_names': 1}
            }), encoding='utf-8')
            (dest / 'brawl_cards.csv').write_text('arena_id\n42\n', encoding='utf-8')
            (dest / 'brawl_commanders.csv').write_text('arena_id\n42\n', encoding='utf-8')

    def invoke(self, mock_step=None):
        with patch.object(ctl.shutil, 'which', return_value='/fake/executable'), \
             patch.object(ctl, 'wsl_windows_path', side_effect=lambda p: 'WINDOWS:' + str(p)), \
             patch.object(ctl, 'stream_step', side_effect=mock_step or self.stub_step):
            return ctl.run(self.args, root=self.root)

    def test_plan_invokes_windows_reader_then_independent_audits(self):
        out = self.root / 'data/snapshots/preview'
        steps = ctl.make_steps(self.root, self.reference, out, scan_only=False,
                               no_brawl=False, use_deck_index=False,
                               translator=lambda p: 'WIN:' + str(p))
        self.assertEqual(len(steps), 5)
        self.assertEqual(steps[0][1][:2], ['py.exe', '-3'])
        self.assertIn('extract_collection.py', steps[0][1][2])
        self.assertIn('--reference', steps[0][1])
        self.assertIn('--output', steps[0][1])
        self.assertIn('audit_collection_change_aware.py', steps[1][1][1])
        self.assertIn('resolve_collection_cards.py', steps[2][1][1])
        self.assertIn('audit_resolved_collection.py', steps[3][1][1])
        self.assertIn('audit_brawl_readiness.py', steps[4][1][1])
        self.assertNotIn('--deck-index', steps[2][1])

    def test_full_workflow_saves_manifest_on_success(self):
        dest = self.invoke()
        result = json.loads((dest / 'run_summary.json').read_text(encoding='utf-8'))
        self.assertEqual(result['workflow_status'], 'all_requested_stages_passed')
        self.assertEqual(result['results']['recorded_copies'], 2)
        self.assertEqual(result['results']['reference_changes']['quantity_changed'], 1)
        self.assertEqual(result['results']['resolved_identities'], 1)
        self.assertEqual(result['results']['commander_names_by_snapshot'], 1)
        self.assertEqual(ctl.latest_successful(self.root), dest)
        self.assertEqual(self.reference.read_text(encoding='utf-8'), 'fixture')

    def test_scan_only_does_not_run_resolution(self):
        self.args.scan_only = True
        dest = self.invoke()
        self.assertTrue((dest / 'run_summary.json').exists())
        self.assertFalse((dest / 'resolved_collection_snapshot.json').exists())
        self.assertFalse((dest / '03-resolution.log').exists())

    def test_no_brawl_retains_resolution(self):
        self.args.no_brawl = True
        dest = self.invoke()
        self.assertTrue((dest / 'resolved_collection_snapshot.json').is_file())
        self.assertFalse((dest / 'brawl_readiness.json').exists())

    def test_failed_stage_never_marks_complete(self):
        def failing_step(title, argv, logfile):
            if logfile.name == '03-resolution.log':
                raise ctl.ControlError('Injected resolution failure')
            self.stub_step(title, argv, logfile)
        with self.assertRaisesRegex(ctl.ControlError, 'Injected'):
            self.invoke(failing_step)
        runs = list((self.root / ctl.RUNS_SUBDIR).glob(ctl.RUN_PREFIX + '*'))
        self.assertEqual(len(runs), 1)
        self.assertFalse((runs[0] / 'run_summary.json').exists())

    def test_missing_dependencies_stop_before_writes(self):
        (self.root / 'resolve_collection_cards.py').unlink()
        with self.assertRaisesRegex(ctl.ControlError, 'Missing required files'):
            self.invoke()
        self.assertFalse((self.root / ctl.RUNS_SUBDIR).exists())

    def test_dry_run_never_creates_directory(self):
        self.args.dry_run = True
        self.assertIsNone(self.invoke())
        self.assertFalse((self.root / ctl.RUNS_SUBDIR).exists())

    def test_run_dirs_never_collide(self):
        constant = lambda: datetime(2026, 10, 26, 7, 30, tzinfo=timezone.utc)
        parent = self.root / ctl.RUNS_SUBDIR
        first = ctl.make_directory(parent, clock=constant)
        second = ctl.make_directory(parent, clock=constant)
        self.assertNotEqual(first, second)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_stream_runner_captures_success_and_failure(self):
        log_ok = self.root / 'ok.log'
        ctl.stream_step('short test', [sys.executable, '-c', "print('CAPTURED')"], log_ok)
        self.assertIn('CAPTURED', log_ok.read_text(encoding='utf-8'))
        log_bad = self.root / 'bad.log'
        with self.assertRaisesRegex(ctl.ControlError, 'exit 9'):
            ctl.stream_step('failing test', [sys.executable, '-c',
                            "print('FAILED OUTPUT'); raise SystemExit(9)"], log_bad)
        self.assertIn('FAILED OUTPUT', log_bad.read_text(encoding='utf-8'))

    def test_real_uploaded_audit_summary(self):
        # Optional extra test only when developing against the user's uploaded samples.
        base = Path('/mnt/data')
        source_files = ['collection_candidate.json', 'resolved_collection_candidate.json',
                        'brawl_readiness_audit.json']
        if not all((base / name).is_file() for name in source_files):
            self.skipTest('Project fixtures not present')
        out = self.root / 'audit_fixtures'
        out.mkdir()
        (out / 'collection_snapshot.json').write_bytes((base / 'collection_candidate.json').read_bytes())
        (out / 'resolved_collection_snapshot.json').write_bytes((base / 'resolved_collection_candidate.json').read_bytes())
        (out / 'brawl_readiness.json').write_bytes((base / 'brawl_readiness_audit.json').read_bytes())
        summary = ctl.inspect_snapshot(out, False, False)
        self.assertEqual(summary['collection_ids'], 1660)
        self.assertEqual(summary['recorded_copies'], 2527)
        self.assertEqual(summary['resolved_identities'], 1660)
        self.assertEqual(summary['identity_only'], 86)
        self.assertEqual(summary['commander_names_by_snapshot'], 133)


if __name__ == '__main__':
    unittest.main()
