#!/usr/bin/env python3
"""Run the ZAP experiment against the currently deployed sqli namespace.

This wrapper intentionally does not apply kustomize profiles and does not restart
Kubernetes deployments. Use it after manually choosing the desired live profile.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'rasp_toggle_experiment_zap.py'


def main() -> int:
    profile = 'current'
    mode = 'sqli-focused'
    extra_args = []
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ('--profile-label', '--profile'):
            try:
                profile = args[i + 1]
            except IndexError:
                raise SystemExit(f'{args[i]} requires a value')
            i += 2
        elif args[i] == '--mode':
            try:
                mode = args[i + 1]
            except IndexError:
                raise SystemExit('--mode requires a value (sqli-focused|full)')
            i += 2
        else:
            extra_args.append(args[i])
            i += 1

    if mode not in ('sqli-focused', 'full'):
        raise SystemExit(f'Unsupported mode: {mode}. Use sqli-focused or full.')

    cmd = [
        sys.executable,
        str(SCRIPT),
        '--profiles',
        profile,
        '--skip-profile-apply',
        '--skip-final-restore',
    ]
    if mode == 'sqli-focused':
        cmd.extend([
            '--scan-paths',
            '/webgoat/WebGoat/SqlInjection',
            '--spider-max-children',
            '10',
        ])
    cmd.extend(extra_args)
    return subprocess.call(cmd)


if __name__ == '__main__':
    raise SystemExit(main())
