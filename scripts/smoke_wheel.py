"""Install/exercise the actual built wheel in a disposable venv and user home."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv
import zipfile


def main():
    repository = Path(__file__).resolve().parents[1]
    wheels = sorted((repository / 'dist').glob('icezy_audit-*.whl'))
    if len(wheels) != 1:
        raise RuntimeError('Expected exactly one built Icezy Audit wheel')
    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Wheel integrity failed')
        names = archive.namelist()
        payload = [n for n in names if n.startswith('icezy_audit/payload/')]
        if len(payload) != 17 or not any('/.cursor/' in n for n in payload) or not any('/.github/' in n for n in payload):
            raise RuntimeError('Incomplete packaged baseline')
    env = dict(os.environ)
    env.pop('PYTHONPATH', None)
    env['PIP_DISABLE_PIP_VERSION_CHECK'] = '1'
    with tempfile.TemporaryDirectory(prefix='icezy-wheel-smoke-') as directory:
        root = Path(directory).resolve()
        virtual = root / 'venv'
        venv.EnvBuilder(with_pip=True).create(virtual)
        bindir = virtual / ('Scripts' if os.name == 'nt' else 'bin')
        python = bindir / ('python.exe' if os.name == 'nt' else 'python')
        command = bindir / ('icezy-audit.exe' if os.name == 'nt' else 'icezy-audit')
        installed = subprocess.run([str(python), '-m', 'pip', 'install', '--no-index', '--no-deps', str(wheel)],
                                   cwd=root, env=env, capture_output=True, text=True, timeout=90)
        if installed.returncode:
            raise RuntimeError('Local wheel installation failed: ' + installed.stderr[-500:])
        home = root / 'synthetic owner home'
        def run(*args):
            result = subprocess.run([str(command), *args, '--home', str(home)], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise RuntimeError('Installed command failed: ' + result.stdout[-500:])
            return json.loads(result.stdout)
        preview = run('install')
        if home.exists() or preview['apply']:
            raise RuntimeError('Dry run wrote a user directory')
        run('install', '--apply')
        status = run('status')
        if len(status['adapters']) != 5 or not all(i['baseline_verified'] for i in status['adapters']):
            raise RuntimeError('Installed adapter/baseline verification failed')
        run('install', '--apply')
        run('uninstall', '--apply')
        if run('status')['adapters']:
            raise RuntimeError('Installed command uninstall failed')
    print(json.dumps({'installed_wheel_smoke': 'PASS', 'adapters_verified': 5,
                      'pythonpath_removed': True, 'real_agent_home_changed': False}))


if __name__ == '__main__':
    main()
