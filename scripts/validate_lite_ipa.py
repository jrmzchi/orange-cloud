#!/usr/bin/env python3
"""Validate the actual Lite archive before it can be released or enter AltStore."""
import argparse
import json
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile
import zipfile


def version(value):
    return tuple(int(x) for x in str(value).split('.')) + (0,) * (4 - len(str(value).split('.')))


def validate(ipa):
    with zipfile.ZipFile(ipa) as archive, tempfile.TemporaryDirectory() as folder:
        assert archive.testzip() is None, 'Corrupt IPA'
        names = archive.namelist()
        roots = {n.split('/')[1] for n in names if n.startswith('Payload/') and len(n.split('/')) > 1 and n.split('/')[1]}
        assert len(roots) == 1 and next(iter(roots)).endswith('.app'), 'Expected exactly one main app'
        root = 'Payload/' + next(iter(roots)) + '/'
        assert not any('/Watch/' in n or '/PlugIns/' in n or '.appex/' in n or '.app/' in n[len(root):] for n in names), 'Lite IPA contains an embedded app or extension'
        for n in names:
            assert not n.startswith('/') and '..' not in Path(n).parts, 'Unsafe archive member'
        archive.extractall(folder)
        app = Path(folder) / root
        info = plistlib.loads((app / 'Info.plist').read_bytes())
        assert info['CFBundleIdentifier'] == 'com.jccmon.jcccloud', 'Wrong main Bundle ID'
        assert info['CFBundleDisplayName'] == 'MeowFlare', 'Wrong display name'
        assert 'orangecloud' in [s for entry in info.get('CFBundleURLTypes', []) for s in entry.get('CFBundleURLSchemes', [])], 'Missing OAuth callback scheme'
        minimum = version(info['MinimumOSVersion'])
        main = app / info['CFBundleExecutable']
        assert main.is_file(), 'Missing main executable'
        binaries = [main]
        for framework in (app / 'Frameworks').glob('*.framework'):
            data = plistlib.loads((framework / 'Info.plist').read_bytes())
            assert version(data.get('MinimumOSVersion', info['MinimumOSVersion'])) <= minimum, f'{framework.name} requires a newer OS than the app'
            binary = framework / data['CFBundleExecutable']
            assert binary.is_file(), f'Missing executable: {framework.name}'
            binaries.append(binary)
        for binary in binaries:
            architectures = subprocess.check_output(['lipo', '-archs', str(binary)], text=True).split()
            assert 'arm64' in architectures, f'No arm64 device slice: {binary.name}'
            commands = subprocess.check_output(['otool', '-arch', 'arm64', '-l', str(binary)], text=True)
            builds = re.findall(r'cmd LC_BUILD_VERSION\s+cmdsize \d+\s+platform (\d+)\s+minos ([\d.]+)', commands)
            for platform, minos in builds:
                assert platform == '2', f'Not an iOS device binary: {binary.name}'
                assert version(minos) <= minimum, f'Mach-O minimum OS too high: {binary.name}: {minos}'
            for minos in re.findall(r'cmd LC_VERSION_MIN_IPHONEOS\s+cmdsize \d+\s+version ([\d.]+)', commands):
                assert version(minos) <= minimum, f'Mach-O minimum OS too high: {binary.name}'
            assert builds or 'LC_VERSION_MIN_IPHONEOS' in commands, f'Missing iOS deployment metadata: {binary.name}'
            dependencies = subprocess.check_output(['otool', '-arch', 'arm64', '-L', str(binary)], text=True)
            uses_system_swift = re.search(r'cmd LC_RPATH\s+cmdsize \d+\s+path /usr/lib/swift ', commands) is not None
            for line in dependencies.splitlines()[1:]:
                dependency = line.strip().split(' (', 1)[0]
                if dependency.startswith('@rpath/'):
                    relative = dependency[len('@rpath/'):]
                    # Apple Swift compatibility dylibs may resolve through the system rpath.
                    system_swift = uses_system_swift and re.fullmatch(r'libswift[A-Za-z0-9_]+\.dylib', relative)
                    assert system_swift or (app / 'Frameworks' / relative).is_file(), f'Missing runtime framework: {dependency}'
        return {k: info[k] for k in ['CFBundleIdentifier', 'CFBundleDisplayName', 'CFBundleShortVersionString', 'CFBundleVersion', 'MinimumOSVersion']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ipa', type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(args.ipa)))
