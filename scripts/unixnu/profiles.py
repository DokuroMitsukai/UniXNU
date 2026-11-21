"""Layered ARM64, SoC, OS, and device configuration."""
from copy import deepcopy
from pathlib import Path

from .config import load_toml
from .util import Error


def merge(base, overlay):
    result = deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def resolve_os(ctx, wanted):
    """--os 17, 26 or 27 (the OS major version) or a full profiles/os directory name.
    A bare version resolves within the iPadOS profiles; prefix it with macos- (macos-27,
    macos-27.3) or ipados- (ipados-27) when several OS families ship the same major."""
    names = sorted(path.name for path in (ctx.root / 'profiles/os').iterdir() if path.is_dir())
    if wanted in names:
        return wanted
    family, version = 'ipados-', wanted
    for prefix in ('ipados-', 'macos-'):
        if wanted.startswith(prefix):
            family, version = prefix, wanted[len(prefix):]
            break
    matches = [name for name in names
               if name.startswith(f'{family}{version}.') or name.startswith(f'{family}{version}-')]
    if len(matches) != 1:
        raise Error(f'--os {wanted}: expected one of {", ".join(names)} or 17, 26, 27, macos-27')
    return matches[0]


def load(ctx, allow_fetch=False):
    from . import feeds
    board = ctx.raw_board.get('board', {})
    soc_name, os_name = board.get('soc_source'), board.get('os_profile')
    if getattr(ctx.args, 'os', None):
        os_name = resolve_os(ctx, ctx.args.os)
    if not soc_name or not os_name:
        raise Error('schema_version = 2 requires [board] soc_source and os_profile')
    if Path(os_name).name != os_name or os_name in ('.', '..'):
        raise Error('[board] os_profile must be a profile directory name')
    os_root = ctx.root / 'profiles/os' / os_name
    if not (os_root / 'profile.toml').is_file():
        raise Error(f'{os_name}: OS profile is not installed under profiles/os')
    # [package.defconfig] is the board's packaging contract: a requested full profile must be one of its keys.
    # Validate it before resolving the SoC so a wrong target cannot fetch sources or reach a build step.
    packaged = ctx.raw_board.get('package', {}).get('defconfig', {})
    if packaged:
        if os_name not in packaged:
            raise Error(f'{os_name}: [package.defconfig] lists {", ".join(sorted(packaged))}; '
                        'this board does not package that OS profile')
        selected = packaged[os_name]
        if not isinstance(selected, str) or Path(selected).name != selected or selected in ('.', '..'):
            raise Error(f'[package.defconfig] {os_name} must name a defconfig in the device configs directory')
        if not (ctx.device / 'configs' / selected).is_file():
            raise Error(f'[package.defconfig] {os_name}: configs/{selected} is missing')
    ctx.soc = feeds.resolve_soc(ctx, soc_name, allow_fetch)
    os_toml = load_toml(os_root / 'profile.toml')
    arch_name = os_toml.get('os', {}).get('arch', 'arm64')
    if arch_name not in ('arm64', 'arm64e'):
        raise Error(f'{os_name}: [os] arch must be arm64 or arm64e')
    declared = os_toml.get('os', {}).get('name')
    if declared and declared != os_name:
        raise Error(f'{os_name}: [os] name is {declared}, not the profile directory name')
    ctx.os_name = os_name
    ctx.profile_roots = {'arch': ctx.root / 'profiles/arch' / arch_name, 'soc': ctx.soc.path,
                         'os': os_root, 'device': ctx.device}
    ctx.profile_files = [ctx.profile_roots['arch'] / 'profile.toml', ctx.soc.path / 'soc.toml',
                         os_root / 'profile.toml', ctx.device / 'board.toml']
    result = {}
    for path in ctx.profile_files:
        result = merge(result, load_toml(path))
    # board.toml [os_overrides."<profile>"] holds the board values that differ for one OS profile (kernel archives, kernel
    # arguments); the table of the selected profile is merged over the board, the others are dropped.
    overrides = result.pop('os_overrides', {})
    chosen = deepcopy(overrides.get(os_name, {}))
    removed = chosen.pop('remove', [])
    result = merge(result, chosen)
    for dotted in removed:   # keys the board sets for other profiles and this one does not have
        *parents, leaf = dotted.split('.')
        node = result
        for key in parents:
            node = node.get(key, {})
        node.pop(leaf, None)
    # The package contract and the resolved profile identity cannot be changed by a per-OS override.
    if 'package' in ctx.raw_board:
        result['package'] = deepcopy(ctx.raw_board['package'])
    result.setdefault('board', {})['os_profile'] = os_name
    resolved_arch = result.get('os', {}).get('arch', 'arm64')
    if resolved_arch not in ('arm64', 'arm64e'):
        raise Error(f'{os_name}: resolved [os] arch is {resolved_arch}; expected arm64 or arm64e')
    resolved_name = result.get('os', {}).get('name')
    if resolved_name and resolved_name != os_name:
        raise Error(f'{os_name}: resolved [os] name is {resolved_name}, not the profile directory name')
    return result


def resolve_path(ctx, value, modules=None):
    """Resolve profile-prefixed paths and component:ID/path references."""
    if value.startswith('component:'):
        identifier, sep, relative = value[len('component:'):].partition('/')
        if not sep:
            raise Error(f'component path needs ID/path: {value}')
        modules = modules if modules is not None else getattr(ctx, 'modules', {})
        module = next((m for m in modules.values() if m.name == identifier), None)
        if not module or module.path is None:
            raise Error(f'component source unavailable: {identifier}; run unixnu fetch')
        return module.path / relative
    prefix, separator, relative = value.partition(':')
    if separator and prefix in ctx.profile_roots:
        return ctx.profile_roots[prefix] / relative
    path = Path(value)
    return path if path.is_absolute() else ctx.device / path
