"""Side-effect-free inspection of a device repository for offline inventories.

It runs the production profile merge, feed resolution and patch planning with
fetching disabled.  It never writes saved state, never reads a host build-input
file and never applies environment values; an inventory can therefore report
the effective target of the checked-out repositories independently of the
machine that happens to run it.
"""
from pathlib import Path
from types import SimpleNamespace

from .config import ROOT, load_toml
from .util import Error, expand, redact, sha256_file


def _arguments(os_name):
    return SimpleNamespace(command='inspect', os=os_name, local_module=None, local=None,
                           local_drivers=None, local_kits=None, local_patches=None,
                           local_scripts=None, local_package=None)


def _module(ctx, module, locked):
    from . import feeds
    source = module.source or {}
    return {'kind': module.kind, 'name': module.name, 'origin': module.origin,
            'local': module.local, 'path': str(module.path) if module.path else None,
            'revision': module.commit,
            'pin': None if module.local else (feeds.pinned_revision(ctx, module, locked)
                                              or getattr(module, 'spec', {}).get('revision')),
            'repository': source.get('git')}


def inspect(device, root=ROOT, out_root=None, os_name=None):
    """Resolve a device repository without fetching, writing or building.

    The result always has ``resolved``, ``errors``, ``selection``,
    ``profile_files``, ``modules``, ``patches`` and ``board`` keys.  A missing
    source cache or an unresolved component is reported in ``errors`` with
    ``resolved`` false; it is not an exception and does not stop an offline
    inventory.
    """
    device, root = expand(device), expand(root)
    out_root = expand(out_root or root / 'out')
    result = {'resolved': False, 'schema_version': None, 'errors': [], 'selection': None,
              'profile_files': [], 'modules': [], 'patches': [], 'board': None}
    try:
        raw_board = load_toml(device / 'board.toml')
        schema = raw_board.get('schema_version', 1)
        result['schema_version'] = schema
        ctx = SimpleNamespace(root=root, device=device, raw_board=raw_board, schema_version=schema,
                              args=_arguments(os_name), feeds_dir=out_root / 'feeds',
                              lock_path=device / 'unixnu.lock', profile_roots={'device': device},
                              profile_files=[device / 'board.toml'], board=raw_board, soc=None,
                              component_specs=[], modules={})
        if schema not in (1, 2):
            raise Error(f'unsupported schema_version: {schema}')
        if schema == 2:
            from . import profiles
            ctx.board = profiles.load(ctx, allow_fetch=False)
        name = ctx.board.get('board', {}).get('name')
        if not name:
            raise Error('board.toml needs [board] name')
        if Path(name).name != name or name in ('.', '..'):
            raise Error('[board] name must be a directory name')
        from . import feeds, patches
        modules = feeds.resolve(ctx)
        if ctx.soc is not None:
            modules[('soc', ctx.soc.name)] = ctx.soc
        locked = feeds.lock_read(ctx)
        if schema == 2:
            profile = ctx.os_name
            mapping = raw_board.get('package', {}).get('defconfig', {}).get(profile)
            config_name = mapping or ctx.board.get('kernel', {}).get('defconfig')
            if not config_name:
                raise Error('schema_version = 2 needs a mapped or [kernel] defconfig')
            selection = {'name': name, 'os_profile': profile, 'config': config_name,
                         'work': str(out_root / name / profile / config_name.removesuffix('_defconfig'))}
            order = patches.plan(ctx, modules)
            patches_list = [{'path': str(path), 'name': path.name, 'sha256': sha256_file(path)}
                            for path in order]
        else:
            selection = {'name': name, 'os_profile': raw_board.get('board', {}).get('os_profile'),
                         'config': None, 'work': str(out_root / name)}
            patches_list = []
        result.update({
            'resolved': True, 'selection': selection,
            'board': ctx.board,
            'profile_files': [{'path': str(path), 'sha256': sha256_file(path) if path.is_file() else None}
                              for path in ctx.profile_files],
            'modules': [_module(ctx, module, locked) for _, module in sorted(modules.items())],
            'patches': patches_list,
        })
    except Error as error:
        result['errors'].append(redact(str(error)))
    return result
