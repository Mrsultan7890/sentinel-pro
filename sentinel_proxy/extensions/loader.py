# ============================================================================
# Sentinel Pro v3.1 — SentinelProxy Extension Loader
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

import importlib.util
import os
import traceback
from sentinel_proxy.extensions.base import SentinelExtension

EXTENSIONS_DIR = os.path.join(os.path.dirname(__file__))


class ExtensionManager:
    def __init__(self):
        self._extensions: list[SentinelExtension] = []

    # ── Loading ───────────────────────────────────────────────────────────────

    def load_all(self):
        """Scan extensions dir and load all .py files (except base/loader)."""
        skip = {'__init__.py', 'base.py', 'loader.py'}
        for fname in sorted(os.listdir(EXTENSIONS_DIR)):
            if fname.endswith('.py') and fname not in skip:
                self.load_file(os.path.join(EXTENSIONS_DIR, fname))

    def load_file(self, path: str) -> tuple[bool, str]:
        """Load a single extension file. Returns (success, message)."""
        try:
            spec   = importlib.util.spec_from_file_location('_ext_tmp', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for attr in dir(module):
                cls = getattr(module, attr)
                if (isinstance(cls, type)
                        and issubclass(cls, SentinelExtension)
                        and cls is not SentinelExtension):
                    # Avoid duplicate load
                    if any(type(e).__name__ == cls.__name__ for e in self._extensions):
                        return False, f'{cls.__name__} already loaded'
                    inst = cls()
                    inst._path = path
                    inst.on_load()
                    self._extensions.append(inst)
                    return True, f'Loaded: {inst.name}'
            return False, 'No SentinelExtension subclass found'
        except Exception:
            return False, traceback.format_exc()

    def unload(self, name: str) -> tuple[bool, str]:
        """Unload extension by name."""
        for ext in self._extensions:
            if ext.name == name:
                try:
                    ext.on_unload()
                except Exception:
                    pass
                self._extensions.remove(ext)
                return True, f'Unloaded: {name}'
        return False, f'Extension not found: {name}'

    def toggle(self, name: str) -> bool:
        """Toggle enabled state. Returns new state."""
        for ext in self._extensions:
            if ext.name == name:
                ext.enabled = not ext.enabled
                return ext.enabled
        return False

    # ── Hooks ─────────────────────────────────────────────────────────────────

    def run_request_hooks(self, flow: dict) -> dict:
        for ext in self._extensions:
            if ext.enabled:
                try:
                    flow = ext.on_request(flow) or flow
                except Exception:
                    pass
        return flow

    def run_response_hooks(self, flow: dict) -> dict:
        for ext in self._extensions:
            if ext.enabled:
                try:
                    flow = ext.on_response(flow) or flow
                except Exception:
                    pass
        return flow

    def run_intercept_hooks(self, flow: dict) -> dict:
        for ext in self._extensions:
            if ext.enabled:
                try:
                    flow = ext.on_intercept(flow) or flow
                except Exception:
                    pass
        return flow

    # ── Info ──────────────────────────────────────────────────────────────────

    def list_extensions(self) -> list[dict]:
        return [
            {
                'name':        e.name,
                'description': e.description,
                'version':     e.version,
                'author':      e.author,
                'enabled':     e.enabled,
                'path':        getattr(e, '_path', ''),
            }
            for e in self._extensions
        ]

    def __len__(self):
        return len(self._extensions)
