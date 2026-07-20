#!/usr/bin/env python3
"""
轻量级插件管理器
支持：数据源 / 通知通道 / Agent 三种插件类型
"""

import os
import sys
import json
import importlib.util
import inspect
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime


class PluginManager:
    """插件管理器 - 热加载 + 注册 + 生命周期"""

    def __init__(self, plugin_dirs: List[str] = None):
        self._plugins: Dict[str, Dict] = {}
        self._hooks: Dict[str, List[Callable]] = {}
        self._plugin_dirs = plugin_dirs or []
        # 默认插件目录
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._plugin_dirs.extend([
            os.path.join(project_root, 'core'),
            os.path.join(project_root, 'agents'),
        ])

    def discover(self) -> List[Dict]:
        """发现可用的插件"""
        discovered = []
        for pdir in self._plugin_dirs:
            if not os.path.exists(pdir):
                continue
            for f in sorted(os.listdir(pdir)):
                if not f.endswith('.py') or f.startswith('_'):
                    continue
                module_name = f[:-3]
                module_path = os.path.join(pdir, f)
                discovered.append({
                    'name': module_name,
                    'path': module_path,
                    'type': self._classify(module_name),
                })
        return discovered

    def register(self, name: str, plugin: Any, plugin_type: str = 'custom'):
        """注册一个插件实例"""
        self._plugins[name] = {
            'instance': plugin,
            'type': plugin_type,
            'registered_at': datetime.now().isoformat(),
            'metadata': self._extract_metadata(plugin),
        }
        return True

    def unregister(self, name: str) -> bool:
        """注销插件"""
        if name in self._plugins:
            del self._plugins[name]
            return True
        return False

    def get(self, name: str) -> Optional[Any]:
        """获取插件实例"""
        p = self._plugins.get(name)
        return p['instance'] if p else None

    def list(self, plugin_type: str = None) -> List[Dict]:
        """列出已注册的插件"""
        result = []
        for name, info in self._plugins.items():
            if plugin_type and info['type'] != plugin_type:
                continue
            result.append({
                'name': name,
                'type': info['type'],
                'registered_at': info['registered_at'],
                'metadata': {k: v for k, v in info['metadata'].items() if k != 'instance'},
            })
        return result

    def register_hook(self, event: str, callback: Callable):
        """注册事件钩子"""
        if event not in self._hooks:
            self._hooks[event] = []
        self._hooks[event].append(callback)

    def emit(self, event: str, **data):
        """触发事件"""
        for cb in self._hooks.get(event, []):
            try:
                cb(**data)
            except Exception as e:
                print(f'[Plugin] hook error {event}: {e}')

    def load_module(self, module_path: str) -> Optional[Any]:
        """从文件路径加载 Python 模块"""
        module_name = os.path.basename(module_path).replace('.py', '')
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if not spec or not spec.loader:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _classify(self, name: str) -> str:
        """根据文件名猜测插件类型"""
        keywords = {
            'source': ['source', 'datasource', 'splunk', 'elk', 'wazuh', 'syslog'],
            'agent': ['agent', 'triage', 'hunting', 'response', 'vuln'],
            'notification': ['notify', 'notification', 'feishu', 'email', 'slack', 'webhook'],
        }
        for ptype, kwlist in keywords.items():
            for kw in kwlist:
                if kw in name.lower():
                    return ptype
        return 'custom'

    def _extract_metadata(self, plugin: Any) -> Dict:
        """提取插件元数据"""
        meta = {
            'class': type(plugin).__name__,
            'module': type(plugin).__module__,
            'methods': [m for m in dir(plugin) if not m.startswith('_') and callable(getattr(plugin, m))],
        }
        if hasattr(plugin, 'name'):
            meta['name'] = plugin.name
        if hasattr(plugin, 'description'):
            meta['description'] = plugin.description
        return meta


# 全局单例
_global_plugin_manager = None


def get_plugin_manager() -> PluginManager:
    """获取全局插件管理器实例"""
    global _global_plugin_manager
    if _global_plugin_manager is None:
        _global_plugin_manager = PluginManager()
        # 自动注册内置插件
        _auto_register_builtins()
    return _global_plugin_manager


def _auto_register_builtins():
    """自动注册内置数据源和 Agent"""
    pm = _global_plugin_manager
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # 确保 core 和 agents 模块可导入
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    # 注册 Agent
    agent_map = {
        'triage_agent': ('AlertTriageAgent', 'agents'),
        'hunting_agent': ('ThreatHuntingAgent', 'agents'),
        'response_agent': ('ResponseAgent', 'agents'),
        'vuln_agent': ('VulnAssessmentAgent', 'agents'),
    }
    for mod_name, (cls_name, subdir) in agent_map.items():
        try:
            module_path = os.path.join(project_root, subdir, f'{mod_name}.py')
            spec = importlib.util.spec_from_file_location(mod_name, module_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                cls = getattr(module, cls_name, None)
                if cls:
                    instance = cls()
                    pm.register(instance.name, instance, 'agent')
        except Exception as e:
            print(f'[Plugin] register {mod_name} failed: {e}')


if __name__ == '__main__':
    pm = get_plugin_manager()
    print('已注册插件:')
    for p in pm.list():
        print(f'  [{p["type"]}] {p["name"]}')
    print(f'  发现模块: {len(pm.discover())} 个')
