#!/usr/bin/env python3
"""
SOC Agent API 单元测试
覆盖：API 登录、鉴权、CRUD 接口
"""

import sys
import os
import json
import tempfile
import time
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'web', 'admin'))
sys.path.insert(0, PROJECT_ROOT)


class TestAPI(unittest.TestCase):
    """API 接口测试"""

    @classmethod
    def setUpClass(cls):
        # 使用临时数据库
        import web.admin.db as db_module
        cls._orig_db_path = db_module.DB_PATH
        cls.tmp_dir = tempfile.mkdtemp()
        cls.test_db = os.path.join(cls.tmp_dir, 'test_api.db')
        db_module.DB_PATH = cls.test_db
        db_module.init_db(lock=False)

        # 创建测试 app
        from app import app
        cls.app = app.test_client()
        # 注入 session
        with cls.app.session_transaction() as sess:
            sess['username'] = 'admin'
            sess['role'] = 'admin'

    @classmethod
    def tearDownClass(cls):
        import web.admin.db as db_module
        db_module.DB_PATH = cls._orig_db_path
        import shutil
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def set_auth(self):
        with self.app.session_transaction() as sess:
            sess['username'] = 'admin'
            sess['role'] = 'admin'

    # ====== 健康检查 ======

    def test_01_health(self):
        r = self.app.get('/health')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data['status'], 'ok')
        self.assertEqual(data['db'], 'ok')

    def test_02_api_version(self):
        r = self.app.get('/api/version')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn('version', data)
        self.assertEqual(data['agent'], 'SOC Multi-Agent System')

    # ====== 认证 ======

    def test_10_login_success(self):
        r = self.app.post('/api/auth/login', json={
            'username': 'admin', 'password': 'admin123'
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('token', data)

    def test_11_login_wrong_password(self):
        r = self.app.post('/api/auth/login', json={
            'username': 'admin', 'password': 'wrong'
        })
        self.assertEqual(r.status_code, 401)
        data = r.get_json()
        self.assertFalse(data['success'])

    def test_12_login_no_password(self):
        r = self.app.post('/api/auth/login', json={'username': 'admin'})
        self.assertEqual(r.status_code, 400)

    def test_13_unauthorized_access(self):
        with self.app.session_transaction() as sess:
            sess.clear()
        r = self.app.get('/api/admin/stats')
        self.assertEqual(r.status_code, 401)

    # ====== 仪表盘 ======

    def test_20_dashboard_stats(self):
        self.set_auth()
        r = self.app.get('/api/admin/stats')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])

    def test_21_dashboard_charts(self):
        self.set_auth()
        r = self.app.get('/api/admin/dashboard/charts')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('charts', data)

    # ====== Incidents ======

    def test_30_incidents_list(self):
        self.set_auth()
        r = self.app.get('/api/admin/incidents/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('incidents', data)
        self.assertIn('stats', data)

    def test_31_incidents_filter_by_priority(self):
        self.set_auth()
        r = self.app.get('/api/admin/incidents/list?priority=P1')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        for inc in data['incidents']:
            self.assertEqual(inc['priority'], 'P1')

    def test_32_incidents_search_by_alert_type(self):
        """search 参数应过滤 alert_type LIKE 字段"""
        self.set_auth()
        from db import get_db
        import time
        unique_type = 'search_test_type_' + str(int(time.time()))
        with get_db() as conn:
            conn.execute("""
                INSERT INTO incidents (alert_id, timestamp, source_ip, alert_type, severity, priority, risk_score, hostname, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f'TEST-{int(time.time())}', '2026-07-20T10:00:00Z', '203.0.113.99',
                unique_type, 'high', 'P1', 80, 'search-test-host', 'desc'
            ))
            conn.commit()

        r = self.app.get(f'/api/admin/incidents/list?search=search_test_type')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        # at least our inserted row matches
        found = [inc for inc in data['incidents'] if inc['alert_type'] == unique_type]
        self.assertGreater(len(found), 0, f"search did not match {unique_type}")

    def test_33_incidents_search_by_ip(self):
        """search 参数应过滤 source_ip LIKE 字段"""
        self.set_auth()
        from db import get_db
        import time
        unique_ip = '203.0.113.' + str((int(time.time()) % 200) + 50)
        with get_db() as conn:
            conn.execute("""
                INSERT INTO incidents (alert_id, timestamp, source_ip, alert_type, severity, priority, risk_score, hostname, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f'TEST-{int(time.time())}-{unique_ip}', '2026-07-20T10:00:00Z', unique_ip,
                'ssh_brute_force', 'medium', 'P2', 60, 'ip-search-host', 'desc'
            ))
            conn.commit()

        r = self.app.get(f'/api/admin/incidents/list?search={unique_ip}')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        found = [inc for inc in data['incidents'] if inc['source_ip'] == unique_ip]
        self.assertGreater(len(found), 0, f"search did not match IP {unique_ip}")

    def test_34_incidents_export(self):
        self.set_auth()
        r = self.app.post('/api/admin/incidents/export', json={})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertGreater(data['count'], 0)

    # ====== 用户管理 ======

    def test_40_users_list(self):
        self.set_auth()
        r = self.app.get('/api/admin/users/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        users = data['users']
        usernames = [u['username'] for u in users]
        self.assertIn('admin', usernames)
        self.assertIn('analyst', usernames)

    def test_41_create_user(self):
        self.set_auth()
        r = self.app.post('/api/admin/users/create', json={
            'username': 'test_user_' + str(int(time.time())), 'password': 'TestPass123',
            'email': 'test@test.com', 'full_name': 'Test User', 'role': 'analyst'
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])

    def test_42_create_user_weak_password(self):
        self.set_auth()
        r = self.app.post('/api/admin/users/create', json={
            'username': 'weak', 'password': '12345', 'role': 'analyst'
        })
        self.assertEqual(r.status_code, 400)

    # ====== Playbooks ======

    def test_45_playbooks_list(self):
        self.set_auth()
        r = self.app.get('/api/admin/playbooks/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])

    # ====== 数据源 ======

    def test_50_sources_list(self):
        self.set_auth()
        r = self.app.get('/api/admin/sources/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])

    def test_51_sources_templates(self):
        self.set_auth()
        r = self.app.get('/api/admin/sources/templates')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn('templates', data)

    # ====== 目标 (Targets) ======

    def test_55_assets_list(self):
        self.set_auth()
        r = self.app.get('/api/admin/targets/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('assets', data)

    # ====== 设置 ======

    def test_60_settings_list(self):
        self.set_auth()
        r = self.app.get('/api/admin/settings/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('settings', data)

    # ====== 代理 (Agent Registry) ======

    def test_65_agents_registry(self):
        self.set_auth()
        r = self.app.get('/api/admin/agents/registry/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertGreater(data['total'], 0)

    def test_66_agents_registry_categories(self):
        self.set_auth()
        r = self.app.get('/api/admin/agents/registry/categories')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn('categories', data)

    def test_67_agents_registry_stats(self):
        self.set_auth()
        r = self.app.get('/api/admin/agents/registry/stats')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('stats', data)

    # ====== 白名单 ======

    def test_70_whitelist_list(self):
        self.set_auth()
        r = self.app.get('/api/admin/scans/whitelist/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('whitelist', data)

    # ====== 扫描 ======

    def test_75_scans_stats(self):
        self.set_auth()
        r = self.app.get('/api/admin/scans/stats')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('stats', data)

    def test_76_tools_status(self):
        self.set_auth()
        r = self.app.get('/api/admin/scans/tools')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('tools', data)

    # ====== 审计日志 ======

    def test_80_audit_list(self):
        self.set_auth()
        r = self.app.get('/api/admin/audit/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('logs', data)

    # ====== 租户 ======

    def test_85_tenants_list(self):
        self.set_auth()
        r = self.app.get('/api/admin/tenants/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('tenants', data)

    # ====== 品牌 ======

    def test_90_branding_get(self):
        self.set_auth()
        r = self.app.get('/api/admin/branding/get')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('branding', data)

    # ====== 通知 ======

    def test_95_notification_channels(self):
        self.set_auth()
        r = self.app.get('/api/admin/notifications/channels')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])

    def test_96_notification_templates(self):
        self.set_auth()
        r = self.app.get('/api/admin/notifications/templates')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])

    # ====== 管线 ======

    def test_97_pipelines_list(self):
        self.set_auth()
        r = self.app.get('/api/admin/pipelines/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('pipelines', data)


# ====== RBAC 权限测试 ======

class TestRBAC(unittest.TestCase):
    """RBAC 权限控制测试"""

    @classmethod
    def setUpClass(cls):
        import web.admin.db as db_module
        cls._orig_db_path = db_module.DB_PATH
        cls.tmp_dir = tempfile.mkdtemp()
        cls.test_db = os.path.join(cls.tmp_dir, 'test_rbac.db')
        db_module.DB_PATH = cls.test_db
        db_module.init_db(lock=False)
        from app import app
        cls.app = app.test_client()

    @classmethod
    def tearDownClass(cls):
        import web.admin.db as db_module
        db_module.DB_PATH = cls._orig_db_path
        import shutil
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_01_analyst_cannot_access_users(self):
        """analyst 不能访问用户管理"""
        with self.app.session_transaction() as sess:
            sess['username'] = 'analyst'
            sess['role'] = 'analyst'
        r = self.app.get('/api/admin/users/list')
        self.assertEqual(r.status_code, 403)

    def test_02_admin_can_access_users(self):
        """admin 可以访问用户管理"""
        with self.app.session_transaction() as sess:
            sess['username'] = 'admin'
            sess['role'] = 'admin'
        r = self.app.get('/api/admin/users/list')
        self.assertEqual(r.status_code, 200)

    def test_03_analyst_cannot_create_user(self):
        """analyst 不能创建用户"""
        with self.app.session_transaction() as sess:
            sess['username'] = 'analyst'
            sess['role'] = 'analyst'
        r = self.app.post('/api/admin/users/create', json={
            'username': 'hacker', 'password': 'Hack1234', 'role': 'analyst'
        })
        self.assertEqual(r.status_code, 403)

    def test_04_analyst_can_access_dashboard(self):
        """analyst 可以访问仪表盘"""
        with self.app.session_transaction() as sess:
            sess['username'] = 'analyst'
            sess['role'] = 'analyst'
        r = self.app.get('/api/admin/dashboard/charts')
        self.assertEqual(r.status_code, 200)

    def test_05_viewer_cannot_access_users(self):
        """viewer 不能访问用户管理"""
        with self.app.session_transaction() as sess:
            sess['username'] = 'viewer_user'
            sess['role'] = 'viewer'
        r = self.app.get('/api/admin/users/list')
        self.assertEqual(r.status_code, 403)

    def test_06_viewer_cannot_access_audit(self):
        """viewer 不能访问审计日志"""
        with self.app.session_transaction() as sess:
            sess['username'] = 'viewer_user'
            sess['role'] = 'viewer'
        r = self.app.get('/api/admin/audit/list')
        self.assertEqual(r.status_code, 403)

    def test_07_viewer_can_access_dashboard(self):
        """viewer 可以访问仪表盘"""
        with self.app.session_transaction() as sess:
            sess['username'] = 'viewer_user'
            sess['role'] = 'viewer'
        r = self.app.get('/api/admin/stats')
        self.assertEqual(r.status_code, 200)


class TestAgents(unittest.TestCase):
    """Agent 模块测试"""

    @classmethod
    def setUpClass(cls):
        import web.admin.db as db_module
        cls._orig_db_path = db_module.DB_PATH
        cls.tmp_dir = tempfile.mkdtemp()
        cls.test_db = os.path.join(cls.tmp_dir, 'test_agents.db')
        db_module.DB_PATH = cls.test_db
        db_module.init_db(lock=False)
        from app import app
        cls.app = app.test_client()
        with cls.app.session_transaction() as sess:
            sess['username'] = 'admin'
            sess['role'] = 'admin'

    @classmethod
    def tearDownClass(cls):
        import web.admin.db as db_module
        db_module.DB_PATH = cls._orig_db_path
        import shutil
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_01_agent_configs_list(self):
        r = self.app.get('/api/admin/agents/list')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertIn('agents', data)

    def test_02_agent_config_update(self):
        r = self.app.post('/api/admin/agents/update/triage', json={
            'config': {
                'risk_thresholds': {'P1': 85, 'P2': 65, 'P3': 40, 'P4': 0},
                'enable_ai_analysis': True
            }
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])

    def test_03_agent_config_reset(self):
        r = self.app.post('/api/admin/agents/reset/triage')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])


class TestScanWhitelist(unittest.TestCase):
    """扫描白名单测试"""

    @classmethod
    def setUpClass(cls):
        import web.admin.db as db_module
        cls._orig_db_path = db_module.DB_PATH
        cls.tmp_dir = tempfile.mkdtemp()
        cls.test_db = os.path.join(cls.tmp_dir, 'test_scan.db')
        db_module.DB_PATH = cls.test_db
        db_module.init_db(lock=False)
        from app import app
        cls.app = app.test_client()
        with cls.app.session_transaction() as sess:
            sess['username'] = 'admin'
            sess['role'] = 'admin'

    def _set_auth(self):
        """每个测试前重新注入 session（test_client 每次都新建）"""
        with self.app.session_transaction() as sess:
            sess['username'] = 'admin'
            sess['role'] = 'admin'

    @classmethod
    def tearDownClass(cls):
        import web.admin.db as db_module
        db_module.DB_PATH = cls._orig_db_path
        import shutil
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def setUp(self):
        """每个测试前清理冲突的 scan_whitelist 行（避免与跨隔离在数据序中的污染）。"""
        from db import get_db
        with get_db() as conn:
            conn.execute("DELETE FROM scan_whitelist WHERE ip_or_cidr IN ('198.51.100.0/24', '10.255.255.0/24', '172.31.255.0/24')")
            conn.commit()

    def test_01_whitelist_add(self):
        r = self.app.post('/api/admin/scans/whitelist/add', json={
            'ip_or_cidr': '198.51.100.0/24',
            'label': '办公网段',
            'scope': 'internal'
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])

    def test_02_whitelist_check_authorized(self):
        # 先添加
        self.app.post('/api/admin/scans/whitelist/add', json={
            'ip_or_cidr': '10.255.255.0/24',
            'label': '测试段',
            'scope': 'internal'
        })
        r = self.app.post('/api/admin/scans/check-auth', json={'ip': '10.255.255.1'})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertTrue(data['authorized'])

    def test_03_whitelist_check_unauthorized(self):
        r = self.app.post('/api/admin/scans/check-auth', json={'ip': '1.2.3.4'})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertFalse(data['authorized'])

    def test_04_whitelist_delete(self):
        # 先添加
        r1 = self.app.post('/api/admin/scans/whitelist/add', json={
            'ip_or_cidr': '172.31.255.0/24',
            'label': '测试段',
            'scope': 'internal'
        })
        self.assertEqual(r1.status_code, 200)
        # 获取列表找到 id
        r2 = self.app.get('/api/admin/scans/whitelist/list')
        data = r2.get_json()
        for w in data['whitelist']:
            if w['ip_or_cidr'] == '172.31.255.0/24':
                r3 = self.app.post(f'/api/admin/scans/whitelist/delete/{w["id"]}')
                self.assertEqual(r3.status_code, 200)
                return
        self.fail('未找到测试白名单')


if __name__ == '__main__':
    unittest.main(verbosity=2)
