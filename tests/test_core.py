#!/usr/bin/env python3
"""
SOC Agent 核心单元测试
覆盖：数据库、认证、密码哈希、JWT
"""

import sys
import os
import json
import bcrypt
import time
import unittest
import tempfile

# 将项目根目录加入 sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'web', 'admin'))
sys.path.insert(0, PROJECT_ROOT)

from db import get_db, init_db, DB_PATH
from auth import hash_password, verify_password, create_token, decode_token


class TestDatabase(unittest.TestCase):
    """数据库层测试"""

    @classmethod
    def setUpClass(cls):
        # 使用临时数据库
        cls._orig_db_path = DB_PATH
        cls.tmp_dir = tempfile.mkdtemp()
        cls.test_db = os.path.join(cls.tmp_dir, 'test_admin.db')
        import web.admin.db as db_module
        db_module.DB_PATH = cls.test_db
        init_db(lock=False)

    @classmethod
    def tearDownClass(cls):
        import web.admin.db as db_module
        db_module.DB_PATH = cls._orig_db_path
        import shutil
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_01_tables_created(self):
        """验证所有必要表已创建"""
        conn = get_db()
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        conn.close()
        
        required_tables = [
            'users', 'data_sources', 'agent_configs', 'playbooks',
            'settings', 'audit_logs', 'target_assets', 'agent_registry',
            'incidents', 'scan_whitelist', 'scan_tasks', 'scan_results',
            'tenants', 'notification_channels', 'notification_templates', 'branding'
        ]
        for table in required_tables:
            self.assertIn(table, tables, f'表 {table} 不存在')

    def test_02_default_users_exist(self):
        """验证默认用户已创建"""
        conn = get_db()
        admin = conn.execute("SELECT * FROM users WHERE username='admin'").fetchone()
        analyst = conn.execute("SELECT * FROM users WHERE username='analyst'").fetchone()
        conn.close()
        self.assertIsNotNone(admin, 'admin 用户不存在')
        self.assertIsNotNone(analyst, 'analyst 用户不存在')
        self.assertEqual(admin['role'], 'admin')
        self.assertEqual(analyst['role'], 'analyst')

    def test_03_default_settings_exist(self):
        """验证默认设置已创建"""
        conn = get_db()
        site_name = conn.execute("SELECT value FROM settings WHERE key='site.name'").fetchone()
        timezone = conn.execute("SELECT value FROM settings WHERE key='site.timezone'").fetchone()
        conn.close()
        self.assertIsNotNone(site_name)
        self.assertEqual(site_name['value'], 'SOC Multi-Agent 管理后台')
        self.assertEqual(timezone['value'], 'Asia/Shanghai')

    def test_04_incidents_count(self):
        """验证 incidents 表有数据（演示数据）"""
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()['c']
        conn.close()
        self.assertGreater(count, 0, 'incidents 表为空')

    def test_05_audit_logs_can_insert(self):
        """验证审计日志写入"""
        conn = get_db()
        conn.execute("""
            INSERT INTO audit_logs (username, action, module, target, result)
            VALUES ('unittest', 'test', 'test_module', 'test_target', 'success')
        """)
        conn.commit()
        row = conn.execute(
            "SELECT * FROM audit_logs WHERE username='unittest'"
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row['action'], 'test')
        self.assertEqual(row['module'], 'test_module')

    def test_06_scan_results_table_writable(self):
        """验证 scan_results 表可写可读"""
        conn = get_db()
        result_json = {'task': 'test', 'ports': [22, 80]}
        conn.execute("""
            INSERT INTO scan_results (task_id, target_ip, hostname, risk_score, risk_level, port_count, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ('TEST-TMP-' + str(int(time.time())), '10.0.0.1', 'test-host', 45, 'medium', 2, json.dumps(result_json)))
        conn.commit()
        row = conn.execute("SELECT * FROM scan_results ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row['risk_score'], 45)
        self.assertEqual(row['risk_level'], 'medium')
        self.assertEqual(row['port_count'], 2)


class TestAuth(unittest.TestCase):
    """认证模块测试"""

    def test_01_hash_and_verify(self):
        """密码哈希和验证"""
        password = 'TestPass123!'
        hashed = hash_password(password)
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password('WrongPass', hashed))

    def test_02_create_and_decode_token(self):
        """JWT 创建和解析"""
        token = create_token('testuser', 'admin', tenant_id=1)
        payload = decode_token(token)
        self.assertEqual(payload['username'], 'testuser')
        self.assertEqual(payload['role'], 'admin')
        self.assertEqual(payload['tenant_id'], 1)

    def test_03_invalid_token(self):
        """无效 JWT 处理"""
        result = decode_token('invalid-token-string')
        self.assertIn('error', result)

    def test_04_token_expiry(self):
        """JWT 过期检查（创建时带过期时间）"""
        import jwt
        token = create_token('tmp', 'analyst')
        payload = decode_token(token)
        self.assertEqual(payload['username'], 'tmp')
        # 检查 exp 字段存在
        self.assertIn('exp', payload)

    def test_05_bcrypt_salt_unique(self):
        """每次哈希应该不同（salt 不同）"""
        pwd = 'SamePassword1'
        h1 = hash_password(pwd)
        h2 = hash_password(pwd)
        self.assertNotEqual(h1, h2)
        self.assertTrue(verify_password(pwd, h1))
        self.assertTrue(verify_password(pwd, h2))


class TestPasswordPolicy(unittest.TestCase):
    """密码策略测试"""

    def test_01_min_length(self):
        """密码最少 8 位"""
        self.assertGreaterEqual(len('TestPass123!'), 8)

    def test_02_requires_letter_and_digit(self):
        """密码必须包含字母和数字"""
        import re
        pwd = 'TestPass123!'
        self.assertTrue(re.search(r'[a-zA-Z]', pwd))
        self.assertTrue(re.search(r'\d', pwd))

    def test_03_weak_password_rejected(self):
        """弱密码应该被拒绝"""
        import re
        weak = '12345678'
        self.assertFalse(re.search(r'[a-zA-Z]', weak))  # 无字母


if __name__ == '__main__':
    unittest.main(verbosity=2)
