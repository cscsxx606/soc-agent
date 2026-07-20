#!/usr/bin/env python3
"""
SOC Agent core.notification 单元测试
覆盖: Notifier 模板渲染、空通道处理、错误捕获
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from core.notification import Notifier


class TestNotifier(unittest.TestCase):
    """通知发送器测试"""

    def test_init_empty(self):
        """无 channels_config 初始化不报错"""
        n = Notifier()
        self.assertEqual(n.channels, {})

    def test_init_with_channels(self):
        """channels_config 转字典"""
        cfg = [
            {'name': 'test_feishu', 'channel': 'feishu', 'config_json': '{}'},
            {'name': 'test_email', 'channel': 'email', 'config_json': '{}'},
        ]
        n = Notifier(channels_config=cfg)
        self.assertEqual(len(n.channels), 2)
        self.assertIn('test_feishu', n.channels)

    def test_add_channel(self):
        """add_channel 添加单个通道"""
        n = Notifier()
        n.add_channel({'name': 'foo', 'channel': 'webhook', 'config_json': '{}'})
        self.assertIn('foo', n.channels)

    def test_render_template(self):
        """模板支持 {{ key }} 和 {{ key.nested }}"""
        n = Notifier()
        ctx = {'name': 'foo', 'meta': {'host': 'h1', 'ip': '1.2.3.4'}}
        # 简单 key
        result = n._render('Hello {{ name }}', ctx)
        self.assertEqual(result, 'Hello foo')
        # 嵌套 key
        result2 = n._render('{{ meta.host }} from {{ meta.ip }}', ctx)
        self.assertEqual(result2, 'h1 from 1.2.3.4')
        # 不存在的 key 返回空字符串
        result3 = n._render('not found: {{ nope }}', ctx)
        self.assertEqual(result3, 'not found: ')

    def test_render_list_index(self):
        """{{ items.0 }} 取 list[0]"""
        n = Notifier()
        ctx = {'items': ['a', 'b', 'c']}
        result = n._render('first: {{ items.0 }}', ctx)
        self.assertEqual(result, 'first: a')

    def test_send_empty_channel(self):
        """send 无 enabled channel 不报错，返回空结果"""
        n = Notifier(channels_config=[])
        result = n.send(
            'test_event',
            {'channels': '[]', 'title_template': '', 'body_template': ''},
            {'name': 'x'}
        )
        self.assertEqual(result, [])

    def test_send_unknown_channel_type(self):
        """不支持的 channel type 返回 error in result"""
        n = Notifier(channels_config=[
            {'name': 'c1', 'channel': 'unknown_type_xxx', 'config_json': '{}', 'enabled': True}
        ])
        result = n.send(
            'evt',
            {'channels': '["c1"]', 'title_template': 'T', 'body_template': 'B'},
            {}
        )
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]['success'])
        self.assertIn('不支持', result[0]['error'])

    def test_send_feishu_success(self):
        """飞书 webhook 200 成功"""
        n = Notifier()
        # Patch 内部 send 逻辑 (mock 整个 post 调用)
        with patch('requests.post', return_value=MagicMock(status_code=200)) as mock_post:
            result = n._send_feishu(
                {'webhook_url': 'https://open.feishu.cn/hook/test'},
                'Test Title', 'Test Body'
            )
            self.assertTrue(result['success'])
            self.assertEqual(mock_post.call_args.kwargs['timeout'], 10)
            self.assertEqual(mock_post.call_args.kwargs['json']['msg_type'], 'post')
            self.assertIn('Test Title', str(mock_post.call_args.kwargs['json']))

    def test_send_feishu_failure(self):
        """飞书 webhook 500 失败"""
        n = Notifier()
        with patch('requests.post', return_value=MagicMock(status_code=500)):
            result = n._send_feishu(
                {'webhook_url': 'https://open.feishu.cn/hook/test'},
                'T', 'B'
            )
            self.assertFalse(result['success'])

    def test_send_feishu_no_webhook(self):
        """webhook URL 空 返回 error"""
        n = Notifier()
        result = n._send_feishu({}, 'T', 'B')
        self.assertFalse(result['success'])
        self.assertIn('Webhook URL 为空', result['error'])

    def test_send_email_no_smtp(self):
        """邮件 SMTP 空配置 返回 error（不会真发）"""
        n = Notifier()
        result = n._send_email({}, 'T', 'B')
        self.assertFalse(result['success'])


class TestNotifierPublicAPI(unittest.TestCase):
    """测试 send() 调度链路"""

    def test_send_with_disabled_channel(self):
        """enabled=False 的通道不发送"""
        n = Notifier(channels_config=[
            {'name': 'disabled_ch', 'channel': 'feishu', 'config_json': '{"webhook_url": "http://x"}', 'enabled': False}
        ])
        result = n.send(
            'evt',
            {'channels': '["disabled_ch"]', 'title_template': 'T', 'body_template': 'B'},
            {}
        )
        self.assertEqual(result, [])

    def test_send_handles_exception_in_channel(self):
        """send() 内部 try/except 不让单个通道的 error 中断主流程"""
        n = Notifier()
        n.add_channel({'name': 'broken', 'channel': 'feishu', 'config_json': '{"webhook_url": "http://127.0.0.1:1/no-path"}', 'enabled': True})
        with patch('requests.post', side_effect=Exception('network unreachable')):
            result = n.send(
                'evt',
                {'channels': '["broken"]', 'title_template': 'T', 'body_template': 'B'},
                {}
            )
        # 即使 broken 通道报错也返回 result 而不是 raise
        self.assertEqual(len(result), 1)
        self.assertIn('success', result[0])
        self.assertFalse(result[0]['success'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
