#!/usr/bin/env python3
"""通知通道模块 - 飞书/企微/邮件/Slack/Webhook"""

import os, sys, json, smtplib, email.utils
from email.mime.text import MIMEText
from typing import Dict, Any, List, Optional
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Notifier:
    """通知发送器 - 支持多通道模板渲染"""

    def __init__(self, channels_config: List[Dict] = None):
        self.channels = {}
        if channels_config:
            for cfg in channels_config:
                self.channels[cfg['name']] = cfg

    def add_channel(self, config: Dict):
        self.channels[config['name']] = config

    def send(self, event_type: str, template: Dict, context: Dict) -> List[Dict]:
        """发送通知到所有启用的通道"""
        results = []
        title = self._render(template.get('title_template', ''), context)
        body = self._render(template.get('body_template', ''), context)

        channel_names = json.loads(template.get('channels', '[]')) or list(self.channels.keys())

        for ch_name in channel_names:
            ch = self.channels.get(ch_name)
            if not ch or not ch.get('enabled', True):
                continue
            try:
                channel_type = ch['channel']
                config = json.loads(ch.get('config_json', '{}')) if isinstance(ch.get('config_json'), str) else ch.get('config_json', {})

                if channel_type == 'feishu':
                    result = self._send_feishu(config, title, body)
                elif channel_type == 'wechat_work':
                    result = self._send_wechat_work(config, title, body)
                elif channel_type == 'email':
                    result = self._send_email(config, title, body)
                elif channel_type == 'slack':
                    result = self._send_slack(config, title, body)
                elif channel_type == 'webhook':
                    result = self._send_webhook(config, body)
                elif channel_type == 'dingtalk':
                    result = self._send_dingtalk(config, title, body)
                else:
                    result = {'success': False, 'error': f'不支持的通道: {channel_type}'}
            except Exception as e:
                result = {'success': False, 'error': str(e)}

            results.append({
                'channel': ch_name,
                'type': channel_type,
                'event_type': event_type,
                'timestamp': datetime.now().isoformat(),
                **result
            })
        return results

    def test_channel(self, channel: Dict) -> Dict:
        """测试单个通道"""
        try:
            channel_type = channel.get('channel', '')
            config = channel.get('config_json', {})
            if isinstance(config, str):
                config = json.loads(config)
            title = f'[{channel_type}] 测试通知'
            body = f'这是一条来自 SOC Agent 的测试消息。发送时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
            if channel_type == 'feishu':
                return self._send_feishu(config, title, body)
            elif channel_type == 'email':
                return self._send_email(config, title, body)
            elif channel_type == 'webhook':
                return self._send_webhook(config, body)
            else:
                return {'success': False, 'error': f'通道类型 {channel_type} 暂不支持测试'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _render(self, template: str, context: Dict) -> str:
        """简单模板渲染（支持 {{ key.nested }}）"""
        import re
        def replacer(m):
            key = m.group(1).strip()
            try:
                val = context
                for k in key.split('.'):
                    if isinstance(val, dict):
                        val = val.get(k, '')
                    elif isinstance(val, list):
                        val = val[int(k)] if k.isdigit() else ''
                    else:
                        val = ''
                return str(val)
            except Exception:
                return ''
        return re.sub(r'\{\{(.+?)\}\}', replacer, template)

    def _send_feishu(self, config: Dict, title: str, body: str) -> Dict:
        """飞书机器人 Webhook"""
        webhook = config.get('webhook_url', '')
        if not webhook:
            return {'success': False, 'error': '飞书 Webhook URL 为空'}
        import requests
        payload = {
            'msg_type': 'post',
            'content': {
                'post': {
                    'zh_cn': {
                        'title': title,
                        'content': [[{'tag': 'text', 'text': body}]]}}}}
        r = requests.post(webhook, json=payload, timeout=10)
        return {'success': r.status_code == 200}

    def _send_wechat_work(self, config: Dict, title: str, body: str) -> Dict:
        """企业微信机器人"""
        webhook = config.get('webhook_url', '')
        if not webhook:
            return {'success': False, 'error': '企业微信 Webhook URL 为空'}
        import requests
        payload = {'msgtype': 'markdown', 'markdown': {'content': f'## {title}\n{body}'}}
        r = requests.post(webhook, json=payload, timeout=10)
        return {'success': r.status_code == 200}

    def _send_dingtalk(self, config: Dict, title: str, body: str) -> Dict:
        """钉钉机器人"""
        webhook = config.get('webhook_url', '')
        if not webhook:
            return {'success': False, 'error': '钉钉 Webhook URL 为空'}
        import requests
        payload = {'msgtype': 'text', 'text': {'content': f'{title}\n{body}'}}
        r = requests.post(webhook, json=payload, timeout=10)
        return {'success': r.status_code == 200}

    def _send_slack(self, config: Dict, title: str, body: str) -> Dict:
        """Slack Webhook"""
        webhook = config.get('webhook_url', '')
        if not webhook:
            return {'success': False, 'error': 'Slack Webhook URL 为空'}
        import requests
        payload = {'text': f'*{title}*\n{body}'}
        r = requests.post(webhook, json=payload, timeout=10)
        return {'success': r.status_code == 200}

    def _send_webhook(self, config: Dict, body: str) -> Dict:
        """通用 Webhook"""
        url = config.get('url', '')
        if not url:
            return {'success': False, 'error': 'Webhook URL 为空'}
        import requests
        headers = {'Content-Type': 'application/json'}
        r = requests.post(url, json={'text': body}, headers=headers, timeout=10)
        return {'success': r.status_code in (200, 201, 204)}

    def _send_email(self, config: Dict, title: str, body: str) -> Dict:
        """SMTP 邮件发送"""
        smtp_host = config.get('smtp_host', '')
        smtp_port = config.get('smtp_port', 587)
        smtp_user = config.get('smtp_user', '')
        smtp_pass = config.get('smtp_pass', '')
        from_addr = config.get('from_addr', smtp_user)
        to_addrs = config.get('to_addrs', '')

        if not all([smtp_host, smtp_user, smtp_pass, to_addrs]):
            return {'success': False, 'error': '邮件配置不完整'}
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = title
        msg['From'] = from_addr
        msg['To'] = to_addrs
        msg['Date'] = email.utils.formatdate()
        try:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(from_addr, to_addrs.split(','), msg.as_string())
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}


if __name__ == '__main__':
    n = Notifier()
    r = n._send_feishu({'webhook_url': ''}, 'Test', 'Body')
    print('Test (no webhook):', r)