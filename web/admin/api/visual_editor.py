#!/usr/bin/env python3
"""
可视化编辑器 API
- 数据源: 字段表单 + 类型特定模板
- Playbook: 可视化步骤编辑 + 触发条件构建器
"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify
from auth import login_required, role_required, log_action
from db import get_db


def register(app):

    # ============ 数据源配置模板 ============

    @app.route('/api/admin/sources/templates')
    @login_required
    def source_templates():
        """返回所有数据源类型的配置模板"""
        return jsonify({
            'success': True,
            'templates': {
                'file': {
                    'name': '本地文件',
                    'icon': '📄',
                    'description': '从本地 JSON 文件读取告警',
                    'fields': [
                        {'key': 'path', 'label': '文件路径', 'type': 'text', 'required': True, 'placeholder': '/path/to/alerts.json'},
                        {'key': 'watch', 'label': '监听文件变化', 'type': 'boolean', 'default': False}
                    ]
                },
                'splunk': {
                    'name': 'Splunk',
                    'icon': '🟢',
                    'description': '从 Splunk Enterprise 拉取告警',
                    'fields': [
                        {'key': 'host', 'label': 'Splunk Host', 'type': 'text', 'required': True, 'placeholder': 'splunk.example.com'},
                        {'key': 'port', 'label': '端口', 'type': 'number', 'default': 8089},
                        {'key': 'token', 'label': 'API Token', 'type': 'password', 'required': True},
                        {'key': 'search_query', 'label': 'SPL 查询', 'type': 'textarea', 'default': 'index=security severity IN ("high","critical") earliest=-1h'},
                        {'key': 'verify_ssl', 'label': '验证 SSL', 'type': 'boolean', 'default': False}
                    ]
                },
                'elk': {
                    'name': 'Elasticsearch / ELK',
                    'icon': '🟡',
                    'description': '从 Elasticsearch 拉取告警',
                    'fields': [
                        {'key': 'host', 'label': 'ES Host', 'type': 'text', 'required': True},
                        {'key': 'port', 'label': '端口', 'type': 'number', 'default': 9200},
                        {'key': 'username', 'label': '用户名', 'type': 'text'},
                        {'key': 'password', 'label': '密码', 'type': 'password'},
                        {'key': 'index_pattern', 'label': '索引模式', 'type': 'text', 'default': 'alerts-*'},
                        {'key': 'time_field', 'label': '时间字段', 'type': 'text', 'default': '@timestamp'},
                        {'key': 'use_https', 'label': '使用 HTTPS', 'type': 'boolean', 'default': False}
                    ]
                },
                'wazuh': {
                    'name': 'Wazuh',
                    'icon': '🔵',
                    'description': '从 Wazuh Manager API 拉取告警',
                    'fields': [
                        {'key': 'host', 'label': 'Wazuh Host', 'type': 'text', 'required': True},
                        {'key': 'port', 'label': '端口', 'type': 'number', 'default': 55000},
                        {'key': 'username', 'label': '用户名', 'type': 'text', 'required': True, 'default': 'wazuh'},
                        {'key': 'password', 'label': '密码', 'type': 'password', 'required': True},
                        {'key': 'level_min', 'label': '最小告警级别', 'type': 'number', 'default': 7, 'min': 1, 'max': 15},
                        {'key': 'verify_ssl', 'label': '验证 SSL', 'type': 'boolean', 'default': False}
                    ]
                },
                'feishu': {
                    'name': '飞书 Webhook',
                    'icon': '🔷',
                    'description': '从飞书机器人接收告警',
                    'fields': [
                        {'key': 'app_id', 'label': 'App ID', 'type': 'text', 'required': True},
                        {'key': 'app_secret', 'label': 'App Secret', 'type': 'password', 'required': True},
                        {'key': 'encrypt_key', 'label': 'Encrypt Key', 'type': 'password'},
                        {'key': 'verification_token', 'label': 'Verification Token', 'type': 'password'}
                    ]
                },
                'syslog': {
                    'name': 'Syslog (UDP/TCP)',
                    'icon': '📡',
                    'description': '接收 Syslog 协议告警',
                    'fields': [
                        {'key': 'listen_host', 'label': '监听地址', 'type': 'text', 'default': '0.0.0.0'},
                        {'key': 'listen_port', 'label': '监听端口', 'type': 'number', 'required': True, 'default': 514},
                        {'key': 'protocol', 'label': '协议', 'type': 'select', 'options': ['UDP', 'TCP'], 'default': 'UDP'},
                        {'key': 'parser', 'label': '日志解析器', 'type': 'select', 'options': ['auto', 'json', 'cef', 'leef', 'raw'], 'default': 'auto'}
                    ]
                },
                'webhook': {
                    'name': 'HTTP Webhook',
                    'icon': '🔗',
                    'description': '接收 HTTP POST 告警',
                    'fields': [
                        {'key': 'path', 'label': 'URL 路径', 'type': 'text', 'default': '/api/webhook/alerts'},
                        {'key': 'auth_header', 'label': '鉴权 Header', 'type': 'text', 'placeholder': 'X-API-Key'},
                        {'key': 'secret', 'label': '共享密钥', 'type': 'password'}
                    ]
                },
                'aliyun_sas': {
                    'name': '阿里云 SAS',
                    'icon': '☁️',
                    'description': '从阿里云安全中心拉取告警',
                    'fields': [
                        {'key': 'access_key_id', 'label': 'Access Key ID', 'type': 'text', 'required': True},
                        {'key': 'access_key_secret', 'label': 'Access Key Secret', 'type': 'password', 'required': True},
                        {'key': 'region', 'label': '地域', 'type': 'select', 'options': ['cn-hangzhou', 'cn-beijing', 'cn-shanghai', 'cn-shenzhen'], 'default': 'cn-hangzhou'}
                    ]
                },
                'edr': {
                    'name': 'Osquery EDR',
                    'icon': '🖥️',
                    'description': '通过 Osquery 探针采集端点和事件',
                    'fields': [
                        {'key': 'host', 'label': 'EDR 服务地址', 'type': 'text', 'required': True, 'placeholder': 'soc-edr', 'default': 'soc-edr'},
                        {'key': 'port', 'label': '端口', 'type': 'number', 'default': 9000},
                        {'key': 'interval', 'label': '采集间隔(秒)', 'type': 'number', 'default': 300},
                        {'key': 'collect_process', 'label': '采集进程信息', 'type': 'boolean', 'default': True},
                        {'key': 'collect_network', 'label': '采集网络连接', 'type': 'boolean', 'default': True},
                        {'key': 'collect_crontab', 'label': '采集计划任务', 'type': 'boolean', 'default': False}
                    ]
                }
            }
        })

    # ============ Playbook 可视化编辑器 ============

    @app.route('/api/admin/playbooks/step-templates')
    @login_required
    def playbook_step_templates():
        """返回 Playbook 步骤模板（可视化编辑器用）"""
        return jsonify({
            'success': True,
            'templates': {
                'trigger': [
                    {
                        'type': 'alert_type',
                        'label': '告警类型匹配',
                        'icon': '🎯',
                        'fields': [
                            {'key': 'alert_type', 'label': '告警类型', 'type': 'select',
                             'options': ['brute_force_ssh', 'web_attack_sql_injection', 'privilege_escalation',
                                         'malware_detected', 'c2_communication', 'data_exfiltration',
                                         'ransomware_activity', 'lateral_movement']},
                            {'key': 'match_mode', 'label': '匹配模式', 'type': 'select', 'options': ['exact', 'regex', 'contains'], 'default': 'exact'}
                        ]
                    },
                    {
                        'type': 'severity',
                        'label': '严重级别',
                        'icon': '⚠️',
                        'fields': [
                            {'key': 'severity', 'label': '级别', 'type': 'multi-select',
                             'options': ['critical', 'high', 'medium', 'low']}
                        ]
                    },
                    {
                        'type': 'asset_criticality',
                        'label': '资产重要性',
                        'icon': '🏷️',
                        'fields': [
                            {'key': 'criticality', 'label': '重要性', 'type': 'multi-select',
                             'options': ['critical', 'high', 'medium', 'low']}
                        ]
                    }
                ],
                'action': [
                    {
                        'type': 'block_ip',
                        'label': '阻断 IP',
                        'icon': '🚫',
                        'category': 'containment',
                        'auto_safe': True,
                        'fields': [
                            {'key': 'target', 'label': '阻断对象', 'type': 'select',
                             'options': ['source_ip', 'dest_ip'], 'default': 'source_ip'},
                            {'key': 'duration_hours', 'label': '阻断时长 (小时)', 'type': 'number', 'default': 24},
                            {'key': 'firewall', 'label': '防火墙', 'type': 'select',
                             'options': ['iptables', 'cloudflare', 'aliyun_waf', 'tencent_waf']}
                        ]
                    },
                    {
                        'type': 'isolate_host',
                        'label': '隔离主机',
                        'icon': '🔒',
                        'category': 'containment',
                        'auto_safe': False,
                        'fields': [
                            {'key': 'edr', 'label': 'EDR 系统', 'type': 'select',
                             'options': ['qingteng', 'yaxin', 'symantec', 'crowdstrike']},
                            {'key': 'preserve_evidence', 'label': '保留取证', 'type': 'boolean', 'default': True}
                        ]
                    },
                    {
                        'type': 'disable_user',
                        'label': '禁用账号',
                        'icon': '👤',
                        'category': 'containment',
                        'auto_safe': False,
                        'fields': [
                            {'key': 'system', 'label': '账号系统', 'type': 'select',
                             'options': ['ad', 'ldap', 'okta', 'local']},
                            {'key': 'force_password_reset', 'label': '强制密码重置', 'type': 'boolean', 'default': True}
                        ]
                    },
                    {
                        'type': 'collect_evidence',
                        'label': '收集证据',
                        'icon': '📁',
                        'category': 'forensics',
                        'auto_safe': True,
                        'fields': [
                            {'key': 'evidence_types', 'label': '证据类型', 'type': 'multi-select',
                             'options': ['logs', 'memory_dump', 'disk_image', 'network_pcap', 'registry']}
                        ]
                    },
                    {
                        'type': 'notify',
                        'label': '发送通知',
                        'icon': '📢',
                        'category': 'communication',
                        'auto_safe': True,
                        'fields': [
                            {'key': 'channel', 'label': '通知通道', 'type': 'select',
                             'options': ['feishu', 'email', 'sms', 'webhook', 'phone']},
                            {'key': 'recipients', 'label': '接收人', 'type': 'text', 'placeholder': 'security-team, ciso@example.com'},
                            {'key': 'priority', 'label': '通知优先级', 'type': 'select',
                             'options': ['low', 'normal', 'high', 'urgent'], 'default': 'high'}
                        ]
                    },
                    {
                        'type': 'create_ticket',
                        'label': '创建工单',
                        'icon': '🎫',
                        'category': 'communication',
                        'auto_safe': True,
                        'fields': [
                            {'key': 'system', 'label': '工单系统', 'type': 'select',
                             'options': ['jira', 'redmine', 'zendesk', 'feishu_task']},
                            {'key': 'project', 'label': '项目', 'type': 'text'},
                            {'key': 'assignee', 'label': '负责人', 'type': 'text'}
                        ]
                    },
                    {
                        'type': 'siem_query',
                        'label': '执行 SIEM 查询',
                        'icon': '🔍',
                        'category': 'investigation',
                        'auto_safe': True,
                        'fields': [
                            {'key': 'siem', 'label': 'SIEM 系统', 'type': 'select',
                             'options': ['splunk', 'elk', 'wazuh', 'chronicle']},
                            {'key': 'query', 'label': '查询语句', 'type': 'textarea'}
                        ]
                    },
                    {
                        'type': 'patch_system',
                        'label': '应用补丁',
                        'icon': '🔧',
                        'category': 'eradication',
                        'auto_safe': False,
                        'fields': [
                            {'key': 'patch_type', 'label': '补丁类型', 'type': 'select',
                             'options': ['os', 'application', 'firmware', 'config_change']},
                            {'key': 'maintenance_window', 'label': '维护窗口', 'type': 'boolean', 'default': True}
                        ]
                    },
                    {
                        'type': 'backup_restore',
                        'label': '备份恢复',
                        'icon': '💾',
                        'category': 'recovery',
                        'auto_safe': False,
                        'fields': [
                            {'key': 'backup_source', 'label': '备份源', 'type': 'text'},
                            {'key': 'verify_integrity', 'label': '验证完整性', 'type': 'boolean', 'default': True}
                        ]
                    }
                ],
                'approval': [
                    {
                        'type': 'require_approval',
                        'label': '需要审批',
                        'icon': '✋',
                        'fields': [
                            {'key': 'approvers', 'label': '审批人', 'type': 'text', 'placeholder': 'security-manager'},
                            {'key': 'timeout_minutes', 'label': '超时时间 (分钟)', 'type': 'number', 'default': 30}
                        ]
                    }
                ]
            }
        })

    @app.route('/api/admin/playbooks/visual-create', methods=['POST'])
    @role_required('admin')
    def visual_create_playbook():
        """通过可视化定义创建 Playbook"""
        data = request.get_json()
        playbook_id = data.get('playbook_id', '').strip()
        name = data.get('name', '').strip()
        triggers = data.get('triggers', [])
        actions = data.get('actions', [])
        approvals = data.get('approvals', [])

        if not playbook_id or not name:
            return jsonify({'success': False, 'error': 'ID 和名称必填'}), 400

        # 拼接触发条件
        trigger_alert_type = ''
        trigger_severity = []
        for t in triggers:
            if t.get('type') == 'alert_type' and t.get('values', {}).get('alert_type'):
                trigger_alert_type = t['values']['alert_type']
            elif t.get('type') == 'severity':
                trigger_severity = t.get('values', {}).get('severity', [])

        # 生成 YAML
        description = data.get('description', '自动生成的预案')
        yaml_content = f"""---
id: {playbook_id}
name: {name}
description: {description}
trigger:
"""
        if trigger_alert_type:
            yaml_content += f"  alert_type: {trigger_alert_type}\n"
        if trigger_severity:
            yaml_content += f"  severity: {json.dumps(trigger_severity)}\n"

        yaml_content += "\nsteps:\n"
        for i, action in enumerate(actions, 1):
            yaml_content += f"  - step: {i}\n"
            yaml_content += f"    type: {action.get('type', 'unknown')}\n"
            yaml_content += f"    label: {action.get('label', '')}\n"
            yaml_content += f"    auto: {str(action.get('auto', True)).lower()}\n"
            if action.get('values'):
                yaml_content += "    config:\n"
                for k, v in action['values'].items():
                    yaml_content += f"      {k}: {json.dumps(v) if not isinstance(v, str) else v}\n"

        if approvals:
            yaml_content += "\napprovals:\n"
            for a in approvals:
                yaml_content += f"  - approver: {a.get('approvers', '')}\n"
                yaml_content += f"    timeout_minutes: {a.get('timeout_minutes', 30)}\n"

        # 保存到数据库
        try:
            conn = get_db()
            conn.execute("""
                INSERT INTO playbooks (playbook_id, name, description, yaml_content,
                                       trigger_alert_type, trigger_severity, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                playbook_id, name, data.get('description', ''), yaml_content,
                trigger_alert_type, json.dumps(trigger_severity),
                getattr(__import__('flask').request, 'username', 'system')
            ))
            conn.commit()
            conn.close()

            log_action('create', 'playbooks', playbook_id, f'可视化创建 Playbook: {name}')
            return jsonify({'success': True, 'yaml_content': yaml_content})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/admin/playbooks/preview-yaml', methods=['POST'])
    @login_required
    def preview_yaml():
        """预览 YAML（不保存数据库）"""
        data = request.get_json()
        playbook_id = data.get('playbook_id', '').strip()
        name = data.get('name', '').strip()
        triggers = data.get('triggers', [])
        actions = data.get('actions', [])
        approvals = data.get('approvals', [])

        # 拼接触发条件
        trigger_alert_type = ''
        trigger_severity = []
        for t in triggers:
            if t.get('type') == 'alert_type' and t.get('values', {}).get('alert_type'):
                trigger_alert_type = t['values']['alert_type']
            elif t.get('type') == 'severity':
                trigger_severity = t.get('values', {}).get('severity', [])

        # 生成 YAML
        description = data.get('description', '自动生成的预案')
        yaml_content = f"""---
id: {playbook_id}
name: {name}
description: {description}
trigger:
"""
        if trigger_alert_type:
            yaml_content += f"  alert_type: {trigger_alert_type}\n"
        if trigger_severity:
            yaml_content += f"  severity: {json.dumps(trigger_severity)}\n"

        yaml_content += "\nsteps:\n"
        for i, action in enumerate(actions, 1):
            yaml_content += f"  - step: {i}\n"
            yaml_content += f"    type: {action.get('type', 'unknown')}\n"
            yaml_content += f"    label: {action.get('label', '')}\n"
            yaml_content += f"    auto: {str(action.get('auto', True)).lower()}\n"
            if action.get('values'):
                yaml_content += "    config:\n"
                for k, v in action['values'].items():
                    yaml_content += f"      {k}: {json.dumps(v) if not isinstance(v, str) else v}\n"

        if approvals:
            yaml_content += "\napprovals:\n"
            for a in approvals:
                yaml_content += f"  - approver: {a.get('approvers', '')}\n"
                yaml_content += f"    timeout_minutes: {a.get('timeout_minutes', 30)}\n"

        return jsonify({'success': True, 'yaml_content': yaml_content})

    @app.route('/api/admin/playbooks/from-yaml', methods=['POST'])
    @role_required('admin')
    def from_yaml():
        """从 YAML 反向解析为可视化结构（用于编辑现有 Playbook）"""
        import yaml
        data = request.get_json()
        yaml_content = data.get('yaml_content', '')

        try:
            content = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            return jsonify({'success': False, 'error': f'YAML 解析失败: {e}'}), 400

        # 解析触发条件
        triggers = []
        trigger = content.get('trigger', {})
        if trigger.get('alert_type'):
            triggers.append({
                'type': 'alert_type',
                'label': '告警类型匹配',
                'icon': '🎯',
                'values': {'alert_type': trigger['alert_type'], 'match_mode': 'exact'}
            })
        if trigger.get('severity'):
            sev = trigger['severity']
            if isinstance(sev, str):
                sev = [sev]
            triggers.append({
                'type': 'severity',
                'label': '严重级别',
                'icon': '⚠️',
                'values': {'severity': sev}
            })

        # 解析步骤
        actions = []
        for step in content.get('steps', []):
            actions.append({
                'type': step.get('type'),
                'label': step.get('label', ''),
                'icon': _action_icon(step.get('type')),
                'auto': step.get('auto', True),
                'values': step.get('config', {})
            })

        # 解析审批
        approvals = []
        for a in content.get('approvals', []):
            approvals.append({
                'type': 'require_approval',
                'approvers': a.get('approver'),
                'timeout_minutes': a.get('timeout_minutes', 30)
            })

        return jsonify({
            'success': True,
            'visual': {
                'playbook_id': content.get('id', ''),
                'name': content.get('name', ''),
                'description': content.get('description', ''),
                'triggers': triggers,
                'actions': actions,
                'approvals': approvals
            }
        })


def _action_icon(action_type):
    icons = {
        'block_ip': '🚫',
        'isolate_host': '🔒',
        'disable_user': '👤',
        'collect_evidence': '📁',
        'notify': '📢',
        'create_ticket': '🎫',
        'siem_query': '🔍',
        'patch_system': '🔧',
        'backup_restore': '💾'
    }
    return icons.get(action_type, '⚡')