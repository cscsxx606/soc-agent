#!/usr/bin/env python3
"""任务管线系统 API - 管线管理 + 执行"""

import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify
from auth import login_required, role_required, log_action


# 管线注册表
PIPELINE_REGISTRY = {}

def _load_pipelines():
    """加载管线定义到注册表"""
    from core.task_pipeline import TaskPipeline
    pipe = TaskPipeline()
    for attr in dir(pipe):
        if attr.startswith('PIPELINE_'):
            name = attr.replace('PIPELINE_', '').lower()
            pipeline_def = getattr(pipe, attr)
            PIPELINE_REGISTRY[name] = {
                'id': name,
                'name': pipeline_def.get('name', name),
                'steps': len(pipeline_def.get('steps', [])),
                'steps_detail': pipeline_def.get('steps', []),
                'parallel_supported': True
            }


def register(app):
    _load_pipelines()

    @app.route('/api/admin/pipelines/list')
    @login_required
    def pipelines_list():
        return jsonify({
            'success': True,
            'pipelines': [
                {k: v for k, v in p.items() if k != 'steps_detail'}
                for p in PIPELINE_REGISTRY.values()
            ]
        })

    @app.route('/api/admin/pipelines/get/<pipeline_id>')
    @login_required
    def pipelines_get(pipeline_id):
        pipeline = PIPELINE_REGISTRY.get(pipeline_id)
        if not pipeline:
            return jsonify({'success': False, 'error': '管线不存在'}), 404
        return jsonify({'success': True, 'pipeline': pipeline})

    @app.route('/api/admin/pipelines/test/<pipeline_id>', methods=['POST'])
    @login_required
    def pipelines_test(pipeline_id):
        """测试运行管线"""
        pipeline = PIPELINE_REGISTRY.get(pipeline_id)
        if not pipeline:
            return jsonify({'success': False, 'error': '管线不存在'}), 404

        data = request.get_json() or {}
        input_data = data.get('input_data', '测试输入数据')
        use_parallel = data.get('use_parallel', False)

        try:
            from core.llm_client import DeepSeekClient
            from core.task_pipeline import TaskPipeline

            llm = DeepSeekClient()
            pipe = TaskPipeline(llm)

            if use_parallel:
                result = pipe.run_parallel(pipeline_id, input_data)
            else:
                result = pipe.run(pipeline_id, input_data)

            result['pipeline_name'] = pipeline['name']
            return jsonify({'success': True, 'result': result})

        except ImportError as e:
            return jsonify({'success': False, 'error': f'LLM 客户端加载失败: {e}', 'fallback': True, 'pipeline_name': pipeline['name']}), 500
        except Exception as e:
            import traceback
            return jsonify({'success': False, 'error': str(e), 'trace': traceback.format_exc()[:300], 'pipeline_name': pipeline['name']}), 500

    @app.route('/api/admin/pipelines/execute', methods=['POST'])
    @role_required('admin', 'analyst')
    def pipelines_execute():
        """执行管线（供 Agent 集成调用）"""
        data = request.get_json() or {}
        pipeline_id = data.get('pipeline_id', '').strip()
        input_data = data.get('input_data', '')
        context = data.get('context', {})
        use_parallel = data.get('use_parallel', False)

        if not pipeline_id or not input_data:
            return jsonify({'success': False, 'error': 'pipeline_id 和 input_data 必填'}), 400

        from core.llm_client import DeepSeekClient
        from core.task_pipeline import TaskPipeline

        try:
            llm = DeepSeekClient()
            pipe = TaskPipeline(llm)
            if use_parallel:
                result = pipe.run_parallel(pipeline_id, input_data, context)
            else:
                result = pipe.run(pipeline_id, input_data, context)
            log_action(request, 'execute', 'pipeline', pipeline_id,
                       f'管线 {pipeline_id}: {result.get("duration_seconds", 0)}s')
            return jsonify({'success': True, 'result': result})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500