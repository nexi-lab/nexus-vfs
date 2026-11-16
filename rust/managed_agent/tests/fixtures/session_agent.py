"""Deterministic ACP peer for testing the real subprocess mailbox adapter."""
import json
import os
import time
import sys

pending = None
permission_id = 0
new_count = 0
load_count = 0


def emit(message):
    message['jsonrpc'] = '2.0'
    print(json.dumps(message), flush=True)


for line in sys.stdin:
    message = json.loads(line)
    method = message.get('method')
    if method == 'initialize':
        emit({'id': message['id'], 'result': {'protocolVersion': 1, 'agentCapabilities': {}, '_meta': {'nativePid': os.getpid()}}})
    elif method == 'session/new':
        new_count += 1
        emit({'id': message['id'], 'result': {'sessionId': 'durable-fixture-session'}})
    elif method == 'session/load':
        load_count += 1
        sid = message['params']['sessionId']
        if sid == 'durable-fixture-session':
            emit({'id': message['id'], 'result': {}})
        elif sid == 'wrong-load-result':
            emit({'id': message['id'], 'result': {'sessionId': 'different-transcript'}})
        else:
            emit({'id': message['id'], 'error': {'code': -32002, 'message': 'not found', 'data': {'sessionId': sid}}})
    elif method == 'test/counts':
        emit({'id': message['id'], 'result': {'new': new_count, 'load': load_count}})
    elif method == 'session/prompt':
        assert pending is None
        pending = message['id']
        emit({'method': 'session/update', 'params': {
            'sessionId': 'durable-fixture-session', 'update': {
                'sessionUpdate': 'agent_message_chunk', 'content': {'type': 'text', 'text': 'before approval'}}}})
        emit({'id': permission_id, 'method': 'session/request_permission', 'params': {
            'sessionId': 'durable-fixture-session', 'toolCall': {'toolCallId': 'edit', 'title': 'Edit file'},
            'options': [{'optionId': 'yes', 'kind': 'allow_once', 'name': 'Allow once'}]}})
    elif method == 'test/close_stdout':
        os.close(sys.stdout.fileno())
        time.sleep(60)
    elif method == 'session/cancel':
        if pending is not None:
            emit({'id': pending, 'result': {'stopReason': 'cancelled'}})
            pending = None
            permission_id += 1
    elif method is None and message.get('id') == permission_id and pending is not None:
        assert message['result']['outcome']['optionId'] == 'yes'
        emit({'method': 'session/update', 'params': {
            'sessionId': 'durable-fixture-session', 'update': {
                'sessionUpdate': 'tool_call_update', 'toolCallId': 'edit', 'status': 'completed'}}})
        emit({'id': pending, 'result': {'stopReason': 'end_turn'}})
        pending = None
        permission_id += 1
