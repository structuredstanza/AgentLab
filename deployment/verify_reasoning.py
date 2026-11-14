#!/usr/bin/env python3
"""Run a real local-model tool task and validate its exported reasoning and outcome."""
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('agentlab', str(ROOT / 'lab'))
spec = importlib.util.spec_from_loader(loader.name, loader)
lab = importlib.util.module_from_spec(spec)
loader.exec_module(lab)


def jsonl(path):
    with path.open() as stream:
        return [json.loads(line) for line in stream if line.strip()]


def main():
    if not __debug__:
        raise SystemExit('refusing to run with asserts disabled (python -O); the checks are asserts')
    token = lab.login()
    active = next(p for p in lab.api('/api/llm/profiles', token=token)['profiles'] if p['is_default'])
    if active.get('base_url') != lab.PRIMARY_URL or active.get('name') != lab.PRIMARY_NAME:
        raise RuntimeError('Refusing model smoke: the active profile is not the local open-weight primary')
    settings = lab.api('/api/settings', token=token)
    if not all(settings.get(k) for k in ('llm_record', 'traffic_capture', 'agent_traffic_binding')):
        raise RuntimeError('Refusing model smoke without complete capture enabled')
    if settings.get('llm_pool_enabled'):
        raise RuntimeError('Refusing model smoke with provider failover enabled')
    agent = next(a for a in lab.api('/api/agents', token=token)['agents'] if a['key'] == 'auto')
    if agent.get('llm_profile_id') is not None and str(agent['llm_profile_id']) != str(active['id']):
        raise RuntimeError('Refusing model smoke: auto agent is bound to another provider')
    lab.primary_runtime()
    nonce = uuid.uuid4().hex
    conversation = lab.api('/api/conversations', {'agent_key': 'auto', 'title': 'Local reasoning smoke ' + nonce,
        'llm_profile_id': int(active['id'])}, token)
    conversation_id = str(int(conversation['id']))
    session_id = 'conv-' + conversation_id
    fixture = {'nonce': nonce, 'product': 17 * 19}
    code = ('import json; from pathlib import Path; '
            'data={"nonce":' + repr(nonce) + ',"product":17*19}; '
            'Path("reasoning-smoke.json").write_text(json.dumps(data)); '
            'print(json.dumps(data))')
    command = 'python3 -c ' + shlex.quote(code)
    prompt = ('This is an authorized offline verification inside this VM. Use the Bash tool EXACTLY ONCE '
              'to run the command below. It computes a product and writes reasoning-smoke.json in your '
              'current session directory. Do not use any other tools, access the network, or inspect '
              'unrelated files. After the successful tool result, give a concise final answer with the '
              'computed product and filename; do not call another tool. Keep deliberation brief.\n\n' + command)
    lab.api('/api/conversations/' + conversation_id + '/messages', {'message': prompt}, token)
    events = []
    cursor = 0
    deadline = time.monotonic() + 600
    while True:
        page = lab.api('/api/conversations/' + conversation_id + '/messages?since=' + str(cursor) + '&limit=1000', token=token)
        events.extend(page['items'])
        cursor = page['cursor']
        if not page['running'] and not page.get('hasMore'):
            break
        if time.monotonic() >= deadline:
            lab.api('/api/conversations/' + conversation_id + '/stop', {}, token)
            raise RuntimeError('Local reasoning smoke timed out; conversation retained: ' + conversation_id)
        time.sleep(1)
    assert any(e['kind'] == 'result' and not e.get('is_error') for e in events), 'No successful terminal agent result'
    assert not any(e.get('is_error') for e in events), 'Agent reported an error; inspect conversation ' + conversation_id
    uses = [e for e in events if e['kind'] == 'tool_use']
    assert len(uses) == 1 and uses[0].get('tool') == 'Bash', 'Agent did not follow the one-Bash-tool scope'
    assert any(e['kind'] == 'tool_result' and e.get('tool_use_id') == uses[0].get('tool_use_id') and not e.get('is_error') for e in events)
    assert any(e['kind'] == 'thinking' for e in events), 'No native reasoning activity'
    exported = json.loads(subprocess.run([str(ROOT / 'lab'), 'export'], check=True, capture_output=True, text=True).stdout)
    output = Path(exported['export'])
    artifact = output / 'raw/application/sessions' / session_id / 'reasoning-smoke.json'
    assert json.loads(artifact.read_text()) == fixture, 'Actual exported task outcome differs from the expected nonce/product'
    records = [r for r in jsonl(output / 'raw/llm_records.jsonl') if r.get('session_id') == session_id]
    assert records and all(r.get('status') == 'ok' and r.get('raw_request') and r.get('raw_response') for r in records)
    assert all(r.get('profile_name') == lab.PRIMARY_NAME for r in records), 'Unexpected provider handled the task'
    samples = [r for r in jsonl(output / 'training/train.jsonl') if r.get('metadata', {}).get('session_id') == session_id]
    assert {str(s['id']) for s in samples} == {str(r['id']) for r in records}, 'A genuine model turn was lost during SFT export'
    assert any(s['messages'][-1].get('reasoning') for s in samples), 'Export lost readable reasoning'
    assert any(s['messages'][-1].get('tool_calls') for s in samples), 'Export lost the actual tool call'
    assert any(m.get('role') == 'tool' for s in samples for m in s['messages']), 'Export lost the actual tool result'
    reasoning = [r for r in jsonl(output / 'raw/reasoning.jsonl') if r.get('session_id') == session_id]
    assert reasoning and any(r.get('kind') == 'raw' and r.get('text') for r in reasoning), 'Raw local thinking was not archived'
    assert all(r.get('model_backend') == 'llama.cpp' and r.get('provenance') == 'open-weight-local' for r in reasoning)
    assert all(s['metadata'].get('model_backend') == 'llama.cpp' and
               s['metadata'].get('provenance') == 'open-weight-local' for s in samples)
    assert all(s['metadata'].get('reasoning_kind') == 'raw' for s in samples if s['messages'][-1].get('reasoning'))
    manifest = json.loads((output / 'manifest.json').read_text())
    for relative, expected in manifest['sha256'].items():
        with (output / relative).open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected, relative
    print(json.dumps({'verified': ['real open-weight inference', 'autonomous Bash execution',
          'independent nonce/product artifact', 'native reasoning activity', 'every real model turn exported',
          'thinking text and tool-call/result preservation', 'raw reasoning archive and model provenance', 'artifact checksums'],
          'conversation_id': conversation_id, 'session_id': session_id, 'model': active['model'],
          'llm_records': len(records), 'training_samples': len(samples),
          'export': str(output), 'model_run': True}, indent=2))


if __name__ == '__main__':
    main()
