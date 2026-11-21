import json
from pathlib import Path

import pytest

from ordivyr.board.bootstrap import initialize, status
from ordivyr.board.service import Board, Forbidden, NotFound
from ordivyr.board import contract as C


def test_doctor_optional_lite_dependency_and_required_worker(tmp_path, monkeypatch, capsys):
    import importlib.util
    from ordivyr.board.__main__ import main
    initialize(tmp_path, 'model', 'http://127.0.0.1:9000/v1', engine='lite')
    monkeypatch.setattr(importlib.util, 'find_spec', lambda name: None)
    assert main(['doctor', '--home', str(tmp_path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['ok'] and not report['lite_installed'] and not report['lite_required']
    assert main(['doctor', '--home', str(tmp_path), '--lite-worker']) == 2
    report = json.loads(capsys.readouterr().out)
    assert not report['ok'] and report['lite_required']
    monkeypatch.setattr(importlib.util, 'find_spec', lambda name: object() if name == 'ordivyr_lite' else None)
    assert main(['doctor', '--home', str(tmp_path), '--lite-worker']) == 2
    report = json.loads(capsys.readouterr().out)
    assert report['lite_installed'] and not report['lite_adapter_available']
    monkeypatch.setattr(importlib.util, 'find_spec', lambda name: object())
    assert main(['doctor', '--home', str(tmp_path), '--lite-worker']) == 0
    capsys.readouterr()
    # Optional dependency presence must not hide a broken Board database.
    (tmp_path / 'queue.db').unlink()
    for extra in ([], ['--lite-worker']):
        assert main(['doctor', '--home', str(tmp_path), *extra]) == 2
        assert not json.loads(capsys.readouterr().out)['ok']
    (tmp_path / 'queue.db').write_bytes(b'invalid SQLite database')
    assert main(['doctor', '--home', str(tmp_path), '--lite-worker']) == 2
    assert not json.loads(capsys.readouterr().out)['ok']


def test_personal_bootstrap_reuses_identity_and_preserves_config(tmp_path):
    state = initialize(tmp_path, 'model', 'http://127.0.0.1:9000/v1', engine='lite')
    before = {p.name: p.read_bytes() for p in tmp_path.glob('*.token')}
    again = initialize(tmp_path, 'model', 'http://127.0.0.1:9000/v1', engine='lite')
    assert state['created'] and not again['created']
    assert before == {p.name: p.read_bytes() for p in tmp_path.glob('*.token')}
    assert (tmp_path / 'selfhost.json').stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError, match='already configured'):
        initialize(tmp_path, 'other-model', 'http://127.0.0.1:9000/v1')
    board = Board(tmp_path)
    admin = board.principal((tmp_path / 'admin.token').read_text())
    workers = board.workers(admin)
    assert len(workers) == 1 and workers[0]['caps']['max_concurrency'] == 1
    assert workers[0]['caps']['tools'] == sorted(['list_files', 'read_file', 'grep', 'find_files', 'edit_file', 'write_file'])
    assert status(tmp_path)['databases'] == {'board.db': 'ok', 'queue.db': 'ok'}


def test_output_cursor_is_scoped_and_survives_reopen(tmp_path):
    initialize(tmp_path, 'model', 'http://127.0.0.1:9000/v1', engine='lite')
    board = Board(tmp_path)
    admin = board.principal((tmp_path / 'admin.token').read_text())
    result = board.submit_job(admin, 'main', 'Create a result', agent_id='coder')
    task = board.store.claim('w', 'n', 20, kinds=['board.lite'])
    for text in ['one', 'two', 'three']:
        board.store.record_output(task['id'], task['fence'], 'lite.progress', {}, text)
    rows = board.job_outputs(admin, 'main', result['job_id'], limit=2)
    assert [r['output'] for r in rows] == ['one', 'two']
    reopened = Board(tmp_path)
    assert [r['output'] for r in reopened.job_outputs(admin, 'main', result['job_id'], rows[-1]['id'])] == ['three']
    with pytest.raises(NotFound):
        board.job_outputs(admin, 'main', 'j-unknown')


def test_bootstrap_rejects_unsafe_model_urls_and_capacity(tmp_path):
    for url in ['http://user:pass@127.0.0.1:9000/v1', 'http://remote.example/v1']:
        with pytest.raises(ValueError):
            initialize(tmp_path, 'model', url)
    with pytest.raises(ValueError):
        initialize(tmp_path, 'model', 'http://127.0.0.1:9000/v1', slots=3)


def test_dashboard_output_refresh_advances_past_first_page():
    import shutil
    import subprocess
    node = shutil.which('node')
    if not node: pytest.skip('Node is needed for dashboard behavior check')
    source = (Path(__file__).parents[1] / 'board/static/dashboard.js').read_text()
    helper = source.split('async function jobOutputs(', 1)[1].split('async function jobDetail()', 1)[0]
    script = '''const assert=require('node:assert/strict');
const S={me:{org:'local'}};const rows=Array.from({length:1205},(_,i)=>({id:i+1,output:String(i+1)}));
async function api(method,path){const q=new URL('http://local'+path).searchParams;
const batch=rows.filter(r=>r.id>Number(q.get('after'))).slice(0,Number(q.get('limit')));
return {outputs:batch,next_after:batch.length?batch.at(-1).id:null};}
async function jobOutputs(''' + helper + '''
(async()=>{let result=await jobOutputs('main','j-one');assert.equal(result.after,1000);
result=await jobOutputs('main','j-one');assert.equal(result.after,1205);
assert.equal(result.outputs.length,200);assert.equal(result.outputs.at(-1).output,'1205');
await jobOutputs('main','j-one');assert.equal(result.outputs.length,200);})().catch(e=>{console.error(e);process.exit(1)});
'''
    result = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_personal_adapter_requires_current_attempt_approval(tmp_path, monkeypatch):
    import sys
    import threading
    import types
    from ordivyr import durable as D
    from ordivyr.board.lite_adapter import board_handler
    calls = []
    fake = types.ModuleType('ordivyr_lite.board_adapter')
    fake.execute = lambda *args, **kwargs: calls.append(args) or C.make_result('j-test','completed','done')
    parent = types.ModuleType('ordivyr_lite'); parent.__path__ = []
    monkeypatch.setitem(sys.modules, 'ordivyr_lite', parent)
    monkeypatch.setitem(sys.modules, 'ordivyr_lite.board_adapter', fake)
    config = tmp_path / 'worker.json'
    config.write_text(json.dumps({'route': {'model': 'test'}, 'model': 'test'}))
    monkeypatch.setenv('ORDIVYR_LITE_WORKER_CONFIG', str(config))
    ctx = types.SimpleNamespace(payload={'model_ref': {'endpoint': 'local','model': 'test'}},
        task={'attempt': 2}, checkpoint={}, dir=tmp_path/'a7', cancel=threading.Event(),
        lost=threading.Event(), check=lambda: None)
    ctx.dir.mkdir()
    with pytest.raises(D.NeedsApproval): board_handler(ctx)
    assert calls == []
    ctx.task['attempt'] = 3
    ctx.checkpoint = {'owner_approval': {'attempt': 2,'resolution': 'retry'}}
    result, _ = board_handler(ctx)
    assert result['status'] == 'completed' and len(calls) == 1
    ctx.task['attempt'] = 4
    with pytest.raises(D.NeedsApproval): board_handler(ctx)
    assert len(calls) == 1


def test_default_init_uses_builtin_engine_and_needs_no_lite_package(tmp_path):
    state = initialize(tmp_path, 'model', 'http://127.0.0.1:9000/v1')
    assert state['engine'] == 'ordivyr' and (tmp_path / 'worker.token').is_file() and not (tmp_path / 'lite-worker.token').exists()
    board = Board(tmp_path)
    admin = board.principal((tmp_path / 'admin.token').read_text())
    (worker,) = board.workers(admin)
    assert worker['caps']['engine'] == 'ordivyr' and worker['caps']['isolation'] == 'process' and worker['caps']['endpoints'] == ['local']
    (agent,) = board.agents(admin, 'main')
    assert agent['id'] == 'coder' and agent['engine'] == 'ordivyr' and agent['model_ref']['endpoint'] == 'local'
    report = status(tmp_path)
    assert report['ok'] and report['engine'] == 'ordivyr' and report['endpoint']['paid'] is False
    assert initialize(tmp_path, 'model', 'http://127.0.0.1:9000/v1')['created'] is False
    with pytest.raises(ValueError, match='already configured'):
        initialize(tmp_path, 'model', 'http://127.0.0.1:9000/v1', engine='lite')


def test_remote_endpoint_is_refused_until_spend_is_authorized(tmp_path):
    key = tmp_path / 'k'; key.write_text('sk-test-not-real')
    initialize(tmp_path / 'a', 'model', 'https://api.example.com/v1', key_file=str(key))
    report = status(tmp_path / 'a')
    assert not report['ok'] and report['endpoint']['paid'] and not report['endpoint']['authorized']
    initialize(tmp_path / 'b', 'model', 'https://api.example.com/v1', key_file=str(key), authorize=(1.0, 5.0))
    assert status(tmp_path / 'b')['ok']
    assert 'sk-test-not-real' not in (tmp_path / 'b' / 'selfhost.json').read_text()


def test_personal_credentials_are_backed_up_only_on_request_and_restore_to_a_new_path(tmp_path):
    from ordivyr.board import backup as BK
    initialize(tmp_path / 'h', 'model', 'http://127.0.0.1:9000/v1')
    BK.backup(tmp_path / 'h', tmp_path / 'plain')
    assert not (tmp_path / 'plain' / 'personal').exists()                       # default backups stay credential-free
    man = BK.backup(tmp_path / 'h', tmp_path / 'full', include_personal=True)
    assert man['personal'] and 'personal/admin.token' in man['files'] and 'personal/worker.token' in man['files']
    assert not any(n.endswith('master.key') for n in man['files'])
    BK.restore(tmp_path / 'full', tmp_path / 'new')
    assert (tmp_path / 'new' / 'admin.token').read_text() == (tmp_path / 'h' / 'admin.token').read_text()
    assert (tmp_path / 'new' / 'gateway').is_dir() and status(tmp_path / 'new')['ok']
    (tmp_path / 'full' / 'personal' / 'admin.token').write_text('tampered')
    with pytest.raises(BK.BackupError):
        BK.verify_backup(tmp_path / 'full')
