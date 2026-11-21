"""Every repo-bench task is valid: reference solution passes the hidden test, an empty/wrong solution fails (graded in the real no-network sandbox)."""
import random, shutil, pytest
from ordivyr.nova_memory import repo_bench as R

REFS = {
 "drain": "def {fn}(store, worker):\n    n=0\n    while True:\n        t=store.claim(worker)\n        if not t: return n\n        store.begin(t['id'],t['fence']); store.complete(t['id'],t['fence'],{{'handled':'{tag}'}}); n+=1\n",
 "retry": "def {fn}(store, tid, fence):\n    store.release(tid, fence, '{tag}', delay=0)\n",
 "verify": "from ordivyr.nova_memory import NovaMemory\ndef {fn}(mem, author, verifier, text):\n    i=mem.add(author,'team','semantic','t',text,'s'); mem.verify(verifier,i,{{'passed':True,'validator':'ci-{tag}','ref':'run-{tag}'}}); return i\n",
 "effect": "def {fn}(store, tid, fence, key, sink):\n    store.effect(tid, fence, key, lambda k: sink.append(k))\n",
 "pack": "def {fn}(mem, principal, query):\n    return mem.pack(principal, query, 120)['text']\n",
 "supersede": "def {fn}(mem, verifier, old_id, new_text):\n    n=mem.correct(verifier, old_id, new_text, 'fix'); mem.verify(Principal_v(verifier), n, {{'passed':True,'validator':'ci-{tag}','ref':'run-{tag}'}}); return n\n",
}


@pytest.mark.parametrize("fam", list(R.FAMILIES))
def test_task_valid(fam, tmp_path):
    v = R.variant(fam, random.Random(3)); prompt, test = R.make_task(v); w = tmp_path / "w"; w.mkdir(); R.snapshot(w)
    ref = REFS[fam].format(**v)
    if fam == "supersede":                                          # correct() by the verifier is author==verifier -> must be refused; the right reference uses a separate author principal
        ref = ("from ordivyr.nova_memory import Principal\ndef {fn}(mem, verifier, old_id, new_text):\n    a=Principal.make(verifier.tenant, verifier.project, 'editor', read=['team'], write=['team'])\n"
               "    n=mem.correct(a, old_id, new_text, 'fix'); mem.verify(verifier, n, {{'passed':True,'validator':'ci-{tag}','ref':'run-{tag}'}}); return n\n").format(**v)
    ok_empty, _ = R.grade(w, v["mod"], test); assert not ok_empty                                # starting state fails
    (w / "solutions" / f"{v['mod']}.py").write_text(ref); ok, summ = R.grade(w, v["mod"], test); assert ok, summ
