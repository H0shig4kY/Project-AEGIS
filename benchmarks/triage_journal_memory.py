"""Measure traced Python heap for 10,000 receipts; excludes setup, RSS and OS cache.

python benchmarks/triage_journal_memory.py --source ./aegis
"""
import argparse
import gc,json,sys,tempfile,tracemalloc
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source",type=Path,default=Path("aegis"))
args=parser.parse_args()
sys.path.insert(0,str(args.source.resolve()))
from aegis.finding_store import FindingStore
from aegis.finding_triage_history_store import FindingTriageHistoryStore
from aegis.models import FindingRecord,AssetType
with tempfile.TemporaryDirectory() as tmp:
 store=FindingStore(Path(tmp)/"findings");history=FindingTriageHistoryStore(Path(tmp)/"triage")
 record=FindingRecord(finding_id="a"*64,rule_id="TEST",severity="medium",title="test",description="test",asset_type=AssetType.SERVICE,asset_value="test:80")
 store.save(record);journal=store.path/".triage-journal";journal.mkdir()
 for i in range(10000):
  event=dict(event_id=f"{i:032x}",finding_id=record.finding_id,event_type="suppress" if i%2==0 else "unsuppress",from_state="open" if i%2==0 else "suppressed",to_state="suppressed" if i%2==0 else "open",detected_at="2026-10-09T00:00:00+00:00",actor="operator",reason="benchmark")
  (history.directory/(event["event_id"]+".json")).write_text(json.dumps(event,indent=2,sort_keys=True),encoding="utf-8")
  (journal/(event["event_id"]+".txn")).write_text(json.dumps(dict(version=1,sequence=i+1,status="done",history_directory="../triage",event=event),indent=2,sort_keys=True),encoding="utf-8")
 gc.collect();tracemalloc.start()
 store.get(record.finding_id);gc.collect()
 first=tracemalloc.get_traced_memory()
 for _ in range(10):store.get(record.finding_id)
 gc.collect();repeat=tracemalloc.get_traced_memory()
 cache=getattr(store,"_triage_cache",None)
 duplicated=0
 if cache:
  expected={d["event"]["event_id"]:d["event"] for _,d in cache.entries}
  duplicated=sum(event is not expected[event["event_id"]] for _,event in cache.events.values())
  del expected
 del cache,store
 gc.collect();released=tracemalloc.get_traced_memory()
 print(json.dumps(dict(first_current_mib=first[0]/2**20,first_peak_mib=first[1]/2**20,repeated_current_mib=repeat[0]/2**20,repeated_peak_mib=repeat[1]/2**20,after_release_current_mib=released[0]/2**20,duplicate_event_dicts=duplicated)))
