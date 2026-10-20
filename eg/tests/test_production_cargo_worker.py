import tempfile,unittest
from pathlib import Path
from tools.production_cargo_worker import CargoWorker,WorkerDenied
class ProductionWorkerFailClosedTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();p=Path(self.temp.name)
  root=p/"project";root.mkdir();(root/"Cargo.toml").write_text("[package]\nname='x'\nversion='0.1.0'\n")
  journal=p/"journal";journal.mkdir(mode=0o700)
  self.worker=CargoWorker(root=root,journal=journal,private=None,adapter_id="trusted-adapter-cargo",
                          hitl_public_key="unset",fetch_state=lambda _:{"current_step":"02.01"},
                          fetch_detail=lambda _:{"task":{"contract_status":"OPEN"}})
  self.root=root
 def tearDown(self):self.temp.cleanup()
 def base(self):
  return {"task_id":"task-knid-solana-e2e","step_key":"02.01",
          "action":{"action_type":"cargo_test","effect_class":"E3","real_world_effect":True,"target":str(self.root/"Cargo.toml")},
          "approval":{}}
 def test_pre_required(self):
  with self.assertRaisesRegex(WorkerDenied,"LIVE_EG_PRE_REQUIRED"):self.worker.execute(**self.base())
 def test_disallow_unscoped_command(self):
  a=self.base();a["action"]["action_type"]="shell"
  with self.assertRaisesRegex(WorkerDenied,"ACTION_SCOPE_DENIED"):self.worker.execute(**a)
 def test_disallow_path_escape(self):
  a=self.base();a["action"]["target"]="/tmp/Cargo.toml"
  with self.assertRaisesRegex(WorkerDenied,"ACTION_SCOPE_DENIED"):self.worker.execute(**a)
 def test_disallow_effect_downgrade(self):
  a=self.base();a["action"]["effect_class"]="E2"
  with self.assertRaisesRegex(WorkerDenied,"ACTION_SCOPE_DENIED"):self.worker.execute(**a)
 def test_does_not_write_intent_when_denied(self):
  with self.assertRaises(WorkerDenied):self.worker.execute(**self.base())
  self.assertEqual(list(self.worker.journal.glob("*.json")),[])
if __name__=="__main__":unittest.main()
