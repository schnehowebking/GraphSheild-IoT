#!/usr/bin/env python3
"""Test real OVS meter-rule expiry and removal in an isolated local namespace lab."""
import json
import os
import time
from run_ovs_controller_trials import preflight, ovs_lab, COOKIE_METER, command

if __name__=="__main__":
    preflight()
    with ovs_lab(f"ttl{os.getpid()%100000}",1000,1) as lab:
        target=lab.hosts["benign"]  # test fixture identity, no model or experimental inference
        lab.set_rate_limit(target,1)
        time.sleep(1.5)
        if COOKIE_METER in lab.dump_flows(): raise RuntimeError("Meter flow did not expire")
        lab.clear_meter()
        evidence=lab.dump_flows()+command(["ovs-ofctl","-O","OpenFlow13","dump-meters",lab.bridge]).stdout
        if COOKIE_METER in evidence or "meter=1" in evidence: raise RuntimeError("Removal failed")
    print(json.dumps({"rule_expiry_checked":True,"rule_and_meter_removal_checked":True,
                      "scope":"isolated OVS lifetime test, not mitigation effectiveness"}))
