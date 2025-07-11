from mitreattack.navlayers.exporters import ToExcel
from mitreattack.stix20 import MitreAttackData
import requests
import json

# Load data từ MITRE ATT&CK STIX bundle
attack = MitreAttackData("enterprise-attack.json")

# Tải danh sách các nhóm APT
groups = attack.get_groups(remove_revoked_deprecated=True)
group_id = []
for group in groups:
    for i in group["external_references"]:
        if i["source_name"] == "mitre-attack":
            group_id.append(i["external_id"])
print(group_id)


BASE_URL = "https://attack.mitre.org"
GROUPS_URL = BASE_URL + "/groups/"


def get_group_content(group_id):
    url = f"{BASE_URL}/groups/{group_id}/{group_id}-enterprise-layer.json"
    res = requests.get(url)

    if res.status_code == 200:
        return res.json()
    else:
        print(f"[-] Failed: {group_id} ({res.status_code})")
        return None
get_group_content(group_id[0])
group_map_name = {}
ttp_map_group = {}
for gid in group_id:
    ttp_map_group[gid] = []
    group_data = get_group_content(gid)
    if group_data is None: continue
    group_map_name[gid] = group_data["name"]
    for i in group_data["techniques"]:
        ttp_map_group[gid].append(i["techniqueID"])
        

from collections import defaultdict

ttp_to_groups = defaultdict(list)

for group_id, ttp_list in ttp_map_group.items():
    for ttp in ttp_list:
        ttp_to_groups[ttp].append(group_id)

with open('ttp_map_group.json', 'w') as f:
    json.dump(ttp_to_groups, f, indent=4)
with open('group_map_name.json', 'w') as f:
    json.dump(group_map_name, f, indent=4)
