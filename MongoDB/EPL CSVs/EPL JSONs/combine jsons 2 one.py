import json
import os

# === PATHS ===
json_folder = r"E:\Tutorial\DataBase\MongoDB\EPL CSVs\EPL JSONs"
master_json_path = os.path.join(json_folder, "EPL_25_26_all_teams.json")

# === LOAD ALL INDIVIDUAL JSON FILES ===
all_teams = []
for file in os.listdir(json_folder):
    if file.endswith(".json") and file != "EPL_25_26_all_teams.json":
        with open(os.path.join(json_folder, file), "r", encoding="utf-8") as f:
            team_data = json.load(f)
            all_teams.append(team_data)

# === WRITE MASTER JSON FILE ===
with open(master_json_path, "w", encoding="utf-8") as f:
    json.dump(all_teams, f, indent=4, ensure_ascii=False)

print(f"🎉 Master JSON created: {master_json_path}")