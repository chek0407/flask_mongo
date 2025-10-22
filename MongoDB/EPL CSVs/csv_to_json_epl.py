import csv
import json
import os

# === PATHS ===
input_folder = r"E:\Tutorial\DataBase\MongoDB\EPL CSVs"
teams_csv = os.path.join(input_folder, "EPL 25-26 teams.csv")
output_folder = os.path.join(input_folder, "EPL JSONs")
os.makedirs(output_folder, exist_ok=True)

# === HELPER: open CSV with fallback encodings ===
def open_csv_safely(path):
    # Try UTF-8 first, then cp1252, then Latin-1
    for enc in ("utf-8-sig", "cp1252", "latin1"):
        try:
            return open(path, "r", encoding=enc, errors="replace")
        except UnicodeDecodeError:
            continue
    # If all fail, raise an explicit error
    raise UnicodeDecodeError(f"Unable to decode file: {path}")

# === LOAD TEAMS INFO ===
teams_info = {}
with open_csv_safely(teams_csv) as f:
    reader = csv.DictReader(f)
    for row in reader:
        clean_row = {k.strip(): v.strip() for k, v in row.items() if k}
        team_id = clean_row["TeamID"].strip()
        teams_info[team_id] = {
            "Stadium": clean_row["Stadium"],
            "Founded": int(clean_row["Founded"]),
            "TeamID": team_id,
            "TeamName": clean_row["TeamName"],
            "Manager": clean_row["Manager"],
            "EntityType": "TEAM",
            "Players": []
        }

# === LOAD PLAYER FILES ===
for file in os.listdir(input_folder):
    if file.startswith("EPL 25-26 - ") and file.endswith(".csv") and "teams" not in file:
        team_id = file.split(" - ")[1].replace(".csv", "").strip()
        csv_path = os.path.join(input_folder, file)

        players = []
        with open_csv_safely(csv_path) as f:
            reader = csv.DictReader(f)
            # Normalize header keys to avoid invisible BOMs or spaces
            reader.fieldnames = [name.strip() for name in reader.fieldnames]
            for idx, row in enumerate(reader, start=1):
                clean_row = {k.strip(): v.strip() for k, v in row.items() if k}
                player = {
                    "PlayerID": str(idx),
                    "PlayerName": clean_row.get("Player Name", ""),
                    "Position": clean_row.get("Position", ""),
                    "Number": int(clean_row["Number"]) if clean_row.get("Number") else None,
                    "Age": int(clean_row["Age"]) if clean_row.get("Age") else None
                }
                players.append(player)

        if team_id in teams_info:
            teams_info[team_id]["Players"] = players
        else:
            print(f"⚠️  Warning: TeamID {team_id} not found in teams CSV.")

# === WRITE INDIVIDUAL JSON FILES ===
for team_id, team_data in teams_info.items():
    out_path = os.path.join(output_folder, f"{team_id}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(team_data, f, indent=4, ensure_ascii=False)
    print(f"✅ Created {team_id}.json")

print("\n🎉 All JSON files created successfully.")