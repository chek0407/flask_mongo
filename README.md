# 🏆 EPL Flask API (2025/26)

A RESTful Flask API providing access to **English Premier League (EPL) team and player data** for the 2025/26 season.  
The API is hosted on **Render** and connected to a **MongoDB Atlas** database.

---

## 🌐 Live API

**Base URL:**  
```
https://epl-flask-api.onrender.com
```

---

## 🧩 Tech Stack

- **Backend:** Python Flask  
- **Database:** MongoDB Atlas (Cluster: `FlaskAPICluster`)  
- **Hosting:** Render  
- **Collection:** `epl_2025_2026_updated`

---

## ⚙️ Project Structure

```
/EPL-Flask-API
│
├── app2_mongo.py        # Main Flask app
├── requirements.txt     # Dependencies
├── README.md            # Project documentation
└── ...
```

---

## 🚀 Endpoints Overview

| Method | Endpoint | Description |
|--------|-----------|-------------|
| **GET** | `/epl/teams` | Get list of all EPL teams |
| **GET** | `/epl/teams/<team_id>` | Get details of a specific team |
| **GET** | `/epl/teams/<team_id>/details` | Get full team info with player filtering/sorting |
| **POST** | `/epl/add_team` | Add a new team |
| **PUT** | `/epl/update_team/<team_id>` | Update team info |
| **DELETE** | `/epl/delete_team/<team_id>` | Delete a team |
| **POST** | `/epl/add_player` | Add a new player |
| **PUT** | `/epl/update_player/<player_id>` | Update a player's info |
| **POST** | `/epl/transfer_player` | Transfer a player between teams |
| **GET** | `/epl/search_player?name=<query>` | Search players by name |

---

## 🧠 Example Response

```json
{
  "Stadium": "Villa Park",
  "Founded": 1874,
  "TeamID": "AVL",
  "TeamName": "Aston Villa",
  "Manager": "Unai Emery",
  "EntityType": "TEAM",
  "Players": [
    {
      "PlayerID": "1",
      "PlayerName": "Emiliano Martínez",
      "Position": "GK",
      "Number": 1,
      "Age": 32
    },
    {
      "PlayerID": "10",
      "PlayerName": "Pau Torres",
      "Position": "CB",
      "Number": 14,
      "Age": 27
    }
  ]
}
```

---

## 🧩 MongoDB Connection

The Flask API connects to MongoDB Atlas via:

```python
from pymongo import MongoClient

client = MongoClient("mongodb+srv://chekvld:P92fRLNGIGPNkky7@flaskapicluster.jiu62vv.mongodb.net/?retryWrites=true&w=majority&appName=FlaskAPICluster")
db = client["FlaskAPICluster"]
epl_collection = db["epl_2025_2026_updated"]
```

---

## 💻 Local Development

### 1. Clone the repo
```bash
git clone https://github.com/your-username/EPL-Flask-API.git
cd EPL-Flask-API
```

### 2. Create a virtual environment
```bash
python -m venv venv
venv\Scripts\activate   # on Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Flask app
```bash
python app2_mongo.py
```

The API will start on:
```
http://127.0.0.1:5000
```

---

## 🌍 Deployment (Render)

The API is deployed automatically on Render.  
Each push to the connected GitHub repo triggers a rebuild.

- **Render Dashboard:** [https://render.com](https://render.com)  
- **Service URL:** [https://epl-flask-api.onrender.com](https://epl-flask-api.onrender.com)

---

## 🏁 Notes

- The current dataset represents the **2025/26 EPL squads**.
- Data is stored in JSON format in MongoDB and managed via the Flask API.
- The project supports full CRUD operations (Create, Read, Update, Delete) and player transfers.

---

## 📧 Contact

**Developer:** Vladi  
**Role:** QA Engineer / Learning Technologies in IT  
**Email:** _(add if you wish)_
