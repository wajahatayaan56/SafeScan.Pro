# SafeScan.Pro 🛡️  
A Smart Phishing Detection System

SafeScan.Pro is a full-stack application designed to detect phishing websites using machine learning and NLP techniques. It includes a Python-based backend for analysis and a Node.js frontend for user interaction.

---

## 📂 Project Structure
```bash
SafeScan.Pro/
│
├── backend/                         # Python backend (ML & API)
│   ├── app.py                       # Main backend application
│   ├── requirements.txt             # Python dependencies
│   ├── model/                       # Pretrained ML model (Git ignored)
│   │   └── random_forest_model.pkl
│   ├── data/                        # CSV feature files (Git ignored)
│   │   ├── clean_data.csv
│   │   └── extracted_features.csv
│   └── utils/                       # Optional: helper functions
│       └── feature_extraction.py
│
├── frontend/                        # Frontend (React or Node)
│   ├── public/                      # Static files
│   ├── src/                         # Source code
│   │   ├── App.js                   # Main React component
│   │   ├── index.js                 # Entry point
│   │   └── components/              # Reusable UI components
│   ├── package.json                 # npm dependencies
│   └── .env                         # Environment variables (Git ignored)
│
├── .gitignore                       # Files to ignore in Git
├── README.md                        # Project overview and instructions
└── .gitattributes                   # Optional: for Git LFS or file rules
```

## 🚀 Features

- Detect phishing websites using ML (Random Forest model)
- Extracts features from URL content
- Clean UI to test links
- Python backend + Node.js frontend
- API integration between both ends

---

## ⚙️ Technologies Used

### 🔸 Backend (Python)
- `Flask` or `FastAPI`
- `pandas`, `numpy`
- `scikit-learn`
- Pretrained `.pkl` model (not included in repo)

### 🔹 Frontend (Node.js / React)
- `npm`
- API calls to Python server

---

## 🛠️ Setup Instructions

### 📌 Clone the Repository

```bash
git clone https://github.com/wajahatayaan56/SafeScan.Pro.git
cd SafeScan.Pro

🔧 Backend Setup
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python app.py

 Frontend Setup
cd ../frontend
npm install
npm start

 Notes
🔐 Large files like random_forest_model.pkl and CSV datasets were removed from the repo due to GitHub file size limits.
