# SafeScan.Pro 🛡️  
A Smart Phishing Detection System

SafeScan.Pro is a full-stack application designed to detect phishing websites using machine learning and NLP techniques. It includes a Python-based backend for analysis and a Node.js frontend for user interaction.

---

## 📂 Project Structure

SafeScan.Pro/
│
├── backend/                           # Python backend (API & ML)
│   ├── app.py                         # Main backend script
│   ├── requirements.txt               # Python dependencies
│   ├── model/                         # ML models (.pkl files) (gitignored)
│   │   └── random_forest_model.pkl
│   ├── data/                          # CSVs / extracted features (gitignored)
│   │   ├── clean_data.csv
│   │   └── extracted_features.csv
│   └── utils/                         # Helper functions (optional)
│       └── feature_extraction.py
│
├── frontend/                          # React or Node.js frontend
│   ├── public/
│   ├── src/
│   │   ├── App.js
│   │   ├── index.js
│   │   └── components/
│   ├── package.json                   # npm dependencies
│   └── .env                           # API URLs or secrets (gitignored)
│
├── .gitignore                         # Files/folders to exclude from git
├── README.md                          # Project description and setup
└── .gitattributes                     # Optional - for Git LFS (large files)


---

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
bash
Copy
Edit

cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python app.py

 Frontend Setup
bash
Copy
Edit
cd ../frontend
npm install
npm start

 Notes
🔐 Large files like random_forest_model.pkl and CSV datasets were removed from the repo due to GitHub file size limits.
