# SafeScan.Pro 🛡️  
A Smart Phishing Detection System

This project introduces SafeScan.Pro, a new tool designed to proactively analyze website links (URLs). Its main goal is to quickly find and help stop cyber threats like malware, viruses, and vulnerabilities. SafeScan.Pro uses a smart combination of Machine Learning (ML) and established cybersecurity techniques. This allows it to automatically and intelligently check if a website link is safe or dangerous. It's built for real-time security, meaning it can give you instant answers about a URL. This helps you stay safe right when you need it. Ultimately, SafeScan.Pro aims to provide a simple, yet powerful solution to keep you safe from tricky online scams and malicious websites.

---
## 📷 Frontend Preview
> <img width="1263" height="583" alt="image" src="https://github.com/user-attachments/assets/2069eb0b-24ab-492a-b713-4ea31e5853ef" />
## Result 
> <img width="1174" height="594" alt="image" src="https://github.com/user-attachments/assets/ed2f7b8e-198b-45a2-a1b5-e12c201a5c0f" />

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
```
```bash
cd SafeScan.Pro
```
🔧 Backend Setup
```bash
cd backend
```
```bash
python -m venv venv
```
```bash
.\venv\Scripts\activate
```
```bash
pip install -r requirements.txt
```
```bash
python app.py
```
 Frontend Setup
 ```bash
cd ../frontend
```
```bash
npm install
```
```bash
npm start
```

 Notes
🔐 Large files like random_forest_model.pkl and CSV datasets were removed from the repo due to GitHub file size limits.
