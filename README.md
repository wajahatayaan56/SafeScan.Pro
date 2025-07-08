# SafeScan.Pro 🛡️  
A Smart Phishing Detection System

SafeScan.Pro is a full-stack application designed to detect phishing websites using machine learning and NLP techniques. It includes a Python-based backend for analysis and a Node.js frontend for user interaction.

---

## 📂 Project Structure

SafeScan.Pro/
├── backend/ # Python backend (Flask/FastAPI/etc.)
│ ├── app.py
│ ├── model/ # ML models (e.g., .pkl files - not uploaded)
│ └── data/ # CSV feature files (ignored in Git)
├── frontend/ # Node.js or React-based UI
│ ├── public/
│ ├── src/
│ └── package.json
├── .gitignore
└── README.md



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
