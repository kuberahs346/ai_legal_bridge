# AI Legal Bridge ⚖️🤖

AI Legal Bridge is a Flask-based web app for **legal document summarization, Kannada translation, audio (gTTS), and PDF generation**.  
It includes **auth, admin dashboard, SMS/Email, and upload history**.

## ✨ Features
- Upload `.txt` / `.csv`
- T5 / BART / LED summarization
- Kannada translation
- gTTS audio
- PDF reports
- User profile + upload history
- Email/SMS notifications (D7 / Gmail SMTP)
- Admin: view/edit/delete/export users

## 🛠 Tech
Flask, Python, SQLAlchemy, SQLite/MySQL, Transformers (T5/BART/LED), gTTS.

## 🚀 Run locally
```bash
git clone https://github.com/kuberahs346/ai_legal_bridge.git
cd ai_legal_bridge
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
