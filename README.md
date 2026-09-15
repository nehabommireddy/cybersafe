# CyberSafe

A Chrome extension that detects potential phishing emails and explains why they may be suspicious.

CyberSafe combines **machine learning and transparent heuristic checks** to analyze email content and generate a phishing risk score from 0–100. It can be used directly in Gmail or through a standalone text-checking interface.

## Demo

<img width="2042" height="1142" alt="image" src="https://github.com/user-attachments/assets/499f0e9b-5595-4944-9c71-07187fed97ec" />


## How It Works

```text
Gmail Email
    ↓
Chrome Extension
    ↓
FastAPI Backend
    ↓
┌─────────────────────────────┐
│ ML Model                    │
│ TF-IDF + Logistic Regression│
└─────────────────────────────┘
    +
┌─────────────────────────────┐
│ Heuristic Checks            │
│ • Suspicious domains        │
│ • Urgency language          │
│ • Credential requests       │
└─────────────────────────────┘
    ↓
Phishing Risk Score + Reasons
```

## Features

* **Phishing risk score:** Generates a score from 0–100.
* **Machine learning classification:** Uses TF-IDF features with Logistic Regression.
* **Heuristic analysis:** Checks for common phishing indicators such as suspicious domains, urgency, and credential requests.
* **Plain-English explanations:** Shows reasons contributing to the risk assessment.
* **Gmail integration:** Analyzes emails directly from Gmail.
* **Standalone text checker:** Allows users to paste text for analysis outside of Gmail.
* **Security tips:** Displays rotating tips about common phishing techniques.

## Tech Stack

| Technology          | Purpose                    |
| ------------------- | -------------------------- |
| JavaScript          | Chrome extension logic     |
| HTML/CSS            | Extension interface        |
| Chrome Manifest V3  | Browser extension platform |
| Python              | Backend and ML pipeline    |
| FastAPI             | REST API                   |
| scikit-learn        | Machine learning           |
| TF-IDF              | Text feature extraction    |
| Logistic Regression | Phishing classification    |

## Project Structure

```text
cybersafe/
├── extension/
│   ├── popup.html
│   ├── popup.css
│   ├── popup.js
│   ├── background.js
│   ├── content.js
│   └── manifest.json
│
├── app.py
├── train_model.py
├── sample_data.csv
├── requirements.txt
└── README.md
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/nehabommireddy/cybersafe.git
cd cybersafe
```

### 2. Set up the backend

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

**Windows:**

```bash
.venv\Scripts\activate
```

**macOS/Linux:**

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### 3. Train the model

```bash
python train_model.py
```

### 4. Start the FastAPI server

```bash
uvicorn app:app --reload --port 8000
```

The API should now be available at:

```text
http://localhost:8000
```

You can verify that the backend is running by visiting:

```text
http://localhost:8000/health
```

### 5. Load the Chrome extension

1. Open Chrome.
2. Navigate to `chrome://extensions`.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Select the `extension/` directory.

### 6. Analyze an email

Open Gmail and select an email. The extension analyzes the message and displays a risk level, score, and reasons for the classification.

You can also use the standalone text-checking interface to analyze pasted text.

## Model

CyberSafe uses a combination of machine learning and rule-based analysis.

### Machine Learning

The text classifier uses:

* **TF-IDF** for converting email text into numerical features
* **Logistic Regression** for binary phishing classification

### Heuristic Analysis

The extension also looks for indicators commonly associated with phishing, including:

* Suspicious or lookalike domains
* Urgent or threatening language
* Requests for credentials or sensitive information
* Other suspicious patterns in the message

The final risk score combines the machine learning prediction with these heuristic signals. This provides both a statistical prediction and interpretable reasons for the result.

## Limitations

CyberSafe is an educational and portfolio project rather than a production security system.

* The included sample dataset is small and is intended to demonstrate the ML pipeline rather than establish model accuracy.
* Gmail DOM selectors may need to be updated if Gmail changes its interface.
* The backend currently runs locally.
* Production deployment would require HTTPS, appropriate authentication, and restrictive CORS configuration.
* Phishing detection is inherently imperfect, so the score should not be treated as a guarantee that an email is safe or malicious.

## Future Improvements

* Integrate live URL reputation services.
* Add support for additional email platforms such as Outlook.
* Add local scan history and trend tracking.
* Provide in-page warnings for high-risk messages.
* Expand the training dataset with a larger collection of labeled phishing and legitimate messages.

## Why I Built This

I built CyberSafe to explore the intersection of **software engineering, cybersecurity, and machine learning**. I wanted to create something that could apply an ML model to a practical security problem while still giving users understandable reasons behind the result.

```
