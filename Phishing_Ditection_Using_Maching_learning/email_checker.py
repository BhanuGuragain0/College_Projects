"""
Phishing Detection System with Advanced NLP
- Utilizes Transformer-based models (BERT/RoBERTa)
- Implements active learning pipeline
- Includes real-time monitoring
- Supports model explainability (SHAP/LIME)
- Containerized deployment (Docker)
- Async API with FastAPI
- Hyperparameter optimization with Optuna
- Integrated with MLflow for experiment tracking
"""

import os
import logging
import pandas as pd
import numpy as np
import torch
import transformers
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    pipeline
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score
import mlflow
import optuna
import shap
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import prometheus_client
from prometheus_client import Counter, Gauge
from datetime import datetime
import docker
import swifter  # For parallel pandas operations

# Configure advanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    handlers=[
        logging.FileHandler('phishing_detector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Prometheus metrics
PREDICTION_COUNTER = Counter('phishing_predictions_total', 'Total phishing predictions', ['result'])
LATENCY_GAUGE = Gauge('prediction_latency_seconds', 'Prediction latency in seconds')
MODEL_VERSION = Gauge('model_version', 'Model version info', ['version', 'type'])

class PhishingDetector:
    def __init__(self, model_name="microsoft/deberta-v3-base"):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
        self.explainer = shap.Explainer(self.predict_proba, self.tokenizer)
        self.version = datetime.now().strftime("%Y%m%d%H%M%S")
        self.active_learning_queue = []
        
        # Initialize MLflow tracking
        mlflow.set_tracking_uri("http://localhost:5000")
        mlflow.set_experiment("phishing-detection")
        
        MODEL_VERSION.labels(version=self.version, type=model_name.split("/")[-1]).set(1)

    def preprocess(self, text):
        """Advanced text preprocessing with entity masking"""
        text = text.lower()
        # Mask email addresses and URLs
        text = re.sub(r'\S+@\S+', '[EMAIL]', text)
        text = re.sub(r'http\S+', '[URL]', text)
        return self.tokenizer(
            text,
            padding='max_length',
            truncation=True,
            max_length=512,
            return_tensors="pt"
        )

    def predict_proba(self, texts):
        """Probability predictions for SHAP explanation"""
        inputs = [self.preprocess(text) for text in texts]
        with torch.no_grad():
            outputs = [self.model(**input_.to(self.device))[0].softmax(dim=1).cpu().numpy() for input_ in inputs]
        return np.vstack(outputs)

    @LATENCY_GAUGE.time()
    def predict(self, text):
        """Real-time prediction with uncertainty estimation"""
        start_time = time.time()
        inputs = self.preprocess(text)
        with torch.no_grad():
            outputs = self.model(**inputs.to(self.device))
        probs = outputs[0].softmax(dim=1).cpu().numpy()[0]
        prediction = np.argmax(probs)
        
        # Active learning: Queue uncertain predictions
        if np.max(probs) < 0.8:  # Confidence threshold
            self.active_learning_queue.append(text)
        
        PREDICTION_COUNTER.labels(result="phishing" if prediction == 1 else "legitimate").inc()
        return {
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "confidence": float(np.max(probs)),
            "shap_values": self.explainer.shap_values(text),
            "timestamp": datetime.utcnow().isoformat(),
            "model_version": self.version
        }

    def train(self, dataset, hyperparams):
        """Advanced training with hyperparameter optimization"""
        # Convert to Hugging Face dataset
        dataset = dataset.map(lambda x: {
            'text': x['text'],
            'label': x['label']
        })
        
        training_args = TrainingArguments(
            output_dir='./results',
            num_train_epochs=hyperparams['epochs'],
            per_device_train_batch_size=hyperparams['batch_size'],
            learning_rate=hyperparams['learning_rate'],
            weight_decay=hyperparams['weight_decay'],
            evaluation_strategy="epoch",
            logging_dir='./logs',
            fp16=torch.cuda.is_available(),
            report_to="mlflow"
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=dataset["train"],
            eval_dataset=dataset["test"],
            compute_metrics=self._compute_metrics
        )

        with mlflow.start_run():
            trainer.train()
            mlflow.log_params(hyperparams)
            eval_results = trainer.evaluate()
            mlflow.log_metrics(eval_results)

        # Update model version
        self.version = datetime.now().strftime("%Y%m%d%H%M%S")

    def optimize_hyperparameters(self, dataset):
        """Automated hyperparameter tuning with Optuna"""
        def objective(trial):
            hyperparams = {
                'learning_rate': trial.suggest_float('learning_rate', 1e-6, 1e-4, log=True),
                'batch_size': trial.suggest_categorical('batch_size', [8, 16, 32]),
                'epochs': trial.suggest_int('epochs', 1, 5),
                'weight_decay': trial.suggest_float('weight_decay', 0.0, 0.1)
            }
            self.train(dataset, hyperparams)
            return self._compute_metrics(self.model, dataset["test"])

        study = optuna.create_study(direction='maximize')
        study.optimize(objective, n_trials=20)
        return study.best_params

    def _compute_metrics(self, eval_pred):
        """Custom metrics computation"""
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)
        return {
            'accuracy': accuracy_score(labels, predictions),
            'f1': f1_score(labels, predictions),
            'precision': precision_score(labels, predictions),
            'recall': recall_score(labels, predictions)
        }

# FastAPI Application
app = FastAPI(title="Phishing Detection API")

@app.on_event("startup")
async def startup_event():
    """Initialize model and monitoring"""
    global detector
    detector = PhishingDetector()
    prometheus_client.start_http_server(8000)

class PredictionRequest(BaseModel):
    text: str

@app.post("/predict")
async def predict(request: PredictionRequest):
    try:
        return detector.predict(request.text)
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/model/retrain")
async def retrain():
    """Trigger active learning retraining"""
    try:
        # Connect to active learning data store
        # Implement your active learning logic here
        return {"status": "Retraining initiated"}
    except Exception as e:
        logger.error(f"Retraining error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Docker Management
class DockerManager:
    def __init__(self):
        self.client = docker.from_env()
    
    def deploy_new_version(self):
        """Automated container deployment"""
        self.client.images.build(path=".", tag=f"phishing-detector:{detector.version}")
        self.client.containers.run(
            image=f"phishing-detector:{detector.version}",
            ports={'8000': 8000},
            detach=True
        )

if __name__ == "__main__":
    # Example usage
    detector = PhishingDetector()
    
    # Load and preprocess data
    df = pd.read_csv("phishing_emails.csv")
    df['text'] = df.swifter.apply(lambda x: detector.preprocess(x['text']), axis=1)
    train, test = train_test_split(df, test_size=0.2)
    
    # Train with optimal hyperparameters
    best_params = detector.optimize_hyperparameters({'train': train, 'test': test})
    detector.train({'train': train, 'test': test}, best_params)
    
    # Start API server
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
