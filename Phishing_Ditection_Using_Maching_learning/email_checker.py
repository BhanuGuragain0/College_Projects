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
import re
import time
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
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
import mlflow
import optuna
import shap
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import prometheus_client
from prometheus_client import Counter, Gauge
from datetime import datetime
import docker

try:
    import swifter  # For parallel pandas operations
except ImportError:
    logging.warning("swifter not installed. Using standard pandas apply.")
    swifter = None

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
        """
        Initialize PhishingDetector with specified model.
        
        Args:
            model_name (str): HuggingFace model identifier
        """
        try:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            logger.info(f"Using device: {self.device}")
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                model_name, 
                num_labels=2
            ).to(self.device)
            
            # Initialize SHAP explainer (optional for performance reasons)
            # Uncomment below to enable SHAP explanations
            # self.explainer = shap.Explainer(self.predict_proba, self.tokenizer)
            self.explainer = None
            
            self.version = datetime.now().strftime("%Y%m%d%H%M%S")
            self.active_learning_queue = []
            
            # Initialize MLflow tracking
            try:
                mlflow.set_tracking_uri("http://localhost:5000")
                mlflow.set_experiment("phishing-detection")
            except Exception as e:
                logger.warning(f"MLflow not available: {e}")
            
            MODEL_VERSION.labels(version=self.version, type=model_name.split("/")[-1]).set(1)
            logger.info("PhishingDetector initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize PhishingDetector: {e}")
            raise

    def preprocess(self, text):
        """
        Advanced text preprocessing with entity masking.
        
        Args:
            text (str): Input text to preprocess
            
        Returns:
            Tokenized input ready for model
        """
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

    def preprocess_text_only(self, text):
        """
        Text preprocessing without tokenization (for dataframes).
        
        Args:
            text (str): Input text to preprocess
            
        Returns:
            Preprocessed text string
        """
        text = text.lower()
        # Mask email addresses and URLs
        text = re.sub(r'\S+@\S+', '[EMAIL]', text)
        text = re.sub(r'http\S+', '[URL]', text)
        return text

    def predict_proba(self, texts):
        """
        Probability predictions for SHAP explanation.
        
        Args:
            texts (list): List of text strings
            
        Returns:
            numpy array of probabilities
        """
        inputs = [self.preprocess(text) for text in texts]
        with torch.no_grad():
            outputs = [
                self.model(**input_.to(self.device))[0].softmax(dim=1).cpu().numpy() 
                for input_ in inputs
            ]
        return np.vstack(outputs)

    @LATENCY_GAUGE.time()
    def predict(self, text):
        """
        Real-time prediction with uncertainty estimation.
        
        Args:
            text (str): Email text to classify
            
        Returns:
            dict: Prediction result with confidence and metadata
        """
        start_time = time.time()
        try:
            inputs = self.preprocess(text).to(self.device)
            with torch.no_grad():
                outputs = self.model(**inputs)
            probs = outputs[0].softmax(dim=1).cpu().numpy()[0]
            prediction = np.argmax(probs)
            
            # Active learning: Queue uncertain predictions
            if np.max(probs) < 0.8:  # Confidence threshold
                self.active_learning_queue.append({
                    "text": text, 
                    "confidence": float(np.max(probs))
                })
            
            label = "phishing" if prediction == 1 else "legitimate"
            PREDICTION_COUNTER.labels(result=label).inc()
            
            result = {
                "prediction": label,
                "confidence": float(np.max(probs)),
                "timestamp": datetime.utcnow().isoformat(),
                "model_version": self.version,
                "processing_time": time.time() - start_time
            }
            
            # Add SHAP values if explainer is enabled
            if self.explainer:
                try:
                    result["shap_values"] = self.explainer.shap_values([text])
                except Exception as e:
                    logger.warning(f"SHAP explanation failed: {e}")
            
            return result
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            raise

    def train(self, dataset, hyperparams):
        """
        Advanced training with hyperparameter optimization.
        
        Args:
            dataset: Dictionary with 'train' and 'test' datasets (HuggingFace format or pandas)
            hyperparams (dict): Hyperparameters for training
        """
        try:
            training_args = TrainingArguments(
                output_dir='./results',
                num_train_epochs=hyperparams.get('epochs', 3),
                per_device_train_batch_size=hyperparams.get('batch_size', 16),
                learning_rate=hyperparams.get('learning_rate', 2e-5),
                weight_decay=hyperparams.get('weight_decay', 0.01),
                evaluation_strategy="epoch",
                logging_dir='./logs',
                fp16=torch.cuda.is_available(),
                report_to=["tensorboard"],
                save_strategy="epoch",
                load_best_model_at_end=True
            )

            trainer = Trainer(
                model=self.model,
                args=training_args,
                train_dataset=dataset.get("train"),
                eval_dataset=dataset.get("test"),
                compute_metrics=self._compute_metrics
            )

            try:
                with mlflow.start_run():
                    trainer.train()
                    mlflow.log_params(hyperparams)
                    eval_results = trainer.evaluate()
                    mlflow.log_metrics(eval_results)
            except Exception as e:
                logger.warning(f"MLflow logging failed: {e}")
                trainer.train()

            # Update model version
            self.version = datetime.now().strftime("%Y%m%d%H%M%S")
            logger.info("Training completed successfully")
        except Exception as e:
            logger.error(f"Training failed: {e}")
            raise

    def optimize_hyperparameters(self, dataset, n_trials=20):
        """
        Automated hyperparameter tuning with Optuna.
        
        Args:
            dataset: HuggingFace dataset for optimization
            n_trials (int): Number of optimization trials
            
        Returns:
            dict: Best hyperparameters found
        """
        def objective(trial):
            hyperparams = {
                'learning_rate': trial.suggest_float('learning_rate', 1e-6, 1e-4, log=True),
                'batch_size': trial.suggest_categorical('batch_size', [8, 16, 32]),
                'epochs': trial.suggest_int('epochs', 1, 5),
                'weight_decay': trial.suggest_float('weight_decay', 0.0, 0.1)
            }
            try:
                self.train(dataset, hyperparams)
                
                # Evaluate on test set
                trainer = Trainer(
                    model=self.model,
                    eval_dataset=dataset["test"],
                    compute_metrics=self._compute_metrics
                )
                metrics = trainer.evaluate()
                return metrics.get('eval_f1', 0)
            except Exception as e:
                logger.error(f"Trial failed: {e}")
                return 0

        try:
            study = optuna.create_study(direction='maximize')
            study.optimize(objective, n_trials=n_trials)
            logger.info(f"Best hyperparameters: {study.best_params}")
            return study.best_params
        except Exception as e:
            logger.error(f"Hyperparameter optimization failed: {e}")
            return {}

    def _compute_metrics(self, eval_pred):
        """
        Custom metrics computation for Trainer.
        
        Args:
            eval_pred: EvalPrediction object with predictions and label_ids
            
        Returns:
            dict: Dictionary of metrics
        """
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)
        return {
            'accuracy': accuracy_score(labels, predictions),
            'f1': f1_score(labels, predictions, average='weighted', zero_division=0),
            'precision': precision_score(labels, predictions, average='weighted', zero_division=0),
            'recall': recall_score(labels, predictions, average='weighted', zero_division=0)
        }


# FastAPI Application
app = FastAPI(title="Phishing Detection API", version="1.0.0")
detector = None


@app.on_event("startup")
async def startup_event():
    """Initialize model and monitoring"""
    global detector
    try:
        detector = PhishingDetector()
        logger.info("Phishing detector loaded successfully")
        try:
            prometheus_client.start_http_server(8001)
            logger.info("Prometheus metrics server started on port 8001")
        except Exception as e:
            logger.warning(f"Prometheus server not started: {e}")
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise


class PredictionRequest(BaseModel):
    text: str


@app.post("/predict")
async def predict(request: PredictionRequest):
    """Predict if email is phishing or legitimate"""
    if not detector:
        raise HTTPException(status_code=503, detail="Model not initialized")
    try:
        return detector.predict(request.text)
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/model/version")
async def get_model_version():
    """Get current model version"""
    if not detector:
        raise HTTPException(status_code=503, detail="Model not initialized")
    return {
        "version": detector.version, 
        "device": str(detector.device),
        "model_type": "microsoft/deberta-v3-base"
    }


@app.get("/model/retrain")
async def retrain():
    """Trigger active learning retraining (placeholder)"""
    if not detector:
        raise HTTPException(status_code=503, detail="Model not initialized")
    try:
        queue_size = len(detector.active_learning_queue)
        logger.info(f"Retraining initiated with {queue_size} uncertain predictions")
        # Implement actual retraining logic here
        return {
            "status": "Retraining initiated", 
            "uncertain_samples": queue_size
        }
    except Exception as e:
        logger.error(f"Retraining error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "model_loaded": detector is not None,
        "timestamp": datetime.utcnow().isoformat()
    }


# Docker Management
class DockerManager:
    def __init__(self):
        try:
            self.client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
            self.client = None
    
    def deploy_new_version(self):
        """Automated container deployment"""
        if not self.client or not detector:
            logger.error("Cannot deploy: Docker or detector not available")
            return False
        try:
            self.client.images.build(
                path=".", 
                tag=f"phishing-detector:{detector.version}"
            )
            self.client.containers.run(
                image=f"phishing-detector:{detector.version}",
                ports={'8000': 8000},
                detach=True
            )
            logger.info(f"Deployed version {detector.version}")
            return True
        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            return False


if __name__ == "__main__":
    import uvicorn
    
    # Example usage for training (uncomment to use)
    """
    # Initialize detector
    detector = PhishingDetector()
    
    # Load and preprocess data
    df = pd.read_csv("phishing_emails.csv")
    
    # Preprocess text (text only, not tokenized)
    if swifter:
        df['text'] = df['text'].swifter.apply(lambda x: detector.preprocess_text_only(x))
    else:
        df['text'] = df['text'].apply(lambda x: detector.preprocess_text_only(x))
    
    # Split data
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)
    
    # Convert to HuggingFace dataset format
    from datasets import Dataset
    train_dataset = Dataset.from_pandas(train_df)
    test_dataset = Dataset.from_pandas(test_df)
    
    # Tokenize datasets
    def tokenize_function(examples):
        return detector.tokenizer(
            examples['text'],
            padding='max_length',
            truncation=True,
            max_length=512
        )
    
    train_dataset = train_dataset.map(tokenize_function, batched=True)
    test_dataset = test_dataset.map(tokenize_function, batched=True)
    
    dataset_dict = {'train': train_dataset, 'test': test_dataset}
    
    # Optimize hyperparameters
    best_params = detector.optimize_hyperparameters(dataset_dict, n_trials=10)
    
    # Train with optimal hyperparameters
    detector.train(dataset_dict, best_params)
    """
    
    # Start API server
    logger.info("Starting Phishing Detection API server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)