"""
Machine Learning Based Phishing Detector
Implements and compares multiple ML algorithms
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score, roc_curve
)
from imblearn.over_sampling import SMOTE
import pickle
import matplotlib.pyplot as plt
import seaborn as sns

from config import ML_ALGORITHMS, ML_MODEL, CV_FOLDS, RANDOM_STATE, RESULTS_DIR
import os


class MLDetector:
    """Machine Learning based phishing detector"""
    
    def __init__(self, algorithm='Random Forest'):
        self.algorithm = algorithm
        self.model = None
        self.best_params = None
        self.feature_importance = None
    
    def handle_class_imbalance(self, X_train, y_train, method='smote'):
        """
        Handle class imbalance in training data
        
        Args:
            X_train: Training features
            y_train: Training labels
            method: 'smote' or 'class_weight'
        
        Returns:
            Balanced X_train, y_train (if SMOTE) or None (if class_weight)
        """
        # Check class distribution
        class_counts = pd.Series(y_train).value_counts()
        print(f"\nOriginal class distribution:")
        print(class_counts)
        
        imbalance_ratio = class_counts.max() / class_counts.min()
        print(f"Imbalance ratio: {imbalance_ratio:.2f}")
        
        if imbalance_ratio > 1.5:
            if method == 'smote':
                print("Applying SMOTE for class balancing...")
                smote = SMOTE(random_state=RANDOM_STATE)
                X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)
                
                print(f"\nBalanced class distribution:")
                print(pd.Series(y_train_balanced).value_counts())
                
                return X_train_balanced, y_train_balanced
            elif method == 'class_weight':
                print("Will use class_weight='balanced' in model training")
                return None, None
        else:
            print("Classes are relatively balanced, no resampling needed")
            return None, None
    
    def train(self, X_train, y_train, use_grid_search=True, balance_method='smote'):
        """
        Train ML model with hyperparameter tuning
        
        Args:
            X_train: Training features
            y_train: Training labels
            use_grid_search: Whether to use grid search for hyperparameter tuning
            balance_method: Method to handle class imbalance ('smote' or 'class_weight')
        """
        print("\n" + "="*70)
        print(f"TRAINING {self.algorithm.upper()} MODEL")
        print("="*70)
        
        # Handle class imbalance
        X_balanced, y_balanced = self.handle_class_imbalance(
            X_train, y_train, method=balance_method
        )
        
        if X_balanced is not None:
            X_train, y_train = X_balanced, y_balanced
        
        # Initialize model
        if self.algorithm == 'Random Forest':
            base_model = RandomForestClassifier(random_state=RANDOM_STATE)
            param_grid = ML_ALGORITHMS['Random Forest']
        elif self.algorithm == 'SVM':
            base_model = SVC(random_state=RANDOM_STATE, probability=True)
            param_grid = ML_ALGORITHMS['SVM']
        elif self.algorithm == 'Logistic Regression':
            base_model = LogisticRegression(random_state=RANDOM_STATE, max_iter=1000)
            param_grid = ML_ALGORITHMS['Logistic Regression']
        else:
            raise ValueError(f"Unknown algorithm: {self.algorithm}")
        
        if use_grid_search and param_grid:
            print(f"\nPerforming Grid Search with {CV_FOLDS}-fold cross-validation...")
            print(f"Parameter grid: {param_grid}")
            
            grid_search = GridSearchCV(
                base_model,
                param_grid,
                cv=CV_FOLDS,
                scoring='f1',
                n_jobs=-1,
                verbose=1
            )
            
            grid_search.fit(X_train, y_train)
            
            self.model = grid_search.best_estimator_
            self.best_params = grid_search.best_params_
            
            print(f"\nBest parameters: {self.best_params}")
            print(f"Best cross-validation F1-score: {grid_search.best_score_:.4f}")
        else:
            print("\nTraining model with default parameters...")
            self.model = base_model
            self.model.fit(X_train, y_train)
        
        # Get feature importance (if available)
        if hasattr(self.model, 'feature_importances_'):
            self.feature_importance = pd.DataFrame({
                'feature': X_train.columns,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            print("\nTop 10 Most Important Features:")
            print(self.feature_importance.head(10).to_string(index=False))
        
        # Cross-validation scores
        cv_scores = cross_val_score(self.model, X_train, y_train, cv=CV_FOLDS, scoring='f1')
        print(f"\nCross-validation F1-scores: {cv_scores}")
        print(f"Mean CV F1-score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        print(f"\n{self.algorithm} model training completed!")
    
    def predict(self, X):
        """Make predictions"""
        if self.model is None:
            raise ValueError("Model not trained yet!")
        return self.model.predict(X)
    
    def predict_proba(self, X):
        """Predict probabilities"""
        if self.model is None:
            raise ValueError("Model not trained yet!")
        return self.model.predict_proba(X)
    
    def evaluate(self, X_test, y_test, save_plots=True):
        """
        Evaluate ML model
        
        Args:
            X_test: Test features
            y_test: Test labels
            save_plots: Whether to save visualization plots
        
        Returns:
            Dictionary of metrics
        """
        print("\n" + "="*70)
        print(f"{self.algorithm.upper()} MODEL EVALUATION")
        print("="*70)
        
        # Predictions
        y_pred = self.predict(X_test)
        y_pred_proba = self.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1_score': f1_score(y_test, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, y_pred_proba)
        }
        
        print(f"\nPerformance Metrics:")
        print(f"Accuracy:  {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall:    {metrics['recall']:.4f}")
        print(f"F1-Score:  {metrics['f1_score']:.4f}")
        print(f"ROC-AUC:   {metrics['roc_auc']:.4f}")
        
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        print(f"\nConfusion Matrix:")
        print(f"                 Predicted")
        print(f"                 Legit  Phish")
        print(f"Actual Legit     {cm[0][0]:5d}  {cm[0][1]:5d}")
        print(f"       Phish     {cm[1][0]:5d}  {cm[1][1]:5d}")
        
        if save_plots:
            self._plot_results(y_test, y_pred, y_pred_proba, cm)
        
        return metrics
    
    def _plot_results(self, y_test, y_pred, y_pred_proba, cm):
        """Create and save evaluation plots"""
        os.makedirs(RESULTS_DIR, exist_ok=True)
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        
        # Confusion Matrix
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0],
                    xticklabels=['Legitimate', 'Phishing'],
                    yticklabels=['Legitimate', 'Phishing'])
        axes[0].set_xlabel('Predicted')
        axes[0].set_ylabel('Actual')
        axes[0].set_title(f'{self.algorithm} - Confusion Matrix')
        
        # ROC Curve
        fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        
        axes[1].plot(fpr, tpr, color='darkorange', lw=2,
                    label=f'ROC curve (AUC = {roc_auc:.4f})')
        axes[1].plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        axes[1].set_xlim([0.0, 1.0])
        axes[1].set_ylim([0.0, 1.05])
        axes[1].set_xlabel('False Positive Rate')
        axes[1].set_ylabel('True Positive Rate')
        axes[1].set_title(f'{self.algorithm} - ROC Curve')
        axes[1].legend(loc='lower right')
        axes[1].grid(alpha=0.3)
        
        plt.tight_layout()
        
        plot_file = os.path.join(RESULTS_DIR, f'{self.algorithm.lower().replace(" ", "_")}_evaluation.png')
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        print(f"\nEvaluation plots saved to {plot_file}")
        plt.close()
        
        # Feature Importance Plot (if available)
        if self.feature_importance is not None:
            plt.figure(figsize=(10, 8))
            top_features = self.feature_importance.head(15)
            plt.barh(range(len(top_features)), top_features['importance'])
            plt.yticks(range(len(top_features)), top_features['feature'])
            plt.xlabel('Importance')
            plt.title(f'{self.algorithm} - Top 15 Feature Importances')
            plt.gca().invert_yaxis()
            plt.tight_layout()
            
            importance_file = os.path.join(RESULTS_DIR, 
                                          f'{self.algorithm.lower().replace(" ", "_")}_feature_importance.png')
            plt.savefig(importance_file, dpi=300, bbox_inches='tight')
            print(f"Feature importance plot saved to {importance_file}")
            plt.close()
    
    def save(self, filepath=None):
        """Save trained model"""
        if filepath is None:
            filepath = ML_MODEL
        
        if self.model is None:
            raise ValueError("No model to save!")
        
        with open(filepath, 'wb') as f:
            pickle.dump({
                'algorithm': self.algorithm,
                'model': self.model,
                'best_params': self.best_params,
                'feature_importance': self.feature_importance
            }, f)
        
        print(f"\nModel saved to {filepath}")
    
    @classmethod
    def load(cls, filepath=None):
        """Load trained model"""
        if filepath is None:
            filepath = ML_MODEL
        
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        detector = cls(algorithm=data['algorithm'])
        detector.model = data['model']
        detector.best_params = data['best_params']
        detector.feature_importance = data['feature_importance']
        
        print(f"Model loaded from {filepath}")
        return detector


def compare_algorithms_all_hyn(X_train, X_test, y_train, y_test):
    """
    Train and compare multiple ML algorithms
    
    Returns:
        Dictionary of results for each algorithm
    """
    algorithms = ['Random Forest', 'SVM', 'Logistic Regression']
    results = {}
    
    for algo in algorithms:
        print("\n" + "="*70)
        print(f"TRAINING AND EVALUATING {algo.upper()}")
        print("="*70)
        
        detector = MLDetector(algorithm=algo)
        detector.train(X_train, y_train, use_grid_search=True)
        metrics = detector.evaluate(X_test, y_test)
        
        results[algo] = {
            'detector': detector,
            'metrics': metrics
        }
    
    # Compare results
    print("\n" + "="*70)
    print("ALGORITHM COMPARISON")
    print("="*70)
    
    comparison_df = pd.DataFrame({
        algo: result['metrics'] for algo, result in results.items()
    }).T
    
    print("\n" + comparison_df.to_string())
    
    # Find best algorithm
    best_algo = comparison_df['f1_score'].idxmax()
    print(f"\nBest Algorithm: {best_algo}")
    print(f"F1-Score: {comparison_df.loc[best_algo, 'f1_score']:.4f}")
    
    return results, best_algo


if __name__ == "__main__":
    print("ML Detector module loaded successfully!")
    print("Available algorithms:", list(ML_ALGORITHMS.keys()))
