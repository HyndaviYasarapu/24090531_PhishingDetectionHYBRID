"""
Hybrid Phishing Detector
Combines rule-based and ML-based detection for optimal performance
"""

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pickle
from src.rule_based_detector_hy import RuleBasedDetector
from src.ml_detector_hy import MLDetector
from config import HYBRID_MODEL


class HybridDetector:
    """Hybrid detector combining rule-based and ML approaches"""
    
    def __init__(self, rule_based_detector_hy, ml_detector_hy, strategy='weighted'):
        """
        Initialize hybrid detector
        
        Args:
            rule_detector: RuleBasedDetector instance
            ml_detector: MLDetector instance
            strategy: Combination strategy ('weighted', 'voting', 'cascade')
        """
        self.rule_detector = rule_based_detector_hy
        self.ml_detector = ml_detector_hy
        self.strategy = strategy
        self.weights = {'rule': 0.3, 'ml': 0.7}  # Default weights
    
    def optimize_weights(self, X_val, y_val):
        """
        Optimize combination weights on validation set
        
        Args:
            X_val: Validation features
            y_val: Validation labels
        """
        print("\nOptimizing hybrid detector weights...")
        
        best_f1 = 0
        best_weights = None
        
        # Try different weight combinations
        for rule_weight in np.arange(0.0, 1.1, 0.1):
            ml_weight = 1.0 - rule_weight
            
            self.weights = {'rule': rule_weight, 'ml': ml_weight}
            predictions = self.predict(X_val)
            f1 = f1_score(y_val, predictions)
            
            if f1 > best_f1:
                best_f1 = f1
                best_weights = self.weights.copy()
        
        self.weights = best_weights
        print(f"Optimal weights: Rule={self.weights['rule']:.2f}, ML={self.weights['ml']:.2f}")
        print(f"Validation F1-score: {best_f1:.4f}")
    
    def predict_single(self, features, return_details=False):
        """
        Predict single URL using hybrid approach
        
        Args:
            features: Dictionary or Series of features
            return_details: If True, return detailed prediction info
        
        Returns:
            Prediction (0 or 1) or detailed dictionary
        """
        if isinstance(features, pd.Series):
            features_dict = features.to_dict()
            features_df = features.to_frame().T
        else:
            features_dict = features
            features_df = pd.DataFrame([features])
        
        # Get predictions from both detectors
        rule_score = self.rule_detector.predict_single(features_dict, return_score=True)
        ml_proba = self.ml_detector.predict_proba(features_df)[0, 1]
        
        if self.strategy == 'weighted':
            # Weighted combination
            combined_score = (
                self.weights['rule'] * rule_score +
                self.weights['ml'] * ml_proba
            )
            prediction = 1 if combined_score > 0.5 else 0
            
        elif self.strategy == 'voting':
            # Simple majority voting
            rule_pred = self.rule_detector.predict_single(features_dict)
            ml_pred = self.ml_detector.predict(features_df)[0]
            prediction = 1 if (rule_pred + ml_pred) > 0 else 0
            combined_score = (rule_score + ml_proba) / 2
            
        elif self.strategy == 'cascade':
            # Cascade: if rule-based is highly confident, use it; otherwise use ML
            if rule_score > 0.8:  # High confidence phishing
                prediction = 1
                combined_score = rule_score
            elif rule_score < 0.2:  # High confidence legitimate
                prediction = 0
                combined_score = rule_score
            else:  # Uncertain, use ML
                prediction = 1 if ml_proba > 0.5 else 0
                combined_score = ml_proba
        else:
            raise ValueError(f"Unknown strategy: {self.strategy}")
        
        if return_details:
            return {
                'prediction': prediction,
                'combined_score': combined_score,
                'rule_score': rule_score,
                'ml_score': ml_proba,
                'confidence': abs(combined_score - 0.5) * 2  # 0 to 1
            }
        
        return prediction
    
    def predict(self, X, return_details=False):
        """
        Predict multiple URLs
        
        Args:
            X: DataFrame of features
            return_details: If True, return detailed predictions
        
        Returns:
            Array of predictions or list of detailed dictionaries
        """
        if return_details:
            return [self.predict_single(row, return_details=True) 
                   for _, row in X.iterrows()]
        else:
            return np.array([self.predict_single(row) 
                           for _, row in X.iterrows()])
    
    def evaluate(self, X_test, y_test, show_comparison=True):
        """
        Evaluate hybrid detector
        
        Args:
            X_test: Test features
            y_test: Test labels
            show_comparison: Whether to compare with individual detectors
        
        Returns:
            Dictionary of metrics
        """
        print("\n" + "="*70)
        print(f"HYBRID DETECTOR EVALUATION (Strategy: {self.strategy})")
        print("="*70)
        
        # Hybrid predictions
        predictions = self.predict(X_test)
        
        metrics = {
            'accuracy': accuracy_score(y_test, predictions),
            'precision': precision_score(y_test, predictions, zero_division=0),
            'recall': recall_score(y_test, predictions, zero_division=0),
            'f1_score': f1_score(y_test, predictions, zero_division=0)
        }
        
        print(f"\nHybrid Detector Performance:")
        print(f"Weights: Rule={self.weights['rule']:.2f}, ML={self.weights['ml']:.2f}")
        print(f"Accuracy:  {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall:    {metrics['recall']:.4f}")
        print(f"F1-Score:  {metrics['f1_score']:.4f}")
        
        if show_comparison:
            # Compare with individual detectors
            print("\n" + "-"*70)
            print("COMPARISON WITH INDIVIDUAL DETECTORS")
            print("-"*70)
            
            rule_preds = self.rule_detector.predict(X_test)
            ml_preds = self.ml_detector.predict(X_test)
            
            comparison_data = {
                'Rule-Based': {
                    'accuracy': accuracy_score(y_test, rule_preds),
                    'precision': precision_score(y_test, rule_preds, zero_division=0),
                    'recall': recall_score(y_test, rule_preds, zero_division=0),
                    'f1_score': f1_score(y_test, rule_preds, zero_division=0)
                },
                'ML-Based': {
                    'accuracy': accuracy_score(y_test, ml_preds),
                    'precision': precision_score(y_test, ml_preds, zero_division=0),
                    'recall': recall_score(y_test, ml_preds, zero_division=0),
                    'f1_score': f1_score(y_test, ml_preds, zero_division=0)
                },
                'Hybrid': metrics
            }
            
            comparison_df = pd.DataFrame(comparison_data).T
            print("\n" + comparison_df.to_string())
            
            # Calculate improvements
            print("\n" + "-"*70)
            print("HYBRID IMPROVEMENTS")
            print("-"*70)
            
            for metric in ['accuracy', 'precision', 'recall', 'f1_score']:
                rule_value = comparison_data['Rule-Based'][metric]
                ml_value = comparison_data['ML-Based'][metric]
                hybrid_value = comparison_data['Hybrid'][metric]
                
                best_individual = max(rule_value, ml_value)
                improvement = ((hybrid_value - best_individual) / best_individual) * 100
                
                print(f"{metric.capitalize():12s}: {improvement:+.2f}% vs best individual")
        
        return metrics
    
    def analyze_predictions(self, X_test, y_test, n_samples=10):
        """
        Analyze detailed predictions on sample data
        
        Args:
            X_test: Test features
            y_test: Test labels
            n_samples: Number of samples to analyze
        """
        print("\n" + "="*70)
        print("DETAILED PREDICTION ANALYSIS")
        print("="*70)
        
        # Get detailed predictions
        detailed_preds = self.predict(X_test.head(n_samples), return_details=True)
        
        for idx, (pred_details, true_label) in enumerate(zip(detailed_preds, y_test.head(n_samples))):
            print(f"\nSample {idx + 1}:")
            print(f"  True Label:     {'Phishing' if true_label == 1 else 'Legitimate'}")
            print(f"  Prediction:     {'Phishing' if pred_details['prediction'] == 1 else 'Legitimate'}")
            print(f"  Correct:        {pred_details['prediction'] == true_label}")
            print(f"  Combined Score: {pred_details['combined_score']:.4f}")
            print(f"  Rule Score:     {pred_details['rule_score']:.4f}")
            print(f"  ML Score:       {pred_details['ml_score']:.4f}")
            print(f"  Confidence:     {pred_details['confidence']:.4f}")
    
    def save(self, filepath=None):
        """Save hybrid detector safely"""
        if filepath is None:
            filepath = HYBRID_MODEL
    
        data = {
            'strategy': self.strategy,
            'weights': self.weights,
            'rule_thresholds': self.rule_detector.thresholds,
            'ml_model': self.ml_detector.model  # or save ML separately if needed
        }
    
        with open(filepath, 'wb') as f:
            pickle.dump(data, f)
    
        print(f"\nHybrid detector saved to {filepath}")
    @classmethod
    def load(cls, filepath=None):
        """Load hybrid detector"""
        if filepath is None:
            filepath = HYBRID_MODEL
        
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        detector = cls(
            rule_detector_hy=data['rule_detector'],
            ml_detector_hy=data['ml_detector'],
            strategy=data['strategy']
        )
        detector.weights = data['weights']
        
        print(f"Hybrid detector loaded from {filepath}")
        return detector


if __name__ == "__main__":
    print("Hybrid Detector module loaded successfully!")
    print("Available strategies: weighted, voting, cascade")
