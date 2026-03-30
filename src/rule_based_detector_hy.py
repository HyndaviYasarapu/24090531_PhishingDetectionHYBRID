"""
Rule-Based Phishing Detector
Implements heuristic rules for phishing detection
"""

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pickle
import os

from config import (
    URL_LENGTH_THRESHOLD, SUBDOMAIN_COUNT_THRESHOLD,
    DOT_COUNT_THRESHOLD, HYPHEN_COUNT_THRESHOLD,
    RULE_BASED_MODEL
)

# =====================
# Top-level functions
# =====================
def check_url_length(features, threshold):
    return features['url_length'] > threshold

def check_has_ip(features):
    return features['has_ip'] == 1

def check_subdomain_count(features, threshold):
    return features['subdomain_count'] > threshold

def check_dot_count(features, threshold):
    return features['dot_count'] > threshold

def check_hyphen_count(features, threshold):
    return features['hyphen_count'] > threshold

def check_at_symbol(features):
    return features['at_symbol'] == 1

def check_double_slash_redirect(features):
    return features['double_slash_redirecting'] == 1

def check_prefix_suffix(features):
    return features['prefix_suffix'] == 1

def check_shortening_service(features):
    return features['shortening_service'] == 1

def check_suspicious_tld(features):
    return features['suspicious_tld'] == 1

def check_https(features):
    return features['has_https'] == 0

def check_dns_record(features):
    return features['has_dns_record'] == 0

def check_login_form(features):
    return features['has_login_form'] == 1

def check_suspicious_keywords(features):
    return features['suspicious_keywords_count'] > 3

def check_external_links(features):
    return features['num_internal_links'] > 0 and features['num_external_links'] > features['num_internal_links']


class RuleBasedDetector:
    """Rule-based phishing detection using heuristics"""
    
    def __init__(self):
        self.rules = []
        self.thresholds = {}
        self.rule_weights = {}
    
    def optimize_thresholds(self, X_train, y_train):
        """
        Optimize rule thresholds based on training data
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        print("Optimizing rule-based thresholds...")
        
        # Analyze feature distributions for legitimate vs phishing
        phishing_data = X_train[y_train == 1]
        legitimate_data = X_train[y_train == 0]
        
        # Optimize thresholds for key features
        self.thresholds['url_length'] = self._find_optimal_threshold(
            legitimate_data['url_length'], 
            phishing_data['url_length']
        )
        
        self.thresholds['subdomain_count'] = self._find_optimal_threshold(
            legitimate_data['subdomain_count'],
            phishing_data['subdomain_count']
        )
        
        self.thresholds['dot_count'] = self._find_optimal_threshold(
            legitimate_data['dot_count'],
            phishing_data['dot_count']
        )
        
        self.thresholds['hyphen_count'] = self._find_optimal_threshold(
            legitimate_data['hyphen_count'],
            phishing_data['hyphen_count']
        )
        
        print("\nOptimized Thresholds:")
        for feature, threshold in self.thresholds.items():
            print(f"  {feature}: {threshold}")
        
        # Define rules with optimized thresholds
        self._define_rules()
    
    def _find_optimal_threshold(self, legitimate_values, phishing_values):
        """Find threshold that best separates legitimate from phishing"""
        # Use mean + std as threshold
        legit_mean = legitimate_values.mean()
        legit_std = legitimate_values.std()
        phish_mean = phishing_values.mean()
        
        # Threshold is midpoint between means, adjusted for std
        threshold = (legit_mean + phish_mean) / 2
        
        return max(threshold, legit_mean + legit_std)
    
    def _define_rules(self):
        """Define detection rules"""
        self.rules = [
        {'name': 'URL Length', 'check': lambda x: check_url_length(x, self.thresholds.get('url_length', 75)), 'weight': 1.5},
        {'name': 'IP Address in URL', 'check': check_has_ip, 'weight': 3.0},
        {'name': 'Excessive Subdomains', 'check': lambda x: check_subdomain_count(x, self.thresholds.get('subdomain_count', 2)), 'weight': 2.0},
        {'name': 'Excessive Dots', 'check': lambda x: check_dot_count(x, self.thresholds.get('dot_count', 3)), 'weight': 1.0},
        {'name': 'Excessive Hyphens', 'check': lambda x: check_hyphen_count(x, self.thresholds.get('hyphen_count', 1)), 'weight': 1.5},
        {'name': 'At Symbol (@)', 'check': check_at_symbol, 'weight': 2.5},
        {'name': 'Double Slash Redirect', 'check': check_double_slash_redirect, 'weight': 2.0},
        {'name': 'Prefix/Suffix with Hyphen', 'check': check_prefix_suffix, 'weight': 1.5},
        {'name': 'URL Shortening Service', 'check': check_shortening_service, 'weight': 2.0},
        {'name': 'Suspicious TLD', 'check': check_suspicious_tld, 'weight': 2.5},
        {'name': 'No HTTPS', 'check': check_https, 'weight': 1.0},
        {'name': 'No DNS Record', 'check': check_dns_record, 'weight': 3.0},
        {'name': 'Has Login Form', 'check': check_login_form, 'weight': 1.5},
        {'name': 'Suspicious Keywords', 'check': check_suspicious_keywords, 'weight': 1.0},
        {'name': 'High External Links', 'check': check_external_links, 'weight': 0.5}
    ]
    
    def predict_single(self, features, return_score=False):
        """
        Predict single URL
        
        Args:
            features: Dictionary of features
            return_score: If True, return risk score instead of binary prediction
        
        Returns:
            Prediction (0=legitimate, 1=phishing) or risk score
        """
        risk_score = 0
        max_score = sum(rule['weight'] for rule in self.rules)
        
        for rule in self.rules:
            try:
                if rule['check'](features):
                    risk_score += rule['weight']
            except (KeyError, TypeError):
                # Feature not available, skip rule
                continue
        
        # Normalize score to 0-1
        normalized_score = risk_score / max_score if max_score > 0 else 0
        
        if return_score:
            return normalized_score
        else:
            # Threshold: if risk score > 30% of max, classify as phishing
            return 1 if normalized_score > 0.3 else 0
    
    def predict(self, X, return_scores=False):
        """
        Predict multiple URLs
        
        Args:
            X: DataFrame of features
            return_scores: If True, return risk scores instead of binary predictions
        
        Returns:
            Array of predictions or risk scores
        """
        if self.rules is None or len(self.rules) == 0:
            self._define_rules()
        
        predictions = []
        
        for idx, row in X.iterrows():
            pred = self.predict_single(row.to_dict(), return_score=return_scores)
            predictions.append(pred)
        
        return np.array(predictions)
    
    def evaluate(self, X_test, y_test):
        """
        Evaluate rule-based detector
        
        Args:
            X_test: Test features
            y_test: Test labels
        
        Returns:
            Dictionary of metrics
        """
        print("\n" + "="*50)
        print("RULE-BASED DETECTOR EVALUATION")
        print("="*50)
        
        predictions = self.predict(X_test)
        
        metrics = {
            'accuracy': accuracy_score(y_test, predictions),
            'precision': precision_score(y_test, predictions, zero_division=0),
            'recall': recall_score(y_test, predictions, zero_division=0),
            'f1_score': f1_score(y_test, predictions, zero_division=0)
        }
        
        print(f"\nAccuracy:  {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall:    {metrics['recall']:.4f}")
        print(f"F1-Score:  {metrics['f1_score']:.4f}")
        
        # Show which rules triggered most often
        print("\n" + "-"*50)
        print("Rule Trigger Frequency:")
        print("-"*50)
        
        rule_triggers = {rule['name']: 0 for rule in self.rules}
        
        for idx, row in X_test.iterrows():
            for rule in self.rules:
                try:
                    if rule['check'](row.to_dict()):
                        rule_triggers[rule['name']] += 1
                except (KeyError, TypeError):
                    continue
        
        for rule_name, count in sorted(rule_triggers.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / len(X_test)) * 100
            print(f"{rule_name:30s}: {count:5d} ({percentage:5.1f}%)")
        
        return metrics
    
    def save(self, filepath=None):
        """Save rule-based detector"""
        if filepath is None:
            filepath = RULE_BASED_MODEL
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump({
            'thresholds': self.thresholds
            }, f)
        
        print(f"\nRule-based detector saved to {filepath}")
    
    @classmethod
    def load(cls, filepath=None):
        """Load rule-based detector"""
        if filepath is None:
            filepath = RULE_BASED_MODEL
        
        detector = cls()
        
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
            
        detector.thresholds = data['thresholds']
        # Recreate rules using thresholds
        detector._define_rules()
        print(f"Rule-based detector loaded from {filepath}")
        return detector


if __name__ == "__main__":
    # Test rule-based detector
    print("Testing Rule-Based Detector...")
    
    # Create sample data
    sample_features = pd.DataFrame({
        'url_length': [25, 80],
        'has_ip': [0, 1],
        'subdomain_count': [1, 4],
        'dot_count': [2, 8],
        'hyphen_count': [0, 5],
        'at_symbol': [0, 1],
        'double_slash_redirecting': [0, 1],
        'prefix_suffix': [0, 1],
        'shortening_service': [0, 0],
        'suspicious_tld': [0, 1],
        'has_https': [1, 0],
        'has_dns_record': [1, 0],
        'has_login_form': [0, 1],
        'suspicious_keywords_count': [0, 5],
        'num_external_links': [10, 50],
        'num_internal_links': [20, 5]
    })
    
    detector = RuleBasedDetector()
    detector._define_rules()
    
    predictions = detector.predict(sample_features, return_scores=True)
    print(f"\nRisk Scores: {predictions}")
    
    binary_preds = detector.predict(sample_features)
    print(f"Predictions: {binary_preds}")
