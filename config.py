"""
Configuration file for Phishing Detection System
"""

import os

# Project Paths
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
RESULTS_DIR = os.path.join(PROJECT_ROOT, 'results')

# Data Files
RAW_DATA_FILE = os.path.join(DATA_DIR, 'phishing_dataset.csv')
PROCESSED_DATA_FILE = os.path.join(DATA_DIR, 'processed_features.csv')
TRAIN_DATA_FILE = os.path.join(DATA_DIR, 'train_data.csv')
TEST_DATA_FILE = os.path.join(DATA_DIR, 'test_data.csv')

# Model Files
RULE_BASED_MODEL = os.path.join(MODELS_DIR, 'rule_based_detector.pkl')
ML_MODEL = os.path.join(MODELS_DIR, 'ml_classifier.pkl')
HYBRID_MODEL = os.path.join(MODELS_DIR, 'hybrid_detector.pkl')
SCALER_FILE = os.path.join(MODELS_DIR, 'feature_scaler.pkl')

# Feature Engineering
TIMEOUT_SECONDS = 5  # Timeout for web requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# Model Parameters
TEST_SIZE = 0.2
RANDOM_STATE = 42
CV_FOLDS = 5

# Rule-Based Thresholds (will be optimized from data)
URL_LENGTH_THRESHOLD = 54
SUBDOMAIN_COUNT_THRESHOLD = 3
DOT_COUNT_THRESHOLD = 5
HYPHEN_COUNT_THRESHOLD = 3

# Feature Categories
URL_FEATURES = [
    'url_length',
    'has_ip',
    'subdomain_count',
    'dot_count',
    'hyphen_count',
    'at_symbol',
    'double_slash_redirecting',
    'prefix_suffix',
    'shortening_service',
    'suspicious_tld'
]

DOMAIN_FEATURES = [
    'has_https',
    'domain_age_days',
    'has_dns_record',
]

CONTENT_FEATURES = [
    'num_external_links',
    'num_internal_links',
    'has_form',
    'num_scripts',
    'num_iframes',
    'has_login_form',
    'suspicious_keywords_count'
]

LEXICAL_FEATURES = [
    'digit_count',
    'letter_count',
    'special_char_count',
    'entropy'
]

ALL_FEATURES = URL_FEATURES + DOMAIN_FEATURES + CONTENT_FEATURES + LEXICAL_FEATURES

# Suspicious Keywords
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'update', 'confirm',
    'secure', 'banking', 'suspended', 'password', 'credential'
]

# Suspicious TLDs
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work'
]

# URL Shortening Services
SHORTENING_SERVICES = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co',
    'is.gd', 'buff.ly', 'adf.ly', 'short.link'
]

# Machine Learning Algorithms to Compare
ML_ALGORITHMS = {
    'Random Forest': {
        'n_estimators': [50, 100, 200],
        'max_depth': [10, 20, None],
        'min_samples_split': [2, 5, 10]
    },
    'SVM': {
        'C': [0.1, 1, 10],
        'kernel': ['rbf', 'linear'],
        'gamma': ['scale', 'auto']
    },
    'Logistic Regression': {
        'C': [0.1, 1, 10],
        'penalty': ['l2'],
        'solver': ['lbfgs', 'liblinear']
    }
}
