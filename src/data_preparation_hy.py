"""
Data Preparation Module
Handles loading and preprocessing of phishing dataset from Kaggle
Supports automatic download via Kaggle API
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import os
import subprocess
import zipfile
import glob

from config import (
    DATA_DIR, RAW_DATA_FILE, PROCESSED_DATA_FILE,
    TRAIN_DATA_FILE, TEST_DATA_FILE, TEST_SIZE, RANDOM_STATE
)


class DataPreparation:
    """Handle data loading and preprocessing"""
    
    def __init__(self):
        self.scaler = StandardScaler()
    
    def download_kaggle_dataset(self, dataset_name='shashwatwork/web-page-phishing-detection-dataset', auto=False):
        """
        Download dataset from Kaggle automatically or show instructions
        
        Args:
            dataset_name: Kaggle dataset identifier (default: recommended phishing dataset)
            auto: If True, attempts automatic download via Kaggle API
        
        Recommended datasets:
        1. "shashwatwork/web-page-phishing-detection-dataset" (11,430 URLs) - RECOMMENDED
        2. "taruntiwarihp/phishing-site-urls" (5,000+ URLs)
        3. "sid321axn/malicious-urls-dataset" (650,000+ URLs)
        """
        
        if auto:
            try:
                print(f"\nAttempting to download Kaggle dataset: {dataset_name}")
                print("Checking Kaggle API credentials...")
                
                # Check if kaggle is installed
                try:
                    import kaggle
                    print("✓ Kaggle package found")
                except ImportError:
                    print("✗ Kaggle package not found. Installing...")
                    subprocess.run(['pip', 'install', 'kaggle'], check=True)
                    import kaggle
                
                # Create data directory
                os.makedirs(DATA_DIR, exist_ok=True)
                
                # Download dataset
                print(f"Downloading {dataset_name}...")
                from kaggle.api.kaggle_api_extended import KaggleApi
                api = KaggleApi()
                api.authenticate()
                
                # Download to data directory
                api.dataset_download_files(dataset_name, path=DATA_DIR, unzip=True)
                
                print("✓ Dataset downloaded successfully!")
                
                # Find the CSV file
                csv_files = glob.glob(os.path.join(DATA_DIR, '*.csv'))
                if csv_files:
                    # Rename to standard filename
                    source_file = csv_files[0]
                    if source_file != RAW_DATA_FILE:
                        os.rename(source_file, RAW_DATA_FILE)
                        print(f"✓ Renamed {os.path.basename(source_file)} to phishing_dataset.csv")
                    
                    print(f"\n✓ Dataset ready at: {RAW_DATA_FILE}")
                    return True
                else:
                    print("✗ No CSV file found in downloaded data")
                    return False
                    
            except Exception as e:
                print(f"\n✗ Automatic download failed: {e}")
                print("\nFalling back to manual instructions...")
                auto = False
        
        if not auto:
            print("=" * 70)
            print("KAGGLE DATASET DOWNLOAD INSTRUCTIONS")
            print("=" * 70)
            print("\nOption 1: Using Kaggle API (Recommended)")
            print("-" * 70)
            print("1. Install kaggle: pip install kaggle")
            print("2. Set up Kaggle API credentials:")
            print("   - Go to https://www.kaggle.com/account")
            print("   - Click 'Create New API Token'")
            print("   - Place kaggle.json in ~/.kaggle/")
            print("3. Run one of these commands:")
            print("\n   # Dataset 1: Phishing Website Detection (RECOMMENDED - 11,430 URLs)")
            print("   kaggle datasets download -d shashwatwork/web-page-phishing-detection-dataset")
            print("   unzip web-page-phishing-detection-dataset.zip -d data/")
            print("\n   # Dataset 2: Phishing URLs Dataset (5,000+ URLs)")
            print("   kaggle datasets download -d taruntiwarihp/phishing-site-urls")
            print("   unzip phishing-site-urls.zip -d data/")
            print("\n   # Dataset 3: Malicious URLs Dataset (650,000+ URLs)")
            print("   kaggle datasets download -d sid321axn/malicious-urls-dataset")
            print("   unzip malicious-urls-dataset.zip -d data/")
            print("\n4. Rename the CSV file to 'phishing_dataset.csv' in data/ directory")
            print("\nOption 2: Manual Download from Browser")
            print("-" * 70)
            print("1. Visit: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset")
            print("2. Click 'Download' button")
            print("3. Extract CSV file")
            print("4. Place in data/ directory as 'phishing_dataset.csv'")
            print("\nExpected CSV format:")
            print("- Must have 'url' column with URLs")
            print("- Must have 'label' column (0=legitimate, 1=phishing)")
            print("  OR 'status' column ('legitimate'/'phishing')")
            print("=" * 70)
            return False
    
    def load_raw_data(self, filepath=None, try_auto_download=True):
        """
        Load raw phishing dataset from Kaggle
        
        Args:
            filepath: Path to CSV file. If None, uses default from config
            try_auto_download: If True and file not found, attempts Kaggle download
        
        Returns:
            pandas DataFrame
        """
        if filepath is None:
            filepath = RAW_DATA_FILE
        
        if not os.path.exists(filepath):
            print(f"\nDataset not found at {filepath}")
            
            if try_auto_download:
                print("\nAttempting automatic download from Kaggle...")
                success = self.download_kaggle_dataset(auto=True)
                
                if not success:
                    print("\nAutomatic download failed.")
                    self.download_kaggle_dataset(auto=False)
                    raise FileNotFoundError(
                        f"Please download dataset manually and place it at {filepath}"
                    )
            else:
                self.download_kaggle_dataset(auto=False)
                raise FileNotFoundError(
                    f"Please download dataset and place it at {filepath}"
                )
        
        print(f"\nLoading Kaggle dataset from {filepath}...")
        df = pd.read_csv(filepath)
        
        # Standardize column names
        df.columns = df.columns.str.lower().str.strip()
        
        print(f"Initial dataset shape: {df.shape}")
        print(f"Columns found: {df.columns.tolist()}")
        
        # Handle different label formats from various Kaggle datasets
        if 'label' not in df.columns:
            if 'status' in df.columns:
                # Convert status to label (0=legitimate, 1=phishing)
                print("Converting 'status' column to 'label'...")
                df['label'] = df['status'].apply(
                    lambda x: 1 if str(x).lower() in ['phishing', 'bad', '1', 'malicious'] else 0
                )
            elif 'class' in df.columns:
                print("Converting 'class' column to 'label'...")
                df['label'] = df['class'].apply(
                    lambda x: 1 if str(x).lower() in ['phishing', 'bad', '1', 'malicious'] else 0
                )
            elif 'type' in df.columns:
                print("Converting 'type' column to 'label'...")
                df['label'] = df['type'].apply(
                    lambda x: 1 if str(x).lower() in ['phishing', 'bad', '1', 'malicious'] else 0
                )
        
        # Ensure we have required columns
        if 'url' not in df.columns:
            # Try to find URL column with different name
            url_columns = [col for col in df.columns if 'url' in col.lower() or 'link' in col.lower() or 'website' in col.lower()]
            if url_columns:
                print(f"Found URL column as '{url_columns[0]}', renaming to 'url'")
                df['url'] = df[url_columns[0]]
            else:
                raise ValueError("No URL column found in Kaggle dataset")
        
        if 'label' not in df.columns:
            raise ValueError("No label column found. Kaggle dataset must have 'label', 'status', 'class', or 'type' column")
        
        # Ensure label is binary
        df['label'] = df['label'].astype(int)
        df = df[df['label'].isin([0, 1])]
        
        print(f"\nKaggle dataset loaded successfully!")
        print(f"Final shape: {df.shape}")
        print(f"\nClass distribution:")
        print(df['label'].value_counts())
        print(f"\nLegitimate URLs: {(df['label'] == 0).sum()} ({(df['label'] == 0).sum()/len(df)*100:.1f}%)")
        print(f"Phishing URLs: {(df['label'] == 1).sum()} ({(df['label'] == 1).sum()/len(df)*100:.1f}%)")
        
        return df
    
    def clean_data(self, df):
        """
        Clean and validate dataset
        
        Args:
            df: pandas DataFrame
        
        Returns:
            Cleaned DataFrame
        """
        print("\nCleaning data...")
        
        initial_size = len(df)
        
        # Remove duplicates
        df = df.drop_duplicates(subset=['url'])
        print(f"Removed {initial_size - len(df)} duplicate URLs")
        
        # Remove missing values
        df = df.dropna(subset=['url', 'label'])
        
        # Remove empty URLs
        df = df[df['url'].str.strip() != '']
        
        # Ensure label is binary (0 or 1)
        df['label'] = df['label'].astype(int)
        df = df[df['label'].isin([0, 1])]
        
        print(f"Final dataset size: {len(df)}")
        print(f"Legitimate: {(df['label'] == 0).sum()}")
        print(f"Phishing: {(df['label'] == 1).sum()}")
        
        return df
    
    def load_or_extract_features(self, df, force_extract=False):
        """
        Load preprocessed features or extract from URLs
        
        Args:
            df: DataFrame with URLs and labels
            force_extract: If True, extract features even if processed file exists
        
        Returns:
            DataFrame with features
        """
        if os.path.exists(PROCESSED_DATA_FILE) and not force_extract:
            print(f"\nLoading preprocessed features from {PROCESSED_DATA_FILE}...")
            features_df = pd.read_csv(PROCESSED_DATA_FILE)
            print(f"Loaded {len(features_df)} samples with {len(features_df.columns)} features")
            return features_df
        
        print("\nExtracting features from URLs...")
        print("This may take a while depending on dataset size...")
        print("Consider extracting features from a sample first for testing.")
        
        from src.feature_extraction import extract_features_from_dataset
        
        features_df = extract_features_from_dataset(df)
        
        # Save processed features
        os.makedirs(DATA_DIR, exist_ok=True)
        features_df.to_csv(PROCESSED_DATA_FILE, index=False)
        print(f"\nSaved processed features to {PROCESSED_DATA_FILE}")
        
        return features_df
    
    def prepare_train_test_split(self, features_df, save=True):
        """
        Split data into train and test sets
        
        Args:
            features_df: DataFrame with features and label
            save: Whether to save train/test splits
        
        Returns:
            X_train, X_test, y_train, y_test
        """
        print("\nPreparing train-test split...")
        
        # Separate features and labels
        X = features_df.drop('label', axis=1)
        y = features_df['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
        )
        
        print(f"Training set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        print(f"\nTraining set class distribution:")
        print(y_train.value_counts())
        print(f"\nTest set class distribution:")
        print(y_test.value_counts())
        
        if save:
            # Save splits
            os.makedirs(DATA_DIR, exist_ok=True)
            train_df = pd.concat([X_train, y_train], axis=1)
            test_df = pd.concat([X_test, y_test], axis=1)
            
            train_df.to_csv(TRAIN_DATA_FILE, index=False)
            test_df.to_csv(TEST_DATA_FILE, index=False)
            print(f"\nSaved train data to {TRAIN_DATA_FILE}")
            print(f"Saved test data to {TEST_DATA_FILE}")
        
        return X_train, X_test, y_train, y_test
    
    def scale_features(self, X_train, X_test):
        """
        Scale features using StandardScaler
        
        Args:
            X_train: Training features
            X_test: Test features
        
        Returns:
            Scaled X_train, X_test
        """
        print("\nScaling features...")
        
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Convert back to DataFrame to preserve feature names
        X_train_scaled = pd.DataFrame(
            X_train_scaled, 
            columns=X_train.columns, 
            index=X_train.index
        )
        X_test_scaled = pd.DataFrame(
            X_test_scaled, 
            columns=X_test.columns, 
            index=X_test.index
        )
        
        return X_train_scaled, X_test_scaled


def create_sample_dataset(n_samples=1000):
    """
    Create a small sample dataset for testing
    Uses a subset of known legitimate and phishing URLs
    """
    print("Creating sample dataset for testing...")
    
    legitimate_urls = [
        "https://www.google.com",
        "https://www.facebook.com",
        "https://www.amazon.com",
        "https://www.wikipedia.org",
        "https://www.github.com",
        "https://www.stackoverflow.com",
        "https://www.reddit.com",
        "https://www.twitter.com",
        "https://www.linkedin.com",
        "https://www.youtube.com"
    ]
    
    phishing_patterns = [
        "http://secure-{}.com/login",
        "http://{}-verify.tk/account",
        "http://www.{}-update.ml/signin",
        "http://192.168.1.{}/admin",
        "http://{}-support.ga/verify"
    ]
    
    companies = ["paypal", "amazon", "microsoft", "apple", "bank", "ebay"]
    
    urls = []
    labels = []
    
    # Generate legitimate URLs (repeat to reach sample size)
    for _ in range(n_samples // 2):
        url = legitimate_urls[np.random.randint(0, len(legitimate_urls))]
        urls.append(url)
        labels.append(0)
    
    # Generate phishing URLs
    for _ in range(n_samples // 2):
        pattern = phishing_patterns[np.random.randint(0, len(phishing_patterns))]
        company = companies[np.random.randint(0, len(companies))]
        url = pattern.format(company)
        urls.append(url)
        labels.append(1)
    
    df = pd.DataFrame({'url': urls, 'label': labels})
    
    # Save sample dataset
    os.makedirs(DATA_DIR, exist_ok=True)
    sample_file = os.path.join(DATA_DIR, 'sample_dataset.csv')
    df.to_csv(sample_file, index=False)
    print(f"Sample dataset created: {sample_file}")
    print(f"Size: {len(df)} URLs")
    
    return df


if __name__ == "__main__":
    # Test data preparation
    prep = DataPreparation()
    
    # Show download instructions
    prep.download_kaggle_dataset()
    
    # Create sample dataset for testing
    sample_df = create_sample_dataset(100)
    print("\nSample dataset created successfully!")
    print(sample_df.head())
