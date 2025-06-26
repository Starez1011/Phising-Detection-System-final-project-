from nlp_models import TinyBERTPhishingDetector
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import os

def prepare_data():
    # Dynamically resolve the path to the dataset so the script works from any directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(script_dir, '..', 'text_csv_file', 'Text_Dataset_both.csv')
    df = pd.read_csv(dataset_path)
    
    # Use 'text' as input and 'labels' as target (ignore 'LABEL' column)
    texts = df['text'].astype(str).tolist()
    labels = df['labels'].astype(int).tolist()
    
    # Split into train and validation sets
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=0.2, random_state=42
    )
    
    return train_texts, train_labels, val_texts, val_labels

def main():
    # Initialize the model
    model = TinyBERTPhishingDetector()
    
    # Prepare the data
    train_texts, train_labels, val_texts, val_labels = prepare_data()
    
    # Fine-tune the model
    model.fine_tune(
        train_texts=train_texts,
        train_labels=train_labels,
        val_texts=val_texts,
        val_labels=val_labels,
        epochs=3,
        batch_size=16,
        learning_rate=2e-5
    )
    
    print("Model fine-tuning completed and saved!")

if __name__ == "__main__":
    main() 