import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from GUI.nlp_models import TinyBERTPhishingDetector

# Load data
csv_path = 'text_csv_file/Text_Dataset_both.csv'
df = pd.read_csv(csv_path)
texts = df['text'].astype(str).tolist()
labels = df['labels'].astype(int).tolist()

# Split into train and validation sets (same as train_nlp_model.py)
_, val_texts, _, val_labels = train_test_split(
    texts, labels, test_size=0.2, random_state=42
)

# Load fine-tuned model from the correct directory
model = TinyBERTPhishingDetector()
model.model_path = 'GUI/GUI/models/tinybert_phishing'  # Ensure correct path
model.tokenizer = model.tokenizer.from_pretrained(model.model_path)
model.model = model.model.from_pretrained(model.model_path)

# Predict on validation set
preds = []
for text in val_texts:
    result = model.predict(text)
    preds.append(result['label'])

# Calculate metrics
accuracy = accuracy_score(val_labels, preds)
precision = precision_score(val_labels, preds)
recall = recall_score(val_labels, preds)
f1 = f1_score(val_labels, preds)
cm = confusion_matrix(val_labels, preds)
report = classification_report(val_labels, preds)

print(f"Validation Accuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1-score: {f1:.4f}")
print("Confusion Matrix:")
print(cm)
print("\nClassification Report:")
print(report) 