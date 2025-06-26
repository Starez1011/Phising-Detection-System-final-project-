from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import os
from torch.optim import AdamW
from tqdm import tqdm

class TinyBERTPhishingDetector:
    def __init__(self):
        self.model_name = "huawei-noah/TinyBERT_General_4L_312D"
        self.max_length = 128
        self.model_path = "GUI/models/tinybert_phishing"
        
        if os.path.exists(self.model_path):
            # Load fine-tuned model
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
        else:
            # Load pre-trained model
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name,
                num_labels=2  # Binary classification: legitimate vs phishing
            )
        
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        
    def predict(self, text):
        # Prepare input
        inputs = self.tokenizer(
            text,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt"
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        # Get prediction
        with torch.no_grad():
            outputs = self.model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=1)
            prediction = torch.argmax(probabilities, dim=1)
            
        return {
            'label': prediction.item(),  # 0 for legitimate, 1 for phishing
            'probabilities': probabilities[0].cpu().numpy().tolist()
        }
    
    def fine_tune(self, train_texts, train_labels, val_texts=None, val_labels=None,
                 epochs=3, batch_size=16, learning_rate=2e-5):
        """
        Fine-tune the model on phishing detection data
        """
        from torch.utils.data import DataLoader, TensorDataset
        import numpy as np
        
        # Prepare training data
        train_encodings = self.tokenizer(
            train_texts,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt"
        )
        
        train_dataset = TensorDataset(
            train_encodings['input_ids'],
            train_encodings['attention_mask'],
            torch.tensor(train_labels)
        )
        
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        
        # Prepare validation data if provided
        if val_texts is not None and val_labels is not None:
            val_encodings = self.tokenizer(
                val_texts,
                padding=True,
                truncation=True,
                max_length=self.max_length,
                return_tensors="pt"
            )
            
            val_dataset = TensorDataset(
                val_encodings['input_ids'],
                val_encodings['attention_mask'],
                torch.tensor(val_labels)
            )
            
            val_loader = DataLoader(val_dataset, batch_size=batch_size)
        
        # Prepare optimizer
        optimizer = AdamW(self.model.parameters(), lr=learning_rate)
        
        # Training loop
        self.model.train()
        for epoch in range(epochs):
            total_loss = 0
            print(f"Epoch {epoch + 1}/{epochs}")
            for batch in tqdm(train_loader, desc="Training", leave=False):
                optimizer.zero_grad()
                
                input_ids = batch[0].to(self.device)
                attention_mask = batch[1].to(self.device)
                labels = batch[2].to(self.device)
                
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=labels
                )
                
                loss = outputs.loss
                total_loss += loss.item()
                
                loss.backward()
                optimizer.step()
            
            avg_train_loss = total_loss / len(train_loader)
            print(f"  Average training loss: {avg_train_loss:.4f}")
            
            # Validation
            if val_texts is not None and val_labels is not None:
                self.model.eval()
                val_loss = 0
                predictions = []
                true_labels = []
                
                with torch.no_grad():
                    for batch in tqdm(val_loader, desc="Validation", leave=False):
                        input_ids = batch[0].to(self.device)
                        attention_mask = batch[1].to(self.device)
                        labels = batch[2].to(self.device)
                        
                        outputs = self.model(
                            input_ids=input_ids,
                            attention_mask=attention_mask,
                            labels=labels
                        )
                        
                        val_loss += outputs.loss.item()
                        predictions.extend(torch.argmax(outputs.logits, dim=1).cpu().numpy())
                        true_labels.extend(labels.cpu().numpy())
                
                avg_val_loss = val_loss / len(val_loader)
                accuracy = np.mean(np.array(predictions) == np.array(true_labels))
                print(f"  Validation loss: {avg_val_loss:.4f}")
                print(f"  Validation accuracy: {accuracy:.4f}")
                
                self.model.train()
        
        # Save the fine-tuned model
        os.makedirs(self.model_path, exist_ok=True)
        self.model.save_pretrained(self.model_path)
        self.tokenizer.save_pretrained(self.model_path) 