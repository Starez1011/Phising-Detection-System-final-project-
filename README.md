# Phishing Website and Text Detection

A machine learning-based system for detecting phishing using both URL analysis and text content analysis. The system leverages advanced models to classify websites and messages as either legitimate or phishing, providing a comprehensive approach to phishing detection.

## Project Overview

This project implements a multi-modal phishing detection system that analyzes both URLs and message text for phishing intent. The system uses:

- **URL Analysis:**

  - Extracts features from URLs and website characteristics.
  - Uses a machine learning model (XGBoost) to classify URLs as legitimate or phishing.

- **Text Analysis:**
  - Uses a fine-tuned TinyBERT NLP model to analyze the content of messages for phishing intent.
  - Classifies message text as legitimate or phishing based on language patterns and context.

**How the system works:**

1. When a user submits a message, the system:
   - Extracts any URLs from the message and analyzes them using the XGBoost model.
   - Analyzes the message text using the NLP model.
2. Each component (URL and text) is classified as either legitimate or phishing.
3. The system provides user-friendly feedback for both URL and text analysis, warning users about potential phishing threats.
4. Results and predictions are stored for each user, and duplicate URLs are not stored for the same user.

**Models Used:**

- **XGBoost:** For URL-based phishing detection.
- **TinyBERT (NLP):** For phishing intent detection in message text.

## Features

The system analyzes the following features to detect phishing websites:

1. **URL-based Features**:

   - Long URL detection (URLs longer than 54 characters)
   - Presence of @ symbol in URL
   - Presence of redirection (//) in URL
   - Prefix/suffix separation in domain
   - Number of sub-domains
   - Presence of IP address in URL
   - Use of URL shortening services
   - Presence of HTTPS token

2. **Domain-based Features**:

   - Web traffic analysis
   - Domain registration length
   - DNS record presence
   - Age of domain

3. **Statistical Features**:
   - Website traffic ranking
   - Domain age verification
   - DNS record validation

## Model Training and Performance

The project implements and compares multiple machine learning models:

1. **Naive Bayes**

   - Training Accuracy: 67.2%
   - Test Accuracy: 68.4%
   - Training Time: 0.004s
   - Good for quick initial screening
   - Confusion Matrix:
     ```
     [[1152   25]
      [ 696  408]]
     ```
   - Working Principle:
     - Uses Bayes' theorem to calculate probability of a website being phishing
     - Assumes features are independent of each other
     - Fast training but may oversimplify complex relationships

2. **Decision Tree**

   - Training Accuracy: 78.5%
   - Test Accuracy: 77.1%
   - Training Time: 0.007s
   - Balanced performance and speed
   - Confusion Matrix:
     ```
     [[920 257]
      [265 839]]
     ```
   - Working Principle:
     - Creates a tree-like model of decisions
     - Each node represents a feature test
     - Leaf nodes represent class labels
     - Easy to interpret but can overfit

3. **Random Forest**

   - Training Accuracy: 78.5%
   - Test Accuracy: 77.2%
   - Training Time: 0.282s
   - Best overall performance
   - Confusion Matrix:
     ```
     [[918 259]
      [262 842]]
     ```
   - Working Principle:
     - Ensemble of multiple decision trees
     - Each tree trained on random subset of data
     - Final prediction by majority voting
     - Reduces overfitting through averaging
     - Handles both numerical and categorical features well

4. **XGBoost**
   - Training Accuracy: 78.4%
   - Test Accuracy: 77.0%
   - Training Time: 1.260s
   - Good performance for URL-based phishing detection
   - Confusion Matrix:
     ```
     [[914 263]
      [261 843]]
     ```
   - Working Principle:
     - Gradient boosting framework
     - Sequentially builds weak learners
     - Each new model corrects errors of previous ones
     - Uses advanced regularization to prevent overfitting
     - Handles missing values automatically

### Understanding Performance Metrics

When evaluating classification models, we use several important metrics:

- **Precision:** Measures how many of the items predicted as phishing are actually phishing.

  - Formula: Precision = True Positives / (True Positives + False Positives)
  - Example: If your model predicts 100 websites as phishing, and 77 of them are actually phishing, the precision is 77%.

- **Recall:** Measures how many of the actual phishing websites your model correctly identified.

  - Formula: Recall = True Positives / (True Positives + False Negatives)
  - Example: If there are 100 phishing websites in reality, and your model correctly finds 77 of them, the recall is 77%.

- **F1-score:** The harmonic mean of precision and recall, providing a single score that balances both.
  - Formula: F1-score = 2 × (Precision × Recall) / (Precision + Recall)
  - Example: If both precision and recall are 77%, the F1-score will also be 77%.

**Why are these important?**

- Precision is important when the cost of a false positive is high (e.g., marking a legitimate site as phishing).
- Recall is important when the cost of a false negative is high (e.g., missing a phishing site).
- F1-score is useful when you want a balance between precision and recall.

| Metric    | What it answers                                          | Formula                                         |
| --------- | -------------------------------------------------------- | ----------------------------------------------- |
| Precision | Of all predicted phishing, how many are really phishing? | TP / (TP + FP)                                  |
| Recall    | Of all real phishing, how many did we catch?             | TP / (TP + FN)                                  |
| F1-score  | Balance between precision and recall                     | 2 × (Precision × Recall) / (Precision + Recall) |

### Model Selection

The project uses XGBoost as the primary model for URL-based phishing detection because:

- XGBoost captures complex patterns and relationships in URL features.
- Provides robust performance and handles various types of phishing attempts.

**Performance:**

- **XGBoost:**

  - Precision: 0.78 (legitimate), 0.76 (phishing)
  - Recall: 0.78 (legitimate), 0.76 (phishing)
  - F1-Score: 0.78 (legitimate), 0.76 (phishing)

- **Confusion Matrix Analysis:**
  - True Negatives (Legitimate): 914
  - False Positives: 263
  - False Negatives: 261
  - True Positives (Phishing): 843

This shows that XGBoost provides reliable performance for URL-based phishing detection.

## NLP Model: Phishing Text Detection

This project also includes a Natural Language Processing (NLP) model for detecting phishing in text content using TinyBERT.

**Model:**

- TinyBERT (huawei-noah/TinyBERT_General_4L_312D), fine-tuned for phishing detection.
- Binary classification: 0 = legitimate, 1 = phishing.

**How it works:**

- If a fine-tuned model exists in `GUI/models/tinybert_phishing/`, it is loaded automatically.
- If not, the pre-trained TinyBERT model is downloaded from HuggingFace and fine-tuned on your dataset using `train_nlp_model.py`.
- The model is used to analyze message text for phishing indicators.

**Accuracy:**

- The script prints validation accuracy after each epoch during training (e.g., `Validation accuracy: 0.93`).
- Check your terminal output after running `train_nlp_model.py` for the exact value.

**How to use the NLP model:**

1. **Download and/or train the model:**
   ```
   python GUI/train_nlp_model.py
   ```
   - This will download TinyBERT if not present, fine-tune it on your dataset, and save it to `GUI/models/tinybert_phishing/`.
2. **Run the app:**
   ```
   python GUI/app.py
   ```
   - The app will automatically use the fine-tuned NLP model for phishing text detection.

**Note:**

- The model and tokenizer will be downloaded automatically if not present.
- Predictions and probabilities for both ML and NLP models are printed to the terminal for each request.

## Usage

1. **GUI Application**:
   - Launch the GUI application
   - Enter the URL to check
   - Click "Analyze" to get results

## Acknowledgments

- Dataset sources - Kaggle, Phistank,
- Dataset sources for nlp model: https://data.mendeley.com/datasets/f45bkkt8pr/1?utm_source=chatgpt.com
