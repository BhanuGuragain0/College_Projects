
```markdown
# Phishing Email Detection

This repository contains scripts to generate phishing and non-phishing emails and to train and utilize a machine learning model for phishing email detection.

## Overview
The project consists of two main scripts:

- `csv_maker.py`: This script generates a dataset of phishing and non-phishing emails.
- `email_checker.py`: This script trains a logistic regression model to detect phishing emails and allows users to check emails for phishing attempts.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Usage](#usage)
  - [Generating the Email Dataset](#generating-the-email-dataset)
  - [Training the Model and Checking Emails](#training-the-model-and-checking-emails)
- [License](#license)

## Features
- **Email Dataset Generation:** Generate a large dataset of phishing and non-phishing emails.
- **Model Training:** Train a logistic regression model to detect phishing emails.
- **Email Prediction:** Check if a given email is phishing or not using the trained model.
- **Report Generation:** Generate a report of predictions for multiple emails.

## Usage
### Generating the Email Dataset

Use `csv_maker.py` to generate a dataset of emails.

python csv_maker.py --num_emails 100000 --file_path ./email_data.csv
```

- `--num_emails`: Number of emails to generate.
- `--file_path`: Path to save the generated CSV file.

### Training the Model and Checking Emails:

```
python email_checker.py
```

`Follow the prompts to enter email texts and check if they are phishing or not.`

## License
This project is licensed under the MIT License.

## Requirements
```
- pandas
- numpy
- scikit-learn
- nltk
- joblib
```
