import csv
import random
import logging
from pathlib import Path
from typing import List, Dict, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def generate_email_dataset(num_emails: int, phishing_texts: List[str], non_phishing_texts: List[str], file_path: Union[str, Path], balance_dataset: bool = False) -> None:
    """
    Generate a dataset of phishing and non-phishing emails and save it to a CSV file.

    Args:
        num_emails (int): Total number of emails to generate.
        phishing_texts (List[str]): List of phishing email templates.
        non_phishing_texts (List[str]): List of non-phishing email templates.
        file_path (Union[str, Path]): File path for the output CSV.
        balance_dataset (bool): Whether to balance the number of phishing and non-phishing emails.
    """
    # Validation
    if num_emails <= 0:
        logging.error("Number of emails must be a positive integer.")
        return

    if not phishing_texts or not non_phishing_texts:
        logging.error("Phishing and non-phishing texts must not be empty.")
        return

    # Generate phishing emails (label 1)
    phishing_emails = [{'text': text, 'label': 1} for text in phishing_texts]

    # Generate non-phishing emails (label 0)
    non_phishing_emails = [{'text': text, 'label': 0} for text in non_phishing_texts]

    # Augment non-phishing emails if needed
    additional_non_phishing_needed = max(0, num_emails - len(phishing_emails) - len(non_phishing_emails))
    additional_non_phishing_emails = [
        {'text': f"Normal email content {i}", 'label': 0} for i in range(additional_non_phishing_needed)
    ]
    non_phishing_emails.extend(additional_non_phishing_emails)

    # Balance dataset if required
    if balance_dataset:
        phishing_count = len(phishing_emails)
        non_phishing_count = len(non_phishing_emails)
        min_count = min(phishing_count, non_phishing_count, num_emails // 2)

        phishing_emails = random.sample(phishing_emails, min_count)
        non_phishing_emails = random.sample(non_phishing_emails, min_count)

    # Combine and shuffle emails
    all_emails = phishing_emails + non_phishing_emails
    random.shuffle(all_emails)

    # Limit to num_emails if dataset is larger
    all_emails = all_emails[:num_emails]

    # Write to CSV
    try:
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with file_path.open('w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['text', 'label']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_emails)
        logging.info(f"Successfully generated {len(all_emails)} emails (Phishing: {sum(1 for email in all_emails if email['label'] == 1)}, Non-Phishing: {sum(1 for email in all_emails if email['label'] == 0)}) and saved to '{file_path}'.")
    except Exception as e:
        logging.error(f"Error writing to file: {e}")

def preview_dataset(file_path: Union[str, Path], sample_size: int = 5) -> None:
    """Preview a few rows of the generated dataset."""
    try:
        file_path = Path(file_path)
        with file_path.open('r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            rows = list(reader)
            preview = random.sample(rows, min(sample_size, len(rows)))
            logging.info(f"Preview of generated dataset:\n{preview}")
    except Exception as e:
        logging.error(f"Error reading dataset for preview: {e}")

if __name__ == "__main__":
    # Example phishing and non-phishing texts
    phishing_texts = [
        "Your account has been compromised. Click here: https://example.com/secure-account",
        "URGENT: Verify your account to avoid suspension: https://example.com/verify",
        "Action required: Unusual activity detected. Secure your account: https://example.com/security-alert"
    ]
    non_phishing_texts = [
        "Thank you for your recent purchase!",
        "Your order has been confirmed.",
        "Reminder: Appointment tomorrow at 10 AM."
    ]

    # Parameters
    num_emails = 1000  # Total emails to generate
    file_path = '/home/bhanu/Desktop/email_data.csv'  # Output file path

    # Generate dataset
    generate_email_dataset(num_emails, phishing_texts, non_phishing_texts, file_path, balance_dataset=True)

    # Preview the generated dataset
    preview_dataset(file_path)
