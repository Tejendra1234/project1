import logging
import pandas as pd

logging.basicConfig(filename="forensics_alerts.log", level=logging.INFO)

def alert(message):
    print(f"[ALERT]: {message}")
    logging.info(message)

def store_in_csv(alert_type, details):
    import os
    import pandas as pd

    # Get timestamp from current time
    timestamp = pd.Timestamp.now()

    # Define the file name
    file_name = 'forensics_alerts.csv'

    # Check if the file exists
    file_exists = os.path.isfile(file_name)

    # Create a DataFrame with the new alert
    df = pd.DataFrame([[timestamp, alert_type, details]], columns=["Timestamp", "Alert Type", "Details"])

    # Write to the file (create if it doesn't exist, append otherwise)
    df.to_csv(file_name, mode='a', header=not file_exists, index=False)
    return True

def generate_report(alerts):
    df = pd.DataFrame(alerts, columns=["Timestamp", "Alert Type", "Details"])
    df.to_csv('forensics_report.csv', index=False)
    print("Report generated: forensics_report.csv")