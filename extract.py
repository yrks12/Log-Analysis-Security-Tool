import re
import pandas as pd

def extract_from_log_txt(filename):
    """Extract log data from a .txt or .log file.

    Args:
        filename (str): The path to the log file.

    Returns:
        list: A list of log entries.
    """
    with open(filename, "r") as logfile:
        data = logfile.read().splitlines()
    return data


def parse_data(data):
    """Parse log entries into a DataFrame.

    Args:
        data (list): List of log entries.

    Returns:
        pd.DataFrame: A DataFrame containing parsed log entries.
    """
    # Define regex patterns for parsing log entries
    ip_pattern = r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}" 
    date_pattern = r"\[([0-9]{2}/[A-Za-z]{3}/[0-9]{4})"
    time_pattern = r"\[([0-9]{2}/[A-Za-z]{3}/[0-9]{4}):([0-9]{2}:[0-9]{2}:[0-9]{2}) [+-][0-9]{4}\]"
    request_pattern = r'"([^"]*)"'
    status_code_pattern = r" (\d{3}) "
    size_of_bytes_pattern = r" (\d+)$"

    log_data_dict = {
        'ip_addr': [],
        'date': [],
        'time': [],
        'request': [],
        'status_code': [],
        'size': []
    }
    
    for entry in data:
        if not entry.strip():
            continue
        
        ip_addr = re.search(ip_pattern, entry)
        date = re.search(date_pattern, entry)
        time = re.search(time_pattern, entry)
        request = re.search(request_pattern, entry)
        status_code = re.search(status_code_pattern, entry)
        size = re.search(size_of_bytes_pattern, entry)
        
        log_data_dict['ip_addr'].append(ip_addr.group(0) if ip_addr else None)
        log_data_dict['date'].append(date.group(1) if date else None) 
        log_data_dict['time'].append(time.group(2) if time else None)
        log_data_dict['request'].append(request.group(1) if request else None)
        log_data_dict['status_code'].append(status_code.group(1) if status_code else None)
        log_data_dict['size'].append(size.group(1) if size else None)
    
    return pd.DataFrame(log_data_dict)