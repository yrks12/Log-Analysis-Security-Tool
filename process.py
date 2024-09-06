import pandas as pd
import re

def preprocess_data(data_frame):
    """Add a 'timestamp' column to the DataFrame by combining the 'date' and 'time' columns.

    Args:
        data_frame (pd.DataFrame): The log DataFrame to preprocess.

    Returns:
        pd.DataFrame: The updated DataFrame with a 'timestamp' column.
    """
    data_frame['timestamp'] = pd.to_datetime(data_frame['date'] + ' ' + data_frame['time'], format='%d/%b/%Y %H:%M:%S')
    return data_frame


def brute_force(data_frame, threshold_attempts=5, time_window_minutes=30):
    """Detect brute force attempts based on failed login attempts within a time window.

    Args:
        data_frame (pd.DataFrame): Preprocessed log data.
        threshold_attempts (int, optional): Number of failed attempts to flag as brute force. Defaults to 5.
        time_window_minutes (int, optional): Time window in minutes to check for multiple failed attempts. Defaults to 30.

    Returns:
        pd.DataFrame: DataFrame containing IP addresses and their respective number of failed attempts flagged as brute force.
    """
    failed_logins = data_frame[data_frame["status_code"] == "401"].sort_values(by=["ip_addr", "timestamp"])
    grouped_failed_logins = []

    for ip_addr, group in failed_logins.groupby("ip_addr"):
        group['time_diff'] = group['timestamp'].diff().fillna(pd.Timedelta(seconds=0))
        failed_in_time_frame = group[group['time_diff'] <= pd.Timedelta(minutes=time_window_minutes)]

        if not failed_in_time_frame.empty:
            grouped_failed_logins.append((ip_addr, failed_in_time_frame.shape[0]))

    grouped_failed_logins = [entry for entry in grouped_failed_logins if entry[1] >= threshold_attempts]
    return pd.DataFrame(grouped_failed_logins, columns=['ip_addr', 'failed_attempts_within_time_window'])


def unauthorized_access(data_frame, black_list_dirs=None):
    """Detect unauthorized access to blacklisted directories based on status code 403.

    Args:
        data_frame (pd.DataFrame): Preprocessed log data.
        black_list_dirs (list, optional): List of blacklisted directories. Defaults to ["admin", "dashboard"].

    Returns:
        pd.DataFrame: DataFrame containing IP addresses and the directories they accessed without authorization.
    """
    if black_list_dirs is None:
        black_list_dirs = ["admin", "dashboard"]

    unauthorized = data_frame[data_frame["status_code"] == "403"]
    grouped_dirs = []
    pattern = r"(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) (/[^ ]+)"

    for ip_addr, group in unauthorized.groupby("ip_addr"):
        for _, row in group.iterrows():
            match = re.search(pattern, row['request'])
            if match:
                dir_accessed = match.group(2).split('/')[1]
                if dir_accessed in black_list_dirs:
                    grouped_dirs.append((ip_addr, dir_accessed))

    return pd.DataFrame(grouped_dirs, columns=['ip_addr', 'accessed_directory'])


def ddos(data_frame, threshold_requests=5, time_window_seconds=10):
    """Detect potential DDoS attacks by analyzing the number of requests in a short time window.

    Args:
        data_frame (pd.DataFrame): Preprocessed log data.
        threshold_requests (int, optional): Number of requests within the time window to flag as DDoS. Defaults to 5.
        time_window_seconds (int, optional): Time window in seconds for detecting multiple requests. Defaults to 10.

    Returns:
        pd.DataFrame: DataFrame containing IP addresses and the number of attempts flagged as potential DDoS.
    """
    entries = []

    for ip_addr, group in data_frame.groupby("ip_addr"):
        group = group.copy()
        group['time_diff'] = group['timestamp'].diff().fillna(pd.Timedelta(seconds=0))
        entries_per_sec = group[group['time_diff'] <= pd.Timedelta(seconds=time_window_seconds)]

        if not entries_per_sec.empty:
            entries.append((ip_addr, entries_per_sec.shape[0]))

    entries = [entry for entry in entries if entry[1] >= threshold_requests]
    return pd.DataFrame(entries, columns=['ip_addr', 'attempts_in_time_window'])