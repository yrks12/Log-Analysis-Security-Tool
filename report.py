import pandas as pd
from process import brute_force, unauthorized_access, ddos

def generate_report(data_frame, output_file="security_report.csv"):
    """Generate a consolidated security report with results from brute force, unauthorized access, and DDoS detection.

    Args:
        data_frame (pd.DataFrame): Preprocessed log data.
        output_file (str, optional): Path to save the report. Defaults to 'security_report.csv'.

    Returns:
        pd.DataFrame: Consolidated report DataFrame.
    """
    # Brute force detection
    brute_force_df = brute_force(data_frame)
    brute_force_df['threat_type'] = 'Brute Force'
    
    # Unauthorized access detection
    unauthorized_df = unauthorized_access(data_frame)
    unauthorized_df['threat_type'] = 'Unauthorized Access'
    
    # DDoS detection
    ddos_df = ddos(data_frame)
    ddos_df['threat_type'] = 'DDoS'
    
    # Combine the results
    report_df = pd.concat([brute_force_df, unauthorized_df, ddos_df], ignore_index=True)
    
    # Write to a CSV file (you can also change this to JSON or other formats)
    report_df.to_csv(output_file, index=False)
    
    return report_df