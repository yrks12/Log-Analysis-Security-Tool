# Log Analysis Security Tool

This Python-based security tool processes web server logs to detect potential brute force attacks, unauthorized access attempts, and Distributed Denial of Service (DDoS) attacks. The tool reads log files, preprocesses the data, detects various security threats, and generates a detailed report summarizing these findings.

## Features

- **Brute Force Detection**: Identifies IP addresses attempting multiple failed logins (HTTP 401 errors) within a configurable time window.
- **Unauthorized Access Detection**: Flags IP addresses that attempt to access blacklisted directories (e.g., `/admin`, `/dashboard`) resulting in an HTTP 403 status.
- **DDoS Detection**: Detects potential DDoS attacks by identifying IP addresses making a high number of requests within a short time frame.
- **Consolidated Security Report**: Generates a report detailing detected threats, including the type of threat and the associated IP address.

## File Structure

The project is organized into four Python files:

1. **`extract.py`**: Contains functions for extracting and parsing log data from text files.
2. **`process.py`**: Contains preprocessing logic and detection algorithms for brute force, unauthorized access, and DDoS attacks.
3. **`report.py`**: Handles report generation by aggregating the results from the detection algorithms.
4. **`main.py`**: The entry point for running the entire tool. It ties together the extraction, processing, and report generation functions.

## Setup

### Prerequisites

Ensure that you have Python 3.x installed on your machine. The tool also requires the following Python packages:

- `pandas`: For data manipulation and analysis.
- `re` (built-in): For regular expression-based log parsing.

You can install the necessary dependencies by running:

```bash
pip install pandas
```

### Installation

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/yrks12/Log-Analysis-Security-Tool.git
   cd log-analysis-security-tool
   ```

2. Place your log file (e.g., `sample_log.txt`) in the project directory.

## Usage

### Running the Tool

To run the tool and generate a security report, execute the `main.py` file:

```bash
python main.py
```

The tool will:
1. Load the log data from the specified file.
2. Parse and preprocess the log entries.
3. Detect brute force attacks, unauthorized access attempts, and potential DDoS attacks.
4. Generate a CSV report (`security_report.csv`) summarizing the findings.

### Customizing the Tool

#### Configuration Parameters

The tool comes with default detection parameters, but you can customize the thresholds:

- **Brute Force Detection**:
  - `threshold_attempts`: Number of failed login attempts required to flag a brute force attack. Default is 5.
  - `time_window_minutes`: Time window (in minutes) to consider multiple failed attempts. Default is 30 minutes.

- **DDoS Detection**:
  - `threshold_requests`: Number of requests required to flag a DDoS attack. Default is 5.
  - `time_window_seconds`: Time window (in seconds) to consider multiple requests. Default is 10 seconds.

#### Example Customization

You can modify the thresholds by editing the function arguments in `main.py`:

```python
# Customize thresholds (optional)
brute_force(data_frame, threshold_attempts=10, time_window_minutes=15)
ddos(data_frame, threshold_requests=20, time_window_seconds=5)
```

## Report Format

The generated report (`security_report.csv`) contains the following columns:

- **`ip_addr`**: The IP address responsible for the flagged activity.
- **`threat_type`**: The type of threat detected (Brute Force, Unauthorized Access, or DDoS).
- **`failed_attempts_within_time_window`** or **`attempts_in_time_window`**: Number of attempts made during the specified time window (depending on the type of threat).

## Example

Here’s an example of the generated report:

| ip_addr       | threat_type         | failed_attempts_within_time_window | accessed_directory | attempts_in_time_window |
|---------------|---------------------|------------------------------------|--------------------|-------------------------|
| 192.168.1.1   | Brute Force          | 7                                  | N/A                | N/A                     |
| 203.0.113.0   | Unauthorized Access  | N/A                                | /admin             | N/A                     |
| 198.51.100.0  | DDoS                 | N/A                                | N/A                | 15                      |

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests to improve the functionality or documentation.
