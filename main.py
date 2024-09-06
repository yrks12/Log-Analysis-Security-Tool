from extract import extract_from_log_txt, parse_data
from process import preprocess_data
from report import generate_report

def main():
    # Load log data from a file (replace 'sample_log.txt' with your actual log file)
    log_data = extract_from_log_txt('sample_log.txt')

    # Parse the log data into a DataFrame
    data_frame = parse_data(log_data)

    # Preprocess the data by adding a timestamp column
    data_frame = preprocess_data(data_frame)

    # Generate the security report
    report = generate_report(data_frame)

    # Print the report to inspect it
    print(report)

if __name__ == "__main__":
    main()