from datetime import datetime

def reformat_timestamp(dt_str):
    # First, parse the string into a datetime object
    dt = datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S')
    # Then, return the formatted string
    return dt.strftime('%H:%M:%S %d-%m-%Y')

# Example usage:
formatted_time = reformat_timestamp("2024-02-24T15:56:00")
print(formatted_time)