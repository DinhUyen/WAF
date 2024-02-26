# Hàm chuyển đổi chuỗi thời gian thành đối tượng datetime
from datetime import datetime, timedelta
import re
def convert_to_datetime(time_str):
    pattern = r'(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+.\d+) (\+\d+)'
    match = re.match(pattern, time_str)
    if match:
        day = int(match.group(1))
        month_map = {
            "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
            "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
        }
        month = month_map[match.group(2)]
        year = int(match.group(3))
        hour = int(match.group(4))
        minute = int(match.group(5))
        second = int(float(match.group(6)))  # Giây có phần thập phân
        timezone_offset = int(match.group(7)) // 100  # Điều chỉnh múi giờ
        return datetime(year, month, day, hour, minute, second) - timedelta(hours=timezone_offset)
    else:
        raise ValueError("Invalid time format")
print(convert_to_datetime("10/Jan/2024:23:06:53.534501 +0700"))