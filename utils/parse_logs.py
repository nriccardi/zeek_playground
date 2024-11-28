import json
import pandas as pd

def parse_logs_to_pd(file_location: str) -> pd.DataFrame:
    with open(file_location, 'r') as f:
        data = []
        for line in f:
            if not line.startswith("#"):
                data.append(line.strip().split('\t'))
            elif line.startswith("#fields"):
                fields = line.replace("#fields", "").strip().split('\t')
    logs_df = pd.DataFrame(data, columns=fields)
    return logs_df

def parse_json_logs_to_pd(file_location: str) -> pd.DataFrame:
    with open(file_location, 'r') as f:
        data = []
        for line in f:
            data.append(json.loads(line))
    return pd.DataFrame.from_records(data)