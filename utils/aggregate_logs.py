import pandas as pd

def get_counts(df: pd.DataFrame, group_by: list[str], time_slot: str = None):
    if time_slot:
        df["time_slot"] = df["dt"].dt.floor(time_slot)
        group_by = group_by + ["time_slot"] if isinstance(group_by, list) else [group_by, "time_slot"]
    counts = df.groupby(group_by).size().reset_index(name="Count").sort_values("Count", ascending=False)
    return counts

def get_sums(df: pd.DataFrame, group_by: list[str], sum_col: str, time_slot: str = None):
    if time_slot:
        df["time_slot"] = df["dt"].dt.floor(time_slot)
        group_by = group_by + ["time_slot"] if isinstance(group_by, list) else [group_by, "time_slot"]
    sums = (
        df.groupby(group_by)
        .agg(**{sum_col: (sum_col, 'sum'), 'conn_count': ("uid", 'count')})
        .reset_index()
        .sort_values(sum_col, ascending=False)
    )
    return sums

def get_avgs(df: pd.DataFrame, group_by: list[str], avg_col: str, time_slot: str = None, ascending=False):
    if time_slot:
        df["time_slot"] = df["dt"].dt.floor(time_slot)
        group_by = group_by + ["time_slot"] if isinstance(group_by, list) else [group_by, "time_slot"]
    avgs = (
        df.groupby(group_by)
        .agg(**{avg_col: (avg_col, 'mean'), 'conn_count': ("uid", 'count')})
        .reset_index()
        .sort_values(avg_col, ascending=ascending)
    )
    return avgs
