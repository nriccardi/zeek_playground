import pandas as pd
from typing import Literal

def get_counts(df: pd.DataFrame, group_by: list[str], time_slot: str = None) -> pd.DataFrame:
    if time_slot:
        df["time_slot"] = df["dt"].dt.floor(time_slot)
        group_by = group_by + ["time_slot"] if isinstance(group_by, list) else [group_by, "time_slot"]
    counts = df.groupby(group_by).size().reset_index(name="Count").sort_values("Count", ascending=False)
    return counts

def get_sums(df: pd.DataFrame, group_by: list[str], sum_col: str, time_slot: str = None) -> pd.DataFrame:
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

def get_summary_stats(df: pd.DataFrame, group_by: list[str], target_col: str, time_slot: str = None, ascending=False) -> pd.DataFrame:
    if time_slot:
        df["time_slot"] = df["dt"].dt.floor(time_slot)
        group_by = group_by + ["time_slot"] if isinstance(group_by, list) else [group_by, "time_slot"]
    summary_stats = (
        df.groupby(group_by)
        .agg(**{f"{target_col}_mean": (target_col, 'mean'), f"{target_col}_std": (target_col, 'std'), 'conn_count': ("uid", 'count')})
        .reset_index()
        .sort_values(f"{target_col}_mean", ascending=ascending)
    )
    return summary_stats

def get_ts(df: pd.DataFrame, group_by: list[str], target_col: str, mode: Literal["count", "sum", "mean"], time_slot: str):
    df["time_slot"] = df["dt"].dt.floor(time_slot)
    group_by = group_by + ["time_slot"] if isinstance(group_by, list) else [group_by, "time_slot"]
    
    if mode == "count":
        group_by += [target_col]
        ts = df.groupby(group_by).size().reset_index(name="Count").sort_values("Count", ascending=False)
        if time_slot:
            ts = (
            ts.groupby(group_by)
                .agg(Count=("Count", "sum"))
                .reset_index()
                .sort_values("time_slot", ascending=True)
            )
    elif mode == "sum":
        ts = (
            df.groupby(group_by)
                .agg(Sum=(target_col, "sum"))
                .reset_index()
                .sort_values("time_slot", ascending=True)
            )
    elif mode == "mean":
        ts = (
            df.groupby(group_by)
                .agg(Mean=(target_col, "mean"))
                .reset_index()
                .sort_values("time_slot", ascending=True)
            )
    else:
        raise NotImplementedError("Unexpected mode!")

    return ts