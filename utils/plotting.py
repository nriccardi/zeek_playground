from typing import Optional, Literal
import pandas as pd
import plotly.express as px

def hist(df: pd.DataFrame, x: str, nbins: int =50) -> None:
    fig = px.histogram(df, x=x, nbins=nbins, template="plotly_dark")
    fig.update_layout(xaxis_title=x, yaxis_title="Frequency")
    fig.show()

def bar(df: pd.DataFrame, x: str, y: str, color_col: Optional[str] = None) -> None:
    fig = px.bar(df, x=x, y=y, color=color_col, template="plotly_dark")
    fig.show()

def ts_line(df: pd.DataFrame, mode: Literal["count", "sum", "mean"], color_col: Optional[str] = None) -> None:
    if mode == "count":
        group_by = ["time_slot"]
        if color_col:
            group_by += [color_col]
        plot_df = (
            df.groupby(group_by)
            .agg(Tot=("Count", "sum"))
            .reset_index()
            .sort_values("time_slot", ascending=True)
        )
    elif mode == "sum":
        group_by = ["time_slot"]
        if color_col:
            group_by += [color_col]
        plot_df = (
            df.groupby(group_by)
            .agg(Tot=("Sum", "sum"))
            .reset_index()
            .sort_values("time_slot", ascending=True)
        )
    elif mode == "mean":
        group_by = ["time_slot"]
        if color_col:
            group_by += [color_col]
        plot_df = (
            df.groupby(group_by)
            .agg(Avg=("Mean", "mean"))
            .reset_index()
            .sort_values("time_slot", ascending=True)
        )
    else:
        raise NotImplementedError("Unexpected mode!")
    
    y_col = "Avg" if mode == "mean" else "Tot"
    fig = px.line(plot_df, x="time_slot", y=y_col, color=color_col, template="plotly_dark")
    fig.update_layout(xaxis_title="Time", yaxis_title=y_col)
    fig.show()
