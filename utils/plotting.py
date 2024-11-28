import pandas as pd
import plotly.express as px

def hist(df: pd.DataFrame, x: str, nbins=50) -> None:
    fig = px.histogram(df, x=x, nbins=nbins, template="plotly_dark")
    fig.update_layout(xaxis_title=x, yaxis_title="Frequency")
    fig.show()

def bar(df: pd.DataFrame, x: str, y: str, color_col: str = None) -> None:
    fig = px.bar(df, x=x, y=y, color=color_col, template="plotly_dark")
    fig.show()

