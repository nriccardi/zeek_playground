import numpy as np
import pandas as pd

def compute_entropy(string: str) -> float:
    if pd.isna(string) or len(string) == 0:
        return None
    prob_dist = [float(string.count(c)) / len(string) for c in set(string)]
    return -sum([p * np.log2(p) for p in prob_dist])
