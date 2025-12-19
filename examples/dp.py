import argparse

import numpy as np

import cryptography_manager as cm

# Set up argument parsing
parser = argparse.ArgumentParser()
parser.add_argument(
    "--config",
    type=str,
    default="./config.yaml",
    help="Path to the config file",
)
args = parser.parse_args()

# Load the config file from the provided argument
config = cm.Config()
config.load_from_file(args.config)

data = np.array([i for i in range(1000)])
# print(f"Original data: {data}")

lower_bound = 0
upper_bound = 999

dp = cm.adapters.DifferentialPrivacyAdapter(
    config, epsilon=1.0, mechanism="laplace"
)

results = 5
epsilon = 1.0  # equal to default value
query_count = 8
divisor = query_count + 1  # to avoid float arithmetic related errors
eps_per_query = epsilon / (results * divisor)

for i in range(results):
    print(
        f"Differentially private data count: {dp.Count(data, eps_per_query)}"
    )
    print(
        f"Differentially private data max: {dp.Max(data, eps_per_query, lower_bound, upper_bound)}"
    )
    print(
        f"Differentially private data min: {dp.Min(data, eps_per_query, lower_bound, upper_bound)}"
    )
    print(
        f"Differentially private data median: {dp.Median(data, eps_per_query, lower_bound, upper_bound)}"
    )
    print(
        f"Differentially private data mean: {dp.BoundedMean(data, eps_per_query, lower_bound, upper_bound)}"
    )
    print(
        f"Differentially private data sum: {dp.BoundedSum(data, eps_per_query, lower_bound, upper_bound)}"
    )
    print(
        f"Differentially private data standard deviation: {dp.BoundedStandardDeviation(data, eps_per_query, lower_bound, upper_bound)}"
    )
    print(
        f"Differentially private data variance: {dp.BoundedVariance(data, eps_per_query, lower_bound, upper_bound)}"
    )
    if i < results:
        print("-" * 10)
