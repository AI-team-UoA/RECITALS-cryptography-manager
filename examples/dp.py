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

data = np.array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
print(f"Original data: {data}")

dp = cm.adapters.DifferentialPrivacyAdapter(
    config, epsilon=1.0, mechanism="laplace"
)

for i in range(5):
    print(f"Differentially private data count: {dp.count(data)}")
    print(f"Differentially private data max: {dp.max(data)}")
    if i < 4:
        print("-" * 10)
