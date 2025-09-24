# Differential Privacy: Adding laplacian noise to datasets with json templates

## Setup

1. Create a Python3.10 virtual environment in `.venv` and activate it.

``` shell
$ python3.10 -m venv .venv
$ source .venv/bin/activate # for bash
```

1. Install the dependencies.

``` shell
pip install -r requirements.txt
```

## JSON templates structure

Each template has the necessary attributes for ANJANA to function. Namely, it *must* include:

1. `data`: The path to the dataset (csv files only for now).
2. `epsilon`: The epsilon value for $\varepsilon$-differential privacy.
2. `numeric`: A dictionary, with the column names of the dataset's numeric attributes as the keys. The values are two-entry lists which contain the lower and upper bounds for the respective attribute.

## Example usage

The provided template uses the `adult.csv` dataset [1]. To use a specific template, pass it as a CLI argument to the `wrapper.py` script, like so:

``` shell
$ python ./wrapper.py sample_templates/adult.json
```

## References

[1] R. K. Barry Becker, “Adult.” UCI Machine Learning Repository, 1996. doi: 10.24432/C5XW20. Available: https://archive.ics.uci.edu/dataset/2
