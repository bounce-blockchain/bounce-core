import json
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

# Load the JSON files
with open('receiving_time_elapsed_100_benchmarks_sorted.json', 'r') as f:
    data_1m = json.load(f)

# Convert data to NumPy arrays
data_1m_np = np.array(data_1m)

# Determine x-axis positions
num_responses = list(range(1, len(data_1m) + 1))  # Assuming all datasets have the same x-axis length
x_positions_1m = [x for x in num_responses]  # Offset positions for 1M dataset

# Create the plot
plt.figure(figsize=(12, 6))

# Plot box plots for each dataset
plt.boxplot(
    data_1m_np.T, positions=x_positions_1m, widths=0.2, showmeans=True, meanline=True, 
    patch_artist=True, boxprops=dict(facecolor="lightblue"), medianprops=dict(color="blue"), 
    meanprops=dict(color="darkblue")
)

# Add labels and grid
plt.xlabel("Number of Ground Stations Response Received")
plt.ylabel("Time Elapsed (ms)")
plt.title("Multi-bench-test")
stride = 5
plt.xticks(ticks=range(0, len(data_1m) + 1, stride), labels=range(0, len(data_1m) + 1, stride))
plt.grid(axis='y')

# Create a custom legend
legend_elements = [
    Patch(facecolor="lightblue", edgecolor="blue", label="1M Transactions"),
]
plt.legend(handles=legend_elements, loc="upper left")

# Display the plot
plt.tight_layout()
plt.show()

