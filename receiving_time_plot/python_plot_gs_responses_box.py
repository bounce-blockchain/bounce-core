import json
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

# Load the JSON files
with open('receiving_time_elapsed_1m.json', 'r') as f:
    data_1m = json.load(f)

with open('receiving_time_elapsed_100k.json', 'r') as f:
    data_100k = json.load(f)

with open('receiving_time_elapsed_500k.json', 'r') as f:
    data_500k = json.load(f)

# Convert data to NumPy arrays
data_1m_np = np.array(data_1m)
data_100k_np = np.array(data_100k)
data_500k_np = np.array(data_500k)

# Determine x-axis positions
num_responses = list(range(1, len(data_1m) + 1))  # Assuming all datasets have the same x-axis length
x_positions_1m = [x for x in num_responses]  # Offset positions for 1M dataset
x_positions_100k = [x for x in num_responses]  # Offset positions for 100K dataset
x_positions_500k = [x for x in num_responses]      # Centered positions for 500K dataset

# Create the plot
plt.figure(figsize=(12, 6))

# Plot box plots for each dataset
plt.boxplot(
    data_1m_np.T, positions=x_positions_1m, widths=0.2, showmeans=True, meanline=True, 
    patch_artist=True, boxprops=dict(facecolor="lightblue"), medianprops=dict(color="blue"), 
    meanprops=dict(color="darkblue")
)
plt.boxplot(
    data_100k_np.T, positions=x_positions_100k, widths=0.2, showmeans=True, meanline=True, 
    patch_artist=True, boxprops=dict(facecolor="lightgreen"), medianprops=dict(color="green"), 
    meanprops=dict(color="darkgreen")
)
plt.boxplot(
    data_500k_np.T, positions=x_positions_500k, widths=0.2, showmeans=True, meanline=True, 
    patch_artist=True, boxprops=dict(facecolor="lightcoral"), medianprops=dict(color="red"), 
    meanprops=dict(color="darkred")
)

# Add labels and grid
plt.xlabel("Number of Ground Stations Response Received")
plt.ylabel("Time Elapsed (ms)")
plt.title("Box Plot of Time Elapsed for Different Transaction Volumes with 39 Ground Stations")
stride = 5
plt.xticks(ticks=range(0, len(data_1m) + 1, stride), labels=range(0, len(data_1m) + 1, stride))
plt.grid(axis='y')

# Create a custom legend
legend_elements = [
    Patch(facecolor="lightblue", edgecolor="blue", label="1M Transactions"),
    Patch(facecolor="lightcoral", edgecolor="red", label="500K Transactions"),
    Patch(facecolor="lightgreen", edgecolor="green", label="100K Transactions"),
]
plt.legend(handles=legend_elements, loc="upper left")

# Display the plot
plt.tight_layout()
plt.show()

