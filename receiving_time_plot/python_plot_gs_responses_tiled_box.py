import json
import matplotlib.pyplot as plt

# Load data from files
with open('sending_time_stamp.json', 'r') as f:
    sending_time_stamps = json.load(f)

with open('receiving_time_elapsed_tiled.json', 'r') as f:
    receiving_time_elapsed_tiled = json.load(f)

# Calculate normalized receiving times for each event
normalized_times = []
for send_time, receive_times in zip(sending_time_stamps, receiving_time_elapsed_tiled):
    actual_receive_times = [send_time + elapsed for elapsed in receive_times]
    normalized_times.append([time - sending_time_stamps[0] for time in actual_receive_times])

# Create the horizontal box plot
plt.figure(figsize=(12, 8))

# Generate the boxplot
plt.boxplot(normalized_times, vert=False, patch_artist=True,
            boxprops=dict(facecolor="skyblue", color="blue"),
            whiskerprops=dict(color="blue"),
            capprops=dict(color="blue"),
            medianprops=dict(color="red"))

# Configure the y-axis labels
plt.yticks(range(1, len(sending_time_stamps) + 1),
           [f"{i+1}" for i in range(len(sending_time_stamps))],
           fontsize=12)

# Add labels and title
plt.xlabel('Time (ms since start)', fontsize=14)
plt.ylabel('Sending Event', fontsize=14)
plt.title('Receiving Times (ms) for different sending events. SS sends to 20 GSs ', fontsize=16)

# Add grid and tighten layout
plt.grid(axis='x', linestyle='--', alpha=0.7)
plt.tight_layout()

# Show the plot
plt.show()

