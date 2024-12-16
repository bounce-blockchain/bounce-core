import json
import matplotlib.pyplot as plt

# Load data from files
with open('sending_time_stamp.json', 'r') as f:
    sending_time_stamps = json.load(f)

with open('receiving_time_elapsed_tiled.json', 'r') as f:
    receiving_time_elapsed_tiled = json.load(f)

# Calculate normalized receiving times for each event
normalized_times = []
time_to_80_percent = []  # Store times to receive from 80% (16th GS)
for send_time, receive_times in zip(sending_time_stamps, receiving_time_elapsed_tiled):
    # Calculate actual receiving times
    actual_receive_times = [send_time + elapsed for elapsed in receive_times]
    normalized_receive_times = [time - sending_time_stamps[0] for time in actual_receive_times]
    normalized_times.append(normalized_receive_times)
    # Find the time to receive from the 16th GS
    sorted_times = sorted(actual_receive_times)  # Sort receiving times
    time_16th = sorted_times[15]  # 16th GS (0-based index is 15)
    time_to_80_percent.append(time_16th - send_time)  # Relative to the sending time

# Normalize sending times
normalized_sending_times = [send_time - sending_time_stamps[0] for send_time in sending_time_stamps]

# Create the horizontal box plot
plt.figure(figsize=(14, 10))

# Generate the boxplot
plt.boxplot(normalized_times, vert=False, patch_artist=True,
            boxprops=dict(facecolor="skyblue", color="blue"),
            whiskerprops=dict(color="blue"),
            capprops=dict(color="blue"),
            medianprops=dict(color="red"))

# Add sending events as green dots
for i, (send_time, y_position) in enumerate(zip(normalized_sending_times, range(1, len(sending_time_stamps) + 1))):
    plt.scatter(send_time, y_position, color='green', label='Sending Event' if i == 0 else "", zorder=3)
    # Annotate the green dot
    plt.text(send_time, y_position, f'{sending_time_stamps[i]} ms', color='green', fontsize=10, ha='right', va='center')

# Add markers for time to receive from 80% of GSs
for i, (time_80, y_position) in enumerate(zip(time_to_80_percent, range(1, len(sending_time_stamps) + 1))):
    normalized_time_80 = normalized_sending_times[i] + time_80  # Normalize the 80% time
    plt.scatter(normalized_time_80, y_position, color='orange', label='80% GS Received' if i == 0 else "", zorder=4)
    # Annotate the orange dot
    actual_80_time = sending_time_stamps[i] + time_80
    plt.text(normalized_time_80, y_position, f'{actual_80_time} ms', color='orange', fontsize=10, ha='left', va='center')

# Configure the y-axis labels
plt.yticks(range(1, len(sending_time_stamps) + 1),
           [f"{i+1}" for i in range(len(sending_time_stamps))],
           fontsize=12)

# Add labels and title
plt.xlabel('Time (ms since start)', fontsize=14)
plt.ylabel('Sending Event', fontsize=14)
plt.title('Receiving Times (ms) for different sending events. SS sends to 20 GSs', fontsize=16)

# Add grid, legend, and tighten layout
plt.grid(axis='x', linestyle='--', alpha=0.7)
plt.legend()
plt.tight_layout()

# Show the plot
plt.show()

