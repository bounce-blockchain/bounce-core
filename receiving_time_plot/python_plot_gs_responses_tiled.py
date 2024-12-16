import json
import matplotlib.pyplot as plt

# Load data from files
with open('sending_time_stamp.json', 'r') as f:
    sending_time_stamps = json.load(f)

with open('receiving_time_elapsed_tiled.json', 'r') as f:
    receiving_time_elapsed_tiled = json.load(f)

# Create the plot
plt.figure(figsize=(12, 8))

# Iterate through each sending event
for i, (send_time, receive_times) in enumerate(zip(sending_time_stamps, receiving_time_elapsed_tiled)):
    # Calculate actual receiving times
    actual_receive_times = [send_time + elapsed for elapsed in receive_times]
    # Normalize x-axis time to start at 0
    normalized_times = [time - sending_time_stamps[0] for time in actual_receive_times]
    # Plot the data
    plt.plot(normalized_times, [i + 1] * len(receive_times), 'o-', label=f'Sending Event {i+1}')

# Configure plot
plt.xlabel('Time (ms since start)', fontsize=14)
plt.ylabel('Sending Event', fontsize=14)
plt.title('Receiving Times for Each Sending Event', fontsize=16)
plt.legend()
plt.grid(True)

# Show the plot
plt.tight_layout()
plt.show()

