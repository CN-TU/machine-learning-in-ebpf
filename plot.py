# import pandas as pd
# import matplotlib.pyplot as plt

# d = {'throughput': [25.3, 27.4], 'packet processing rate': [1238001/1000/10, 1532901/1000/10]}
# df = pd.DataFrame(data=d)


# plt.figure(figsize=(1,3))

# # plot
# ax = df.plot(kind='bar', secondary_y=['throughput'])
# # import pdb; pdb.set_trace()
# ax.set_ylabel('packets/s')
# ax.right_ax.set_ylabel('Gbit/s')

# ax.set_xticklabels(("Userspace", "eBPF"))
# ax.grid(False)
# ax.set_axisbelow(True)

# plt.tight_layout()
# plt.savefig("fig.pdf", bbox_inches = 'tight', pad_inches = 0)

# # plt.show()

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

group_names = ["Userspace", "eBPF"]
feature_names = ["throughput", "packet processing rate"]
values = [[25.3, 1238001/1000/10],[27.4, 1532901/1000/10]]

plt.rcParams['font.family'] = 'serif'
plt.rcParams['savefig.format'] = 'pdf'
colors = plt.rcParams['axes.prop_cycle'].by_key()['color']

print("feature_names", feature_names)
print("group_names", group_names)
print("values", values)
values = np.array(values, dtype=float)

y_labels = ["Gbit/s", "packets/s"]
value_indices_to_plot = (0,1)

values = [[float(item) for item in sublist] for sublist in values]

width = 0.75 / len(value_indices_to_plot)

values = np.array(values)

x = np.arange(len(group_names), dtype=float)

fig, ax1 = plt.subplots(figsize=(3,2))
plt.xticks(x + width/2, group_names)
for tick in plt.gca().xaxis.get_major_ticks():
	label = tick.label1
ax2 = ax1.twinx()
axes = [ax1, ax2]

all_labels = []
for index, i in enumerate(value_indices_to_plot):
	print("plotting", values[:,i])
	label = axes[index].bar(x + width*index, values[:,i], width, color=colors[index], label=feature_names[i])
	all_labels.append(label)
	axes[index].set_ylabel(y_labels[i])

all_legends = [item.get_label() for item in all_labels]
# plt.legend(all_labels, all_legends)

ax2.set_ylabel_legend(Rectangle((0,0), 1, 1, fc=colors[1]), handlelength=1)
ax1.set_ylabel_legend(Rectangle((0,0), 1, 1, fc=colors[0]), handlelength=1)

# plt.tight_layout()
plt.savefig("paper/figures/comparison.pdf", bbox_inches = 'tight', pad_inches = 0)

# plt.show()