import matplotlib.pyplot as plt

plt.rcParams['font.family'] = 'serif'

x = (0,1)
y = (1238001/10/1000, 1532901/10/1000)

plt.figure(figsize=(4,1.5))

plt.bar(x, y)
plt.ylabel('packets/s\n(in 1000s)')

plt.xticks(x, ("Userspace", "eBPF"))
plt.grid(False)
# ax.set_axisbelow(True)

plt.tight_layout()
plt.savefig("paper/figures/comparison_simple.pdf", bbox_inches = 'tight', pad_inches = 0)

# plt.show()