from matplotlib import pyplot as plt

with open("./3.7_relocs_sorted.txt", "r") as f:
    relocs = f.readlines()


# addresses = [int(reloc.split()[0], 16) for reloc in relocs]
#
addresses = []

for reloc in relocs:

    if "ABS" in reloc:
        try:
            addresses.append(int(reloc.split()[0], 16))
        except:
            pass

# plot histogram

plt.hist(addresses, bins=100)

plt.show()
