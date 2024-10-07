with open("./3.7_relocs.txt", "r") as f:
    lines = f.readlines()

# sort by address
lines_with_address = []

for line in lines:
    if not line:
        continue
    try:
        address = int(line.split()[0], 16)
        lines_with_address.append((address, line))
    except:
        pass

lines_with_address.sort(key=lambda x: x[0])

with open("./3.7_relocs_sorted.txt", "w") as f:
    for line in lines_with_address:
        f.write(line[1])
