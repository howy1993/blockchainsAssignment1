import sys
import os

f = []
with os.scandir(path ='.') as it:
    for entry in it:
        if entry.name.endswith(".json") and entry.is_file():
            f.append(open(entry.name, "r"))

for line1 in f[0]:
    for i in (1,9):
        for line2 in f[i]:
            if line1!=line2:
                print("View from node 0 and {0} are different".format(i))
                sys.exit(0)
            break
        f[i].close

f[0].close()

print("Test program terminates here - view from all nodes are the same")
