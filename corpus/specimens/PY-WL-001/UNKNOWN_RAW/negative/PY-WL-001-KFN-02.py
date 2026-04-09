from collections import defaultdict

def aggregate(records):
    groups = defaultdict(list)
    for r in records:
        groups[r["type"]].append(r)
