"""Validate an explicit Linux benchmark CPU set before launching child processes."""

def cpu_set(value, allowed):
    selected = []
    for part in value.split(','):
        ends = part.split('-')
        if len(ends) not in (1, 2):
            raise ValueError('invalid CPU range')
        low, high = int(ends[0]), int(ends[-1])
        if low < 0 or high < low or high > max(allowed):
            raise ValueError('invalid CPU range')
        selected.extend(range(low, high + 1))
    if not selected or len(set(selected)) != len(selected) or not set(selected) <= set(allowed):
        raise ValueError('CPU affinity is empty, duplicated or unavailable')
    return sorted(selected)
