import csv
import sys

def load_publisher(path):
    """Load publisher CSV into a dict keyed by (appId, stNum, sqNum).
       epoch is expected to be in microseconds."""
    pub_times = {}

    with open(path, newline="") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            print(f"{path}: no header row found.")
            return pub_times

        headers = {name.lower(): name for name in reader.fieldnames}

        epoch_field = headers.get("epoch") or headers.get("epoch_us") or headers.get("epoch_ms")
        appid_field = headers.get("appid") or headers.get("appid")
        stnum_field = headers.get("stnum")
        sqnum_field = headers.get("sqnum")

        if not (epoch_field and appid_field and stnum_field and sqnum_field):
            print(f"{path}: missing required columns (epoch/appId/stNum/sqNum).")
            return pub_times

        for row in reader:
            try:
                #Epoch is in microseconds
                epoch = int(row[epoch_field])
                app_id = int(row[appid_field])
                st_num = int(row[stnum_field])
                sq_num = int(row[sqnum_field])
            except (ValueError, KeyError):
                continue

            key = (app_id, st_num, sq_num)
            pub_times[key] = epoch

    return pub_times


def analyze(pub_path, sub_path):
    pub_times = load_publisher(pub_path)
    if not pub_times:
        print("No publisher data loaded; cannot compute latency.")
        return

    latencies_ms = []
    unmatched_sub = 0
    nonpositive = 0
    total_matched = 0

    with open(sub_path, newline="") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            print(f"{sub_path}: no header row found.")
            return

        headers = {name.lower(): name for name in reader.fieldnames}

        epoch_field = headers.get("epoch") or headers.get("epoch_us") or headers.get("epoch_ms")
        appid_field = headers.get("appid") or headers.get("appid")
        stnum_field = headers.get("stnum")
        sqnum_field = headers.get("sqnum")

        if not (epoch_field and appid_field and stnum_field and sqnum_field):
            print(f"{sub_path}: missing required columns (epoch/appId/stNum/sqNum).")
            return

        for row in reader:
            try:
                epoch_sub = int(row[epoch_field])
                app_id = int(row[appid_field])
                st_num = int(row[stnum_field])
                sq_num = int(row[sqnum_field])
            except (ValueError, KeyError):
                continue

            key = (app_id, st_num, sq_num)
            epoch_pub = pub_times.get(key)
            if epoch_pub is None:
                unmatched_sub += 1
                continue

            total_matched += 1

            delta_us = epoch_sub - epoch_pub
            if delta_us <= 0:
                nonpositive += 1
                #Skip non-positive samples from stats
                continue

            delta_ms = delta_us / 1000.0
            latencies_ms.append(delta_ms)

    if not latencies_ms:
        print("No positive-latency matching packets found between publisher and subscriber logs.")
        print(f"Total matched pairs (incl. <=0): {total_matched}")
        print(f"Unmatched subscriber rows:       {unmatched_sub}")
        print(f"Non-positive samples (<=0 ms):   {nonpositive}")
        return

    #Core stats
    avg = sum(latencies_ms) / len(latencies_ms)
    min_lat = min(latencies_ms)
    max_lat = max(latencies_ms)

    #Median
    sorted_lats = sorted(latencies_ms)
    n = len(sorted_lats)
    mid = n // 2
    if n % 2 == 1:
        median = sorted_lats[mid]
    else:
        median = 0.5 * (sorted_lats[mid - 1] + sorted_lats[mid])

    #95th percentile (simple rank-based)
    idx_95 = int(0.95 * (n - 1))
    p95 = sorted_lats[idx_95]

    print(f"Publisher log:   {pub_path}")
    print(f"Subscriber log:  {sub_path}")
    print(f"Total matched pairs (incl. <=0): {total_matched}")
    print(f"Used in stats (>0 ms):           {len(latencies_ms)}")
    print(f"Unmatched subs:                  {unmatched_sub}")
    if nonpositive:
        print(
            f"Note: {nonpositive} samples had non-positive latency "
            f"(<= 0 ms, skew/rounding) and were excluded from stats."
        )

    print()
    print(f"Average latency: {avg:.3f} ms")
    print(f"Median latency:  {median:.3f} ms")
    print(f"95th percentile: {p95:.3f} ms")
    print(f"Min latency:     {min_lat:.3f} ms")
    print(f"Max latency:     {max_lat:.3f} ms")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 latency_analyzer.py <publisher_csv> <subscriber_csv>")
        sys.exit(1)

    pub_csv = sys.argv[1]
    sub_csv = sys.argv[2]
    analyze(pub_csv, sub_csv)
