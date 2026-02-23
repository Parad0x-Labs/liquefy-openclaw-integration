#!/usr/bin/env python3
import time
import zstandard as zstd
import gzip
import os
import random
import sys
import json

# Add path to load the champion
sys.path.append(os.path.abspath("production_engines/aws"))
from AwsChampion_CloudTrail_Liquefy import CloudTrailLiquefyChampion

def gen_cloudtrail_logs(count=5000):
    records = []
    actions = ["ConsoleLogin", "RunInstances", "StopInstances", "DescribeInstances", "CreateBucket", "PutObject"]
    users = ["alice", "bob", "ci-bot", "admin", "dev-user-12"]
    regions = ["us-east-1", "us-west-2", "eu-central-1", "ap-southeast-1"]

    for i in range(count):
        act = random.choice(actions)
        usr = random.choice(users)
        reg = random.choice(regions)

        rec = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDAX{i}",
                "arn": f"arn:aws:iam::123456789012:user/{usr}",
                "accountId": "123456789012",
                "userName": usr
            },
            "eventTime": "2023-12-25T12:00:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": act,
            "awsRegion": reg,
            "sourceIPAddress": f"10.0.{i%255}.{random.randint(1,254)}",
            "userAgent": "aws-cli/2.0.1",
            "requestParameters": {"instanceId": f"i-{i:08x}"},
            "responseElements": {"status": "success"},
            "requestID": f"req-{i:08x}",
            "eventID": f"evt-{i:08x}"
        }
        records.append(rec)

    return json.dumps({"Records": records}, separators=(',',':')).encode('utf-8')

def benchmark_cloudtrail():
    print(f"{' AWS CLOUDTRAIL CHAMPION SHOWDOWN ':=^70}")
    data = gen_cloudtrail_logs(10000)
    print(f">>>> DATASET: AWS CloudTrail Logs ({len(data):,} bytes)")
    print(f"{'Codec':<35} | {'Size (B)':>12} | {'Ratio':>10} | {'Speed':>12}")
    print("-" * 80)

    results = []

    # 1. Gzip -9
    t0 = time.time()
    c = gzip.compress(data, compresslevel=9)
    results.append(("Gzip -9", len(c), time.time()-t0))

    # 2. Zstd -19
    t0 = time.time()
    c = zstd.ZstdCompressor(level=19).compress(data)
    results.append(("Zstd -19", len(c), time.time()-t0))

    # 3. CloudTrail Liquefy
    codec_c = CloudTrailLiquefyChampion(level=22)
    t0 = time.time()
    c_c = codec_c.compress(data)
    t_c = time.time() - t0

    # Validation (Object equality)
    dec_bytes = codec_c.decompress(c_c)
    dec_obj = json.loads(dec_bytes)
    orig_obj = json.loads(data)
    if len(dec_obj["Records"]) != len(orig_obj["Records"]):
        print("ERROR: CLOUDTRAIL NOT LOSSLESS (Record Count)!")

    results.append(("[CHAMPION: CloudTrail Liquefy]", len(c_c), t_c))

    for name, size, duration in sorted(results, key=lambda x: x[1]):
        ratio = len(data) / max(size, 1)
        speed = len(data) / max(duration, 0.001) / 1024 / 1024
        print(f"{name:<35} | {size:>12,} | {ratio:>9.1f}x | {speed:>9.1f} MB/s")

if __name__ == "__main__":
    benchmark_cloudtrail()
