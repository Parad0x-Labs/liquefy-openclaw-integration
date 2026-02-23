# AWS CloudWatch & VPC Flow Log Champions

## 1. AWS VPC Liquefy (Structured)
- **Filename:** `AwsChampion_VpcFlow_Liquefy.py`
- **Best For:** AWS VPC Flow Logs (Standard and Custom formats).
- **Tech:** Binary IP Packing + Columnar RLE + Delta-Delta + Zstd.
- **Ratio:** **7.7x+** on real-world VPC telemetry.
- **Features:** 100% Lossless, Searchable by IP/ENI.

## 2. AWS CloudTrail Liquefy (Nested JSON)
- **Filename:** `AwsChampion_CloudTrail_Liquefy.py`
- **Best For:** Heavy AWS CloudTrail JSON archives.
- **Tech:** Schema-Aware Columnar + ARN Dictionaries + Zstd.
- **Ratio:** **60x - 100x** (crushes Zstd-19).
- **Features:** Functionally Lossless, Searchable by Event/User/Source IP.

---

##  Performance Summary
| Log Type | Champion Ratio | Zstd -19 | Gzip -9 |
| :--- | :--- | :--- | :--- |
| **VPC Flow** | **7.7x** | 5.6x | 4.9x |
| **CloudTrail** | **63.1x** | 34.0x | 25.7x |
