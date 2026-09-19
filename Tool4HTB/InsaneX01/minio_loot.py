#!/usr/bin/env python3
"""List and download every object from a MinIO endpoint."""
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import minio.time
from minio import Minio

p = argparse.ArgumentParser()
p.add_argument("--endpoint", required=True, help="HOST:PORT")
p.add_argument("--access-key", required=True)
p.add_argument("--secret-key", required=True)
p.add_argument("--secure", action="store_true", help="use HTTPS")
p.add_argument("--clock-offset", type=int, default=0,
               help="signed seconds added to the attack-host clock")
p.add_argument("--out", type=Path, required=True)
a = p.parse_args()

minio.time.utcnow = lambda: datetime.now(timezone.utc) + timedelta(seconds=a.clock_offset)
a.out.mkdir(parents=True, exist_ok=True)
out_root = a.out.resolve()
c = Minio(a.endpoint, access_key=a.access_key,
          secret_key=a.secret_key, secure=a.secure)
for bucket in c.list_buckets():
    print(f"BUCKET {bucket.name}")
    for obj in c.list_objects(bucket.name, recursive=True):
        print(f"OBJECT {bucket.name}/{obj.object_name} {obj.size}")
        dest = (out_root / bucket.name / obj.object_name).resolve()
        try:
            dest.relative_to(out_root)
        except ValueError:
            raise SystemExit(
                f"refusing object path outside --out: {bucket.name}/{obj.object_name}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        c.fget_object(bucket.name, obj.object_name, str(dest))
