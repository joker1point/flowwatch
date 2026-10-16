"""连接桶单测：submit_conns → 峰值累积（含 peers 对齐）→ 落 conn_buckets → 查询验证。用临时库，不碰正式库。"""
import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import history

db = os.path.join(tempfile.gettempdir(), "hist_conns_test.db")
if os.path.exists(db):
    os.remove(db)

store = history.HistoryStore(path=db, bucket_seconds=60, flush_interval=0.5)
store.open()
store.start_writer()

# 模拟 localconn 的三次快照投递：alpha 两次（峰值应取 9/2/1.2，peers 取峰值那一刻的），
# beta 一次（300/0/44）；哨兵 pid=-2 应被过滤
store.submit_conns([{"pid": 111, "process": "alpha.exe", "conns": 5, "local_conns": 1,
                     "new_per_sec": 0.5, "peers": {7890: 1}}])
store.submit_conns([{"pid": 111, "process": "alpha.exe", "conns": 9, "local_conns": 2,
                     "new_per_sec": 1.2, "peers": {7890: 2, 8788: 7}}])
store.submit_conns([{"pid": 222, "process": "beta.exe", "conns": 300, "local_conns": 0,
                     "new_per_sec": 44.0, "peers": {}},
                    {"pid": -2, "process": "（未归因）", "conns": 5, "local_conns": 0,
                     "new_per_sec": 0.0, "peers": {}}])
time.sleep(1.2)
store.close()

conn = sqlite3.connect(db)
rows = conn.execute(
    """SELECT pid, process, conns_peak, local_conns_peak, new_per_sec_peak, peers
       FROM conn_buckets ORDER BY pid"""
).fetchall()
conn.close()
print("conn_buckets 内容：")
for row in rows:
    print(" ", row)

ok = (
    len(rows) == 2                                   # 哨兵 pid=-2 被过滤
    and rows[0][:3] == (111, "alpha.exe", 9) and rows[0][3:5] == (2, 1.2)
    and json.loads(rows[0][5]) == {"7890": 2, "8788": 7}   # peers 与峰值对齐
    and rows[1][:3] == (222, "beta.exe", 300)
)
print("断言：", "通过 ✓" if ok else "失败 ✗")
os.remove(db)
sys.exit(0 if ok else 1)
