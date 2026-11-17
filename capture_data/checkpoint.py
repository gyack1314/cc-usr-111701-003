"""检查点与采集状态的持久化。

设计原则：

* confirmed_heads 只追加：每个通过全部密码学核验的树版本留一行，
  重启不会抹掉任何已经确认的树根；
* watermark 是当前可发布水位，只允许在同一事务里随新确认树头前移，
  水位之下的叶子才允许进入正式结果；
* verified_leaves 只保存"包含证明 + 叶子原文哈希"全部核验通过的条目，
  并记录其被核验时所在的树版本，检索可逐条追溯；
* backlog 保存待补项（镜像暂时取不到、落后镜像待追赶）；
* quarantine 保存冲突（两个已签名树头互相矛盾）与不可采信项
  （签名/证明/叶子原文核验失败、伪造重复索引等），候选不进正式结果。
"""
import json
import sqlite3
import time

PENDING = "pending"
CONFLICT = "conflict"
INADMISSIBLE = "inadmissible"
CLASSIFICATIONS = (PENDING, CONFLICT, INADMISSIBLE)

SCHEMA = """
CREATE TABLE IF NOT EXISTS confirmed_heads(
  log_id TEXT, tree_size INTEGER, root_hash TEXT, timestamp INTEGER,
  signature TEXT, consistency_from_size INTEGER, proof_digest TEXT,
  source_mirror TEXT, response_digest TEXT, confirmed_at REAL,
  PRIMARY KEY(log_id, tree_size));
CREATE TABLE IF NOT EXISTS watermark(
  log_id TEXT PRIMARY KEY, tree_size INTEGER NOT NULL, root_hash TEXT NOT NULL,
  confirmed_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS verified_leaves(
  log_id TEXT, leaf_index INTEGER, leaf_hash TEXT NOT NULL,
  raw_b64 TEXT NOT NULL, certificate TEXT, subject TEXT, san_json TEXT,
  included_tree_size INTEGER NOT NULL, root_hash TEXT NOT NULL,
  inclusion_proof_digest TEXT NOT NULL, source_mirror TEXT NOT NULL,
  response_digest TEXT NOT NULL, verified_at REAL NOT NULL,
  PRIMARY KEY(log_id, leaf_index));
CREATE TABLE IF NOT EXISTS backlog(
  log_id TEXT, kind TEXT, item_key TEXT, detail_json TEXT,
  created_at REAL, updated_at REAL,
  PRIMARY KEY(log_id, kind, item_key));
CREATE TABLE IF NOT EXISTS quarantine(
  log_id TEXT, kind TEXT, item_key TEXT, classification TEXT,
  detail_json TEXT, created_at REAL, updated_at REAL,
  PRIMARY KEY(log_id, kind, item_key));
"""


def connect(path):
    """打开（或新建）检查点库，path 可以是 :memory:。"""
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    return conn


def current_watermark(conn, log_id):
    """返回当前可发布水位；从未确认过树头时为 None。"""
    row = conn.execute(
        "SELECT tree_size,root_hash,confirmed_at FROM watermark WHERE log_id=?",
        (log_id,)).fetchone()
    if row is None:
        return None
    return {"tree_size": row[0], "root_hash": row[1], "confirmed_at": row[2]}


def get_confirmed_head(conn, log_id, tree_size):
    row = conn.execute(
        "SELECT tree_size,root_hash,timestamp,signature,consistency_from_size,"
        "proof_digest,source_mirror,response_digest,confirmed_at "
        "FROM confirmed_heads WHERE log_id=? AND tree_size=?",
        (log_id, tree_size)).fetchone()
    if row is None:
        return None
    return {"tree_size": row[0], "root_hash": row[1], "timestamp": row[2],
            "signature": row[3], "consistency_from_size": row[4],
            "proof_digest": row[5], "source_mirror": row[6],
            "response_digest": row[7], "confirmed_at": row[8]}


def list_confirmed_heads(conn, log_id):
    rows = conn.execute(
        "SELECT tree_size,root_hash,timestamp,signature,consistency_from_size,"
        "proof_digest,source_mirror,response_digest,confirmed_at "
        "FROM confirmed_heads WHERE log_id=? ORDER BY tree_size", (log_id,)).fetchall()
    return [{"tree_size": r[0], "root_hash": r[1], "timestamp": r[2],
             "signature": r[3], "consistency_from_size": r[4],
             "proof_digest": r[5], "source_mirror": r[6],
             "response_digest": r[7], "confirmed_at": r[8]} for r in rows]


def commit_advance(conn, log_id, head, watermark):
    """原子地追加已确认树头并前移水位。

    水位只允许单调前移，且根哈希必须与树头一致。重复确认同一树版本是
    幂等的，任何回退尝试都抛 ValueError。
    """
    with conn:
        _write_head_and_watermark(conn, log_id, head, watermark)


def get_verified_leaf(conn, log_id, leaf_index):
    row = conn.execute(
        "SELECT leaf_index,leaf_hash,raw_b64,certificate,subject,san_json,"
        "included_tree_size,root_hash,inclusion_proof_digest,source_mirror,"
        "response_digest,verified_at FROM verified_leaves "
        "WHERE log_id=? AND leaf_index=?", (log_id, leaf_index)).fetchone()
    if row is None:
        return None
    return {"leaf_index": row[0], "leaf_hash": row[1], "raw_b64": row[2],
            "certificate": row[3], "subject": row[4],
            "san": json.loads(row[5]) if row[5] is not None else None,
            "included_tree_size": row[6], "root_hash": row[7],
            "inclusion_proof_digest": row[8], "source_mirror": row[9],
            "response_digest": row[10], "verified_at": row[11]}


def add_verified_leaf(conn, log_id, leaf):
    """写入完全核验的叶子（独立事务，供测试与单条补录使用）。

    同索引已有不同哈希即伪造重复索引，抛错。采集主流程使用
    commit_segment 把整段叶子与水位推进放进同一事务。
    """
    with conn:
        return _insert_verified_leaf(conn, log_id, leaf)


def _insert_verified_leaf(conn, log_id, leaf):
    """不自行管理事务的叶子插入，必须处于调用方事务内。"""
    old = get_verified_leaf(conn, log_id, leaf["leaf_index"])
    if old is not None:
        if old["leaf_hash"] != leaf["leaf_hash"]:
            raise ValueError("伪造的重复索引：同索引叶子哈希不一致")
        return False
    san = leaf.get("san")
    conn.execute(
        "INSERT INTO verified_leaves "
        "(log_id,leaf_index,leaf_hash,raw_b64,certificate,subject,san_json,"
        "included_tree_size,root_hash,inclusion_proof_digest,source_mirror,"
        "response_digest,verified_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (log_id, leaf["leaf_index"], leaf["leaf_hash"], leaf["raw_b64"],
         leaf.get("certificate"), leaf.get("subject"),
         json.dumps(san, ensure_ascii=False) if san is not None else None,
         leaf["included_tree_size"], leaf["root_hash"],
         leaf["inclusion_proof_digest"], leaf["source_mirror"],
         leaf["response_digest"], time.time()))
    return True


def commit_segment(conn, log_id, leaves, head, watermark):
    """单事务提交：整段已核验叶子 + 追加确认树头 + 前移水位。

    任一步失败整体回滚，绝不出现"叶子已入库但树版本未确认"的中间态。
    返回新插入的叶子索引列表。
    """
    inserted = []
    with conn:
        for leaf in leaves:
            if _insert_verified_leaf(conn, log_id, leaf):
                inserted.append(leaf["leaf_index"])
        _write_head_and_watermark(conn, log_id, head, watermark)
    return inserted


def _write_head_and_watermark(conn, log_id, head, watermark):
    now = time.time()
    existing = get_confirmed_head(conn, log_id, head["tree_size"])
    if existing is not None and existing["root_hash"] != head["root_hash"]:
        raise ValueError("同一树大小出现不同已确认树根")
    conn.execute(
        "INSERT OR IGNORE INTO confirmed_heads VALUES(?,?,?,?,?,?,?,?,?,?)",
        (log_id, head["tree_size"], head["root_hash"], head["timestamp"],
         head["signature"], head.get("consistency_from_size"),
         head.get("proof_digest"), head["source_mirror"],
         head["response_digest"], now))
    old = current_watermark(conn, log_id)
    if old is not None:
        if watermark["tree_size"] < old["tree_size"]:
            raise ValueError("可发布水位不允许回退")
        if (watermark["tree_size"] == old["tree_size"]
                and watermark["root_hash"] != old["root_hash"]):
            raise ValueError("同一水位树根不允许改变")
    conn.execute(
        "INSERT INTO watermark VALUES(?,?,?,?) "
        "ON CONFLICT(log_id) DO UPDATE SET tree_size=excluded.tree_size,"
        "root_hash=excluded.root_hash,confirmed_at=excluded.confirmed_at",
        (log_id, watermark["tree_size"], watermark["root_hash"], now))


def upsert_backlog(conn, log_id, kind, item_key, detail):
    """登记/刷新待补项。"""
    now = time.time()
    with conn:
        row = conn.execute(
            "SELECT created_at FROM backlog WHERE log_id=? AND kind=? AND item_key=?",
            (log_id, kind, item_key)).fetchone()
        created = row[0] if row else now
        conn.execute(
            "INSERT INTO backlog VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(log_id,kind,item_key) DO UPDATE SET "
            "detail_json=excluded.detail_json,updated_at=excluded.updated_at",
            (log_id, kind, item_key,
             json.dumps(detail, ensure_ascii=False, sort_keys=True),
             created, now))


def resolve_backlog(conn, log_id, kind, item_key):
    with conn:
        conn.execute(
            "DELETE FROM backlog WHERE log_id=? AND kind=? AND item_key=?",
            (log_id, kind, item_key))


def list_backlog(conn, log_id):
    rows = conn.execute(
        "SELECT kind,item_key,detail_json,created_at,updated_at "
        "FROM backlog WHERE log_id=? ORDER BY kind,item_key", (log_id,)).fetchall()
    return [{"kind": r[0], "item_key": r[1], "detail": json.loads(r[2]),
             "created_at": r[3], "updated_at": r[4]} for r in rows]


def upsert_quarantine(conn, log_id, kind, item_key, classification, detail):
    """登记冲突或不可采信项；分类只能在三态之内且不允许降级。"""
    if classification not in CLASSIFICATIONS:
        raise ValueError("分类非法")
    now = time.time()
    with conn:
        row = conn.execute(
            "SELECT classification,created_at FROM quarantine "
            "WHERE log_id=? AND kind=? AND item_key=?",
            (log_id, kind, item_key)).fetchone()
        if row:
            order = {PENDING: 0, CONFLICT: 1, INADMISSIBLE: 1}
            if order[classification] < order[row[0]]:
                raise ValueError("问题分类不允许降级")
            created = row[1]
        else:
            created = now
        conn.execute(
            "INSERT INTO quarantine VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(log_id,kind,item_key) DO UPDATE SET "
            "classification=excluded.classification,detail_json=excluded.detail_json,"
            "updated_at=excluded.updated_at",
            (log_id, kind, item_key, classification,
             json.dumps(detail, ensure_ascii=False, sort_keys=True),
             created, now))


def list_quarantine(conn, log_id):
    rows = conn.execute(
        "SELECT kind,item_key,classification,detail_json,created_at,updated_at "
        "FROM quarantine WHERE log_id=? ORDER BY kind,item_key", (log_id,)).fetchall()
    return [{"kind": r[0], "item_key": r[1], "classification": r[2],
             "detail": json.loads(r[3]), "created_at": r[4],
             "updated_at": r[5]} for r in rows]


def published_certificates(conn, log_id):
    """正式结果：仅水位以下、含完整树版本追溯信息的证书。"""
    wm = current_watermark(conn, log_id)
    if wm is None:
        return {"watermark": None, "certificates": []}
    rows = conn.execute(
        "SELECT leaf_index,leaf_hash,certificate,subject,san_json,"
        "included_tree_size,root_hash,inclusion_proof_digest,source_mirror,"
        "response_digest FROM verified_leaves "
        "WHERE log_id=? AND leaf_index<? ORDER BY leaf_index",
        (log_id, wm["tree_size"])).fetchall()
    certs = [{"leaf_index": r[0], "leaf_hash": r[1], "certificate": r[2],
              "subject": r[3],
              "san": json.loads(r[4]) if r[4] is not None else None,
              "verified_tree_size": r[5], "verified_root_hash": r[6],
              "inclusion_proof_digest": r[7], "source_mirror": r[8],
              "response_digest": r[9]} for r in rows]
    return {"watermark": wm, "certificates": certs}
