"""未完成密码学验证的树头和叶子不进入可信视图。"""
def assess(rows):
    roots=[r for r in rows if r['kind']=='tree_root']
    leaves=[r for r in rows if r['kind']=='leaf']
    reasons=[]
    if any(not r['payload'].get('signature_verified') for r in rows if r['kind']=='tree_size'):reasons.append('检查点签名未核验')
    if any(not r['payload'].get('consistency_verified') for r in rows if r['kind']=='proof'):reasons.append('追加一致性证明未核验')
    if any(not r['payload'].get('inclusion_verified') for r in leaves):reasons.append('叶子包含证明未核验')
    return {'publishable':not reasons,'reasons':reasons,'candidate_roots':[r['id'] for r in roots]}
