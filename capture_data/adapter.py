import json
def decode(raw, manifest):
    doc=json.loads(raw.decode('utf-8'));size=doc['tree_size']
    if type(size)!=int or size<0:raise ValueError('树大小非法')
    root=f'{size}/{doc["sha256_root_hash"]}'
    records=[{'kind':'tree_size','id':str(size),'version':str(doc['timestamp']),'refs':[],
              'payload':{'signature':doc['tree_head_signature']}},
             {'kind':'tree_root','id':root,'version':str(doc['timestamp']),'refs':[str(size)],
              'payload':{'root_hash':doc['sha256_root_hash']}}]
    for leaf in doc['entries']:
        if type(leaf['index'])!=int or leaf['index']>=size:raise ValueError('叶子索引越界')
        records.append({'kind':'leaf','id':f'leaf/{leaf["index"]}','version':str(size),
                        'refs':[root],'payload':{'leaf_input':leaf['leaf_input']}})
    records.append({'kind':'proof','id':f'{doc["proof"]["first"]}/{size}','version':str(doc['timestamp']),
                    'refs':[root],'payload':doc['proof']})
    return {'protocol':manifest['protocol'],'collection':manifest['collection'],'records':records}
