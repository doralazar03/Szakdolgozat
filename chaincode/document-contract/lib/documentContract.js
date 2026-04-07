'use strict';
const { Contract } = require('fabric-contract-api');

class DocumentContract extends Contract {

  _makeDocVersionKey(documentId, version) {
    return `doc::${documentId}::${version}`;
  }

  _makeHashKey(contentHash) {
    return `hash::${contentHash}`;
  }

  _makeDocIdKey(documentId) {
    return `docid::${documentId}`;
  }

  _makeLatestKey(documentId) {
    return `latest::${documentId}`;
  }

  async initLedger(ctx) {
    console.info('Ledger initialized');
  }

  _isAllowedStatus(s) {
  return ['REGISTERED', 'REVOKED', 'ARCHIVED'].includes(s);
}

_isAllowedTransition(oldStatus, newStatus) {
  if (oldStatus === newStatus) return true;

  if (oldStatus === 'REVOKED') return false;

  if (oldStatus === 'REGISTERED' && (newStatus === 'ARCHIVED' || newStatus === 'REVOKED')) return true;

  if (oldStatus === 'ARCHIVED' && newStatus === 'REVOKED') return true;

  return false;
}


  
  async registerDocumentVersion(ctx, documentId, version, contentHash, owner, metadata) {
    if (!documentId || !version || !contentHash || !owner) {
      throw new Error('documentId, version, contentHash, owner are required');
    }

    const v = parseInt(version, 10);
    if (Number.isNaN(v) || v < 1) {
      throw new Error('version must be a positive integer');
    }

    const hashKey = this._makeHashKey(contentHash);
    const hashExisting = await ctx.stub.getState(hashKey);

    if (hashExisting && hashExisting.length > 0) {
      const ref = JSON.parse(hashExisting.toString()); 

      const existingDocKey = this._makeDocVersionKey(ref.documentId, ref.version);
      const existingDocBytes = await ctx.stub.getState(existingDocKey);

      let doc = null;
      if (existingDocBytes && existingDocBytes.length > 0) {
        doc = JSON.parse(existingDocBytes.toString());
      }

      throw new Error(
        'DUPLICATE_HASH:' +
        JSON.stringify({
          code: 'DUPLICATE_HASH',
          message: 'This contentHash already exists on ledger',
          documentId: ref.documentId,
          version: ref.version,
          contentHash,
          doc
        })
      );
    }

    const docKey = this._makeDocVersionKey(documentId, v);
    const existing = await ctx.stub.getState(docKey);
    if (existing && existing.length > 0) {
      throw new Error(`Version ${v} already exists for document ${documentId}`);
    }

    let previousHash = null;
    if (v > 1) {
      const prevKey = this._makeDocVersionKey(documentId, v - 1);
      const prevBytes = await ctx.stub.getState(prevKey);
      if (!prevBytes || prevBytes.length === 0) {
        throw new Error(`Previous version not found: ${documentId} v${v - 1}`);
      }
      const prev = JSON.parse(prevBytes.toString());
      previousHash = prev.contentHash;
    }

    const ts = ctx.stub.getTxTimestamp();
    const ms = (ts.seconds.low * 1000) + Math.floor(ts.nanos / 1e6);
    const createdAt = new Date(ms).toISOString();

    const txId = ctx.stub.getTxID();
    const mspId = ctx.clientIdentity.getMSPID();

    const record = {
      documentId,
      version: v,
      contentHash,
      previousHash,
      owner,
      metadata,
      status: 'REGISTERED',
      createdAt,
      createdByMSP: mspId,
      txId
    };

    await ctx.stub.putState(docKey, Buffer.from(JSON.stringify(record)));

    await ctx.stub.putState(hashKey, Buffer.from(JSON.stringify({
      documentId,
      version: v
    })));

    const docIdKey = this._makeDocIdKey(documentId);
    const docIdBytes = await ctx.stub.getState(docIdKey);
    if (!docIdBytes || docIdBytes.length === 0) {
      await ctx.stub.putState(docIdKey, Buffer.from(JSON.stringify({
        documentId,
        firstSeenAt: createdAt
      })));
    }

    const latestKey = this._makeLatestKey(documentId);
    await ctx.stub.putState(latestKey, Buffer.from(JSON.stringify({
      documentId,
      version: v,
      contentHash,
      owner,
      status: record.status,
      createdAt,
      createdByMSP: mspId,
      txId
    })));

    return JSON.stringify(record);
  }

  async getByHash(ctx, contentHash) {
    const hashKey = this._makeHashKey(contentHash);
    const hashBytes = await ctx.stub.getState(hashKey);

    if (!hashBytes || hashBytes.length === 0) {
      return JSON.stringify({ exists: false });
    }

    const ref = JSON.parse(hashBytes.toString());
    const docKey = this._makeDocVersionKey(ref.documentId, ref.version);
    const docBytes = await ctx.stub.getState(docKey);

    if (!docBytes || docBytes.length === 0) {
      return JSON.stringify({ exists: false });
    }

    const doc = JSON.parse(docBytes.toString());
    return JSON.stringify({ exists: true, doc });
  }

  async listVersions(ctx, documentId) {
    const start = `doc::${documentId}::`;
    const end = `doc::${documentId}::~`;

    const iterator = await ctx.stub.getStateByRange(start, end);
    const out = [];

    while (true) {
      const res = await iterator.next();
      if (res.value && res.value.value) {
        out.push(JSON.parse(res.value.value.toString()));
      }
      if (res.done) {
        await iterator.close();
        break;
      }
    }

    out.sort((a, b) => a.version - b.version);
    return JSON.stringify({ documentId, versions: out });
  }

  async listDocumentIds(ctx) {
    const iterator = await ctx.stub.getStateByRange('docid::', 'docid::~');
    const out = [];

    while (true) {
      const res = await iterator.next();
      if (res.value && res.value.value) {
        out.push(JSON.parse(res.value.value.toString()));
      }
      if (res.done) {
        await iterator.close();
        break;
      }
    }

    out.sort((a, b) => (a.documentId || '').localeCompare(b.documentId || ''));
    return JSON.stringify({ items: out });
  }

  async getLatest(ctx, documentId) {
    const key = this._makeLatestKey(documentId);
    const bytes = await ctx.stub.getState(key);

    if (!bytes || bytes.length === 0) {
      return JSON.stringify({ exists: false });
    }

    return JSON.stringify({ exists: true, doc: JSON.parse(bytes.toString()) });
  }

async updateStatus(ctx, documentId, version, newStatus) {
  if (!documentId || !version || !newStatus) {
    throw new Error('documentId, version, newStatus are required');
  }

  const v = parseInt(version, 10);
  if (Number.isNaN(v) || v < 1) {
    throw new Error('version must be a positive integer');
  }

  const status = String(newStatus).toUpperCase().trim();
  if (!this._isAllowedStatus(status)) {
    throw new Error(`Invalid status: ${status}. Allowed: REGISTERED, REVOKED, ARCHIVED`);
  }

  const key = this._makeDocVersionKey(documentId, v);
  const bytes = await ctx.stub.getState(key);
  if (!bytes || bytes.length === 0) {
    throw new Error(`Document version not found: ${documentId} v${v}`);
  }

  const doc = JSON.parse(bytes.toString());
  const oldStatus = (doc.status || 'REGISTERED').toUpperCase();

  if (!this._isAllowedTransition(oldStatus, status)) {
    throw new Error(`Invalid status transition: ${oldStatus} -> ${status}`);
  }

  doc.status = status;


  await ctx.stub.putState(key, Buffer.from(JSON.stringify(doc)));

  const latestKey = this._makeLatestKey(documentId);
  const latestBytes = await ctx.stub.getState(latestKey);
  if (latestBytes && latestBytes.length > 0) {
    const latest = JSON.parse(latestBytes.toString());
    if (latest.version === v) {
      latest.status = status;
      await ctx.stub.putState(latestKey, Buffer.from(JSON.stringify(latest)));
    }
  }

  return JSON.stringify(doc);
}
}

module.exports = DocumentContract;