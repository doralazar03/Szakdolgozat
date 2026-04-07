'use strict';
const { Contract } = require('fabric-contract-api');

class DocumentContract extends Contract {

  async initLedger(ctx) {
    console.info('Ledger initialized');
  }

  async registerDocument(ctx, docHash, owner, metadata) {
    const exists = await this.documentExists(ctx, docHash);
    if (exists) {
      throw new Error(`Document ${docHash} already exists`);
    }

    const doc = {
      docHash,
      owner,
      metadata,
      timestamp: new Date().toISOString(),
      status: 'REGISTERED'
    };

    await ctx.stub.putState(docHash, Buffer.from(JSON.stringify(doc)));
    return JSON.stringify(doc);
  }

  async verifyDocument(ctx, docHash) {
    const data = await ctx.stub.getState(docHash);
    if (!data || data.length === 0) {
      return JSON.stringify({ exists: false });
    }
    const doc = JSON.parse(data.toString());
    return JSON.stringify({ exists: true, doc });
  }

  async documentExists(ctx, docHash) {
    const data = await ctx.stub.getState(docHash);
    return data && data.length > 0;
  }

  async updateStatus(ctx, docHash, newStatus) {
    const data = await ctx.stub.getState(docHash);
    if (!data || data.length === 0) {
      throw new Error(`Document ${docHash} not found`);
    }
    const doc = JSON.parse(data.toString());
    doc.status = newStatus;
    await ctx.stub.putState(docHash, Buffer.from(JSON.stringify(doc)));
    return JSON.stringify(doc);
  }
}

module.exports = DocumentContract;
