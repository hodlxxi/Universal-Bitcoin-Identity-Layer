# Frequently Asked Questions

Honest answers to common questions about HODLXXI.

---

## General Questions

### What problem does HODLXXI solve?

HODLXXI explores whether long-term cooperation can emerge from cryptographic commitments rather than legal contracts or social trust.

It does not claim to solve all coordination problems.  
It attempts to solve a specific subset: making commitments durable, observable, and costly to fake.

### Is this proven to work?

No.

HODLXXI is experimental software.  
It has not been stress-tested at scale.  
It may fail in unexpected ways.

### Who created HODLXXI?

HODLXXI was created by an independent developer working pseudonymously.

The creator does not have special privileges in the system.  
The project is open source and can be forked by anyone.

### Is there a company behind this?

No.

There is no corporation, no board of directors, no shareholders.  
HODLXXI is a research project, not a business.

### How is this funded?

The project is self-funded.  
Grant applications to OpenSats and HRF are in progress.  
No venture capital is involved.

---

## Technical Questions

### What blockchain does HODLXXI use?

Bitcoin.

HODLXXI does not have its own blockchain or token.  
It builds on Bitcoin's security and finality guarantees.

### Is this a Layer 2 solution?

Not exactly.

HODLXXI uses Bitcoin's base layer for commitments and identity.  
It plans to integrate Lightning Network for micropayments and real-time interactions.

### Do I need to run a Bitcoin node?

Not required, but recommended.

You can use SPV (Simplified Payment Verification) wallets.  
Running a full node gives you maximum verification and privacy.

### What if I lose my private keys?

You lose access to your identity and time-locked funds.

HODLXXI cannot recover lost keys.  
There is no customer support to call.  
Key management is your responsibility.

### Can transactions be reversed?

No.

Once a time-lock is created, it cannot be reversed.  
Once a transaction is confirmed on Bitcoin, it is final.

This is by design, not a bug.

### Is this compatible with hardware wallets?

Yes.

HODLXXI works with any Bitcoin wallet that supports:
- Message signing
- PSBTs (Partially Signed Bitcoin Transactions)
- Descriptor wallets (for advanced features)

### What about privacy?

HODLXXI supports pseudonymity, not anonymity.

Your Bitcoin addresses are visible on the blockchain.  
Transaction patterns can be analyzed.  
Complete privacy is not guaranteed.

If you need stronger privacy, use:
- CoinJoin before participating
- Separate identities for different contexts
- Tor for network-level privacy

---

## Economic Questions

### Is there a token?

No.

HODLXXI does not have a native token.  
It does not issue coins, NFTs, or governance tokens.

### Can I make money with this?

HODLXXI is not an investment.

It does not promise returns.  
It does not have yields, staking rewards, or airdrops.

If you're looking for financial gain, this is not for you.

### What are the fees?

You pay standard Bitcoin transaction fees.

HODLXXI does not charge additional fees.  
There is no subscription or premium tier.

### Is this a scam?

No.

But you should verify this yourself:
- Code is open source on GitHub
- No promises of guaranteed returns
- No pressure to invest
- No celebrity endorsements
- No "whitelist" or "presale"

If it looks like a scam to you, don't use it.

---

## Security Questions

### Has this been audited?

Not yet.

Security audits are planned but not completed.  
Use at your own risk.

### What if there's a bug?

Bugs are possible and likely.

The code is open source so anyone can review it.  
Formal verification is planned for critical components.

If you find a bug, please report it responsibly.

### Can the government shut this down?

They can try, but it's difficult.

HODLXXI is:
- Open source (code is public)
- Decentralized (no central server)
- Built on Bitcoin (censorship-resistant base layer)

However:
- Governments can pressure service providers
- They can make usage illegal
- They can prosecute users

HODLXXI does not provide legal immunity.

### Is this legal?

Probably, but it depends on your jurisdiction.

Consult a lawyer in your country.  
HODLXXI does not provide legal advice.

---

## Philosophical Questions

### Why 21 years?

21 years is roughly:
- The time from birth to adulthood
- One full generation
- Long enough to experience consequences of decisions made today

It's a symbolic and practical time horizon.

### Why Bitcoin specifically?

Bitcoin provides:
- Decentralized consensus
- Immutable record-keeping
- Longest-running proof-of-work chain
- Maximum security and finality

Other blockchains may be faster or cheaper, but none have Bitcoin's track record.

### What if Bitcoin fails?

If Bitcoin fails, HODLXXI fails.

The project makes no claims of independence from Bitcoin's success.

### Is this anti-government?

No.

HODLXXI is not a political statement.  
It does not advocate for or against any government system.

It simply explores what becomes possible when cryptography replaces institutional trust.

### Is this a cult?

No.

There is no charismatic leader.  
There is no dogma to accept.  
There is no community pressure to conform.

If it starts feeling like a cult, leave immediately.

---

## Practical Questions

### How do I get started?

1. Read [What Is HODLXXI?](what_is_hodlxxi)
2. Understand [How It Works](how_it_works)
3. Review [Principles & Invariants](principles)
4. Set up a Bitcoin wallet with signing capability
5. Visit hodlxxi.com and authenticate with your Bitcoin key

### Do I need programming skills?

Not required, but helpful.

You need to:
- Manage Bitcoin keys safely
- Understand basic blockchain concepts
- Be comfortable with command-line tools (optional)

### What can I do with HODLXXI right now?

Currently:
- Create Bitcoin-based identity
- Make time-locked commitments
- Verify others' commitments
- Build reputation through observable actions

Future features:
- Lightning integration
- Nostr interoperability
- Advanced covenant structures

### Can I contribute?

Yes.

HODLXXI is open source.  
Contributions welcome via GitHub.

You can contribute:
- Code improvements
- Documentation
- Bug reports
- Design feedback

### Where can I get help?

- GitHub Issues: Technical problems
- Documentation: Read this library
- Community: (Nostr/Matrix channels coming soon)

There is no official support team.  
Community help is best-effort only.

---

## Meta Questions

### Why are you so negative about your own project?

Honesty over hype.

HODLXXI documents its limitations openly.  
This builds trust more than marketing promises.

### What if I still have questions?

Read the [Technical Documentation](../index#layer-2-technical-documentation).

If your question is not answered, open a GitHub issue.

### Can I fork this project?

Yes, absolutely.

The code is open source (MIT License).  
Fork it, modify it, improve it.

If you make something better, please share it.

---

*These answers are accurate as of December 2024.*  
*The project evolves. Check for updates regularly.*
