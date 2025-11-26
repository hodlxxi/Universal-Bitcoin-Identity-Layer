# Privacy Policy for HODLXXI

**Last Updated:** October 29, 2025

## 1. Introduction

Welcome to HODLXXI ("we," "our," or "us"). This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use our Bitcoin-based chat and authentication application (the "Service").

By using HODLXXI, you agree to the collection and use of information in accordance with this Privacy Policy. If you do not agree with our policies and practices, please do not use the Service.

## 2. Information We Collect

### 2.1 Information You Provide

**Bitcoin Public Keys**: We collect and process Bitcoin public keys used for authentication and identity verification within the Service.

**Chat Messages**: Messages you send through our chat system are temporarily stored to facilitate real-time communication.

**OAuth/OIDC Data**: When using our OAuth2/OpenID Connect authentication system, we may collect:
- Client credentials (client_id, client_secret)
- Authorization codes and tokens
- Redirect URIs

### 2.2 Automatically Collected Information

**Session Data**: We collect session information including:
- Session identifiers
- Authentication status
- Timestamp of interactions

**Connection Information**: 
- IP addresses
- WebSocket connection identifiers
- User agent information
- Connection timestamps

**Technical Data**:
- Log files containing system activity
- Error reports and debugging information
- Performance metrics

### 2.3 Bitcoin and Blockchain Data

**Proof of Funds (PoF) Data**: When you use our Proof of Funds feature:
- PSBT (Partially Signed Bitcoin Transaction) data
- Challenge responses
- Unspent transaction outputs (UTXOs) referenced in proofs
- Aggregate balance attestations (time-limited, not permanent balance records)
- Privacy level preferences (aggregate, threshold, or boolean)

**Lightning Network Data**: When using LNURL-Auth:
- LNURL authentication challenges
- Lightning Network public keys
- Authentication timestamps

**Important Note**: We do NOT have custody of your Bitcoin. We only verify proofs of ownership through cryptographic signatures and PSBT analysis.

## 3. How We Use Your Information

We use the collected information for:

- **Authentication and Access Control**: Verifying your identity and managing access to the Service
- **Service Delivery**: Enabling real-time chat functionality and user-to-user communication
- **Security**: Preventing fraud, unauthorized access, and abuse of the Service
- **System Monitoring**: Maintaining system health, debugging, and improving performance
- **Proof of Funds Verification**: Validating Bitcoin holdings for reputation or access purposes (non-custodial)
- **OAuth/OIDC Integration**: Enabling third-party application authentication through our system

## 4. Data Retention

**Chat Messages**: Chat history is stored in memory during active sessions. Messages are not permanently stored unless explicitly configured otherwise.

**Session Data**: Session information expires and is removed after periods of inactivity.

**Proof of Funds Attestations**: PoF attestations are time-limited and automatically expire after 48 hours (configurable) unless renewed. These are NOT permanent balance records.

**Log Files**: System logs are retained for up to 10 rotations with a maximum file size of 10MB per rotation for debugging and security purposes.

**Authentication Challenges**: Authentication challenges expire within 15 minutes (900 seconds) of creation.

## 5. Information Sharing and Disclosure

We do NOT sell your personal information. We may share information only in the following circumstances:

**With Your Consent**: We may share your information when you explicitly authorize us to do so.

**Third-Party Services**: If you authorize third-party applications through our OAuth/OIDC system, we may share authentication tokens and authorized profile information with those applications.

**Legal Requirements**: We may disclose information if required by law, court order, or governmental request, or to protect our rights, property, or safety.

**Service Providers**: We may share information with service providers who assist in operating our Service (e.g., hosting providers), under strict confidentiality obligations.

**Blockchain Data**: Information you broadcast to the Bitcoin or Lightning Network blockchain is public by nature and is not subject to this Privacy Policy.

## 6. Data Security

We implement appropriate technical and security measures to protect your information:

- **Encryption**: Session data is protected using secure session management
- **Access Controls**: Secret keys and sensitive credentials are stored securely with restricted access permissions
- **Rate Limiting**: Protection against abuse and unauthorized access attempts
- **Secure Communication**: WebSocket connections for real-time communication
- **Database Security**: SQLite databases with Write-Ahead Logging (WAL) for data integrity
- **Non-Custodial Design**: We never have custody of your Bitcoin private keys

However, no method of transmission over the Internet or electronic storage is 100% secure. We cannot guarantee absolute security.

## 7. Your Rights and Choices

Depending on your jurisdiction, you may have the following rights:

**Access**: Request access to the information we hold about you
**Correction**: Request correction of inaccurate information
**Deletion**: Request deletion of your information (subject to retention requirements)
**Objection**: Object to certain processing of your information
**Portability**: Request transfer of your information to another service
**Withdrawal of Consent**: Withdraw consent for processing where consent is the legal basis

To exercise these rights, please contact us at [YOUR CONTACT EMAIL].

## 8. Cookies and Tracking

We use session cookies to:
- Maintain user authentication state
- Enable proper functioning of the Service
- Track user sessions for security purposes

You can configure your browser to refuse cookies, but this may limit functionality of the Service.

## 9. Third-Party Links

Our Service may contain links to third-party websites or services. We are not responsible for the privacy practices of these third parties. We encourage you to review their privacy policies.

## 10. Children's Privacy

Our Service is not intended for children under 13 (or 16 in the European Union). We do not knowingly collect personal information from children. If you become aware that a child has provided us with personal information, please contact us immediately.

## 11. International Data Transfers

Your information may be transferred to and processed in countries other than your country of residence. These countries may have data protection laws different from your jurisdiction. By using the Service, you consent to such transfers.

## 12. California Privacy Rights (CCPA)

If you are a California resident, you have specific rights under the California Consumer Privacy Act:

- Right to know what personal information is collected
- Right to know if personal information is sold or disclosed
- Right to opt-out of the sale of personal information (Note: We do not sell personal information)
- Right to deletion of personal information
- Right to non-discrimination for exercising CCPA rights

## 13. European Union Privacy Rights (GDPR)

If you are in the European Economic Area (EEA), you have rights under the General Data Protection Regulation:

**Legal Basis for Processing**: We process your data based on:
- Consent: You have given clear consent for processing
- Contract: Processing is necessary for our contract with you
- Legal Obligation: Processing is required by law
- Legitimate Interests: Processing is necessary for our legitimate interests

**Data Protection Officer**: [If applicable, provide DPO contact information]

## 14. Changes to This Privacy Policy

We may update this Privacy Policy from time to time. We will notify you of material changes by:
- Posting the new Privacy Policy on this page
- Updating the "Last Updated" date
- Sending notification through the Service (if applicable)

Your continued use of the Service after changes become effective constitutes acceptance of the revised Privacy Policy.

## 15. Contact Us

If you have questions about this Privacy Policy or our data practices, please contact us:

**Email**: [YOUR CONTACT EMAIL]  
**Address**: [YOUR PHYSICAL ADDRESS]  
**Website**: [YOUR WEBSITE]

---

## Appendix: Technical Details for Developers

### Data Storage

- **Session Storage**: Flask session management with secure secret keys
- **In-Memory Storage**: Real-time chat history (CHAT_HISTORY), online users (ONLINE_USERS), active sockets (ACTIVE_SOCKETS)
- **SQLite Database**: Proof of Funds attestations (pof_attest.db) with WAL journaling
- **OAuth Storage**: In-memory OAuth tokens and client data (production should use Redis)

### Data Transmission

- **WebSockets**: SocketIO for real-time communication
- **HTTPS**: All HTTP traffic should be encrypted in production
- **Bitcoin RPC**: Encrypted connection to Bitcoin Core node

### Privacy Features

- **Non-Custodial**: No private key storage
- **Time-Limited Attestations**: PoF data automatically expires
- **Privacy Levels**: Configurable PoF privacy (aggregate, threshold, boolean)
- **No Permanent Balance Storage**: PoF is proof of ownership, not a balance database
