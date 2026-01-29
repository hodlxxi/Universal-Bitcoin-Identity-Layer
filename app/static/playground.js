// HODLXXI Playground JavaScript
// Handles all interactions, WebLN, Lightning auth, PoF, sharing, animations

// ============================================================================
// CONFIGURATION
// ============================================================================

const API_BASE = window.location.origin;
const SOCKET_URL = window.location.origin;

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

let currentUser = {
    npub: null,
    btcAmount: null,
    proofOfFunds: null,
    authenticated: false
};

let pofSettings = {
    amount: 0.1,
    privacyMode: 'threshold'
};

// ============================================================================
// MATRIX BACKGROUND ANIMATION
// ============================================================================

function initMatrixBackground() {
    const canvas = document.getElementById('matrix-bg');
    const ctx = canvas.getContext('2d');
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const chars = '₿⚡01アイウエオカキクケコサシスセソタチツテト';
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = Array(Math.floor(columns)).fill(1);
    
    function draw() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = '#f7931a';
        ctx.font = `${fontSize}px monospace`;
        
        for (let i = 0; i < drops.length; i++) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }
    
    setInterval(draw, 35);
    
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// ============================================================================
// ACCORDION FUNCTIONALITY
// ============================================================================

function initAccordion() {
    document.querySelectorAll('.accordion-toggle').forEach(toggle => {
        toggle.addEventListener('click', () => {
            const target = toggle.dataset.target;
            const content = document.getElementById(target);
            const arrow = toggle.querySelector('svg');
            
            // Toggle active state
            content.classList.toggle('active');
            arrow.classList.toggle('rotate-180');
        });
    });
}

// ============================================================================
// WEBLN & LIGHTNING AUTHENTICATION
// ============================================================================

async function checkWebLN() {
    if (typeof window.webln !== 'undefined') {
        try {
            await window.webln.enable();
            return true;
        } catch (err) {
            console.error('WebLN enable failed:', err);
            return false;
        }
    }
    return false;
}

async function loginWithLightning(walletName = 'webln') {
    try {
        showLoading('Connecting to your wallet...');
        
        // Check if WebLN is available
        const hasWebLN = await checkWebLN();
        
        if (!hasWebLN && walletName === 'webln') {
            // Fall back to QR code
            showQRAuth();
            return;
        }
        
        // Request LNURL-auth challenge from backend
        const response = await fetch(`${API_BASE}/lnurl/auth`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                wallet: walletName
            })
        });
        
        const data = await response.json();
        
        if (data.lnurl) {
            // Use WebLN to authenticate
            if (hasWebLN) {
                try {
                    const result = await window.webln.lnurl(data.lnurl);
                    
                    // Poll for authentication status
                    await pollAuthStatus(data.k1 || data.challenge_id);
                } catch (err) {
                    console.error('WebLN LNURL failed:', err);
                    showError('Authentication failed. Please try again.');
                }
            } else {
                // Show QR code for mobile wallets
                showQRCode(data.lnurl, data.k1 || data.challenge_id);
            }
        } else {
            throw new Error('Failed to get auth challenge');
        }
        
    } catch (error) {
        console.error('Login error:', error);
        showError('Login failed. Please try again.');
    } finally {
        hideLoading();
    }
}

async function pollAuthStatus(challengeId, maxAttempts = 30) {
    let attempts = 0;
    
    const poll = setInterval(async () => {
        attempts++;
        
        try {
            const response = await fetch(`${API_BASE}/lnurl/auth/status?challenge_id=${challengeId}`);
            const data = await response.json();
            
            if (data.authenticated) {
                clearInterval(poll);
                onAuthSuccess(data);
            } else if (attempts >= maxAttempts) {
                clearInterval(poll);
                showError('Authentication timeout. Please try again.');
            }
        } catch (error) {
            console.error('Poll error:', error);
        }
    }, 1000);
}

function onAuthSuccess(data) {
    // Update user state
    currentUser.authenticated = true;
    currentUser.npub = data.npub || data.pubkey;
    currentUser.btcAmount = data.btc_balance || null;
    
    // Show confetti!
    celebrateLogin();
    
    // Update UI
    updateUIAfterLogin();
    
    // Show tweet template
    showTweetTemplate('login');
}

function celebrateLogin() {
    // Confetti animation
    const duration = 3 * 1000;
    const animationEnd = Date.now() + duration;
    const defaults = { startVelocity: 30, spread: 360, ticks: 60, zIndex: 9999 };
    
    function randomInRange(min, max) {
        return Math.random() * (max - min) + min;
    }
    
    const interval = setInterval(() => {
        const timeLeft = animationEnd - Date.now();
        
        if (timeLeft <= 0) {
            return clearInterval(interval);
        }
        
        const particleCount = 50 * (timeLeft / duration);
        
        confetti({
            ...defaults,
            particleCount,
            origin: { x: randomInRange(0.1, 0.3), y: Math.random() - 0.2 },
            colors: ['#f7931a', '#e8830f', '#00ff41']
        });
        confetti({
            ...defaults,
            particleCount,
            origin: { x: randomInRange(0.7, 0.9), y: Math.random() - 0.2 },
            colors: ['#f7931a', '#e8830f', '#00ff41']
        });
    }, 250);
    
    // Optional: Play success sound
    // playSuccessSound();
}

function updateUIAfterLogin() {
    // Hide logged-out hero
    document.getElementById('hero-logged-out').classList.add('hidden');
    
    // Show logged-in hero
    const heroLoggedIn = document.getElementById('hero-logged-in');
    heroLoggedIn.classList.remove('hidden');
    
    // Update user info
    document.getElementById('user-npub').textContent = formatNpub(currentUser.npub);
    
    if (currentUser.btcAmount) {
        document.getElementById('user-btc-amount').textContent = `₿ ${currentUser.btcAmount.toFixed(5)}`;
    } else {
        document.getElementById('user-btc-amount').textContent = '₿ verified';
    }
}

// ============================================================================
// QR CODE AUTHENTICATION
// ============================================================================

function showQRAuth() {
    const qrContainer = document.getElementById('qr-container');
    qrContainer.classList.remove('hidden');
    
    // Generate LNURL-auth QR
    generateLNURLAuthQR();
}

async function generateLNURLAuthQR() {
    try {
        const response = await fetch(`${API_BASE}/lnurl/auth`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.lnurl) {
            // Use a QR code library (you'll need to add this)
            // For now, show the LNURL as text
            const qrCode = document.getElementById('qr-code');
            qrCode.innerHTML = `
                <div class="text-center p-4">
                    <p class="text-xs text-gray-500 mb-2">LNURL-auth</p>
                    <p class="text-xs font-mono break-all">${data.lnurl}</p>
                    <p class="text-xs text-gray-400 mt-3">Scan with any Lightning wallet</p>
                </div>
            `;
            
            // Poll for authentication
            await pollAuthStatus(data.k1 || data.challenge_id);
        }
    } catch (error) {
        console.error('QR generation error:', error);
    }
}

document.getElementById('show-qr-btn')?.addEventListener('click', showQRAuth);

// ============================================================================
// PROOF OF FUNDS
// ============================================================================

function initProofOfFunds() {
    const slider = document.getElementById('pof-slider');
    const amountDisplay = document.getElementById('pof-amount');
    
    slider?.addEventListener('input', (e) => {
        pofSettings.amount = parseFloat(e.target.value);
        amountDisplay.textContent = pofSettings.amount.toFixed(2);
    });
    
    // Privacy mode buttons
    document.querySelectorAll('.privacy-mode-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active state from all buttons
            document.querySelectorAll('.privacy-mode-btn').forEach(b => {
                b.classList.remove('border-bitcoin');
                b.classList.add('border-transparent');
            });
            
            // Add active state to clicked button
            btn.classList.remove('border-transparent');
            btn.classList.add('border-bitcoin');
            
            pofSettings.privacyMode = btn.dataset.mode;
        });
    });
    
    // Prove funds button
    document.getElementById('prove-funds-btn')?.addEventListener('click', proveFunds);
}

async function proveFunds() {
    if (!currentUser.authenticated) {
        showError('Please login with Lightning first!');
        return;
    }
    
    try {
        showLoading('Generating cryptographic proof...');
        
        const response = await fetch(`${API_BASE}/api/proof-of-funds`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('hodlxxi_token')}`
            },
            body: JSON.stringify({
                threshold: pofSettings.amount,
                privacy_mode: pofSettings.privacyMode
            })
        });
        
        const data = await response.json();
        
        if (data.success && data.proof) {
            // Determine whale tier
            const tier = getWhaleTier(pofSettings.amount);
            
            // Show badge
            showProofBadge(tier, data.share_link);
            
            // Store proof
            currentUser.proofOfFunds = {
                amount: pofSettings.amount,
                tier: tier,
                shareLink: data.share_link
            };
            
            // Celebrate!
            celebrateProof();
        } else {
            throw new Error(data.message || 'Proof generation failed');
        }
        
    } catch (error) {
        console.error('PoF error:', error);
        showError('Failed to generate proof. Please try again.');
    } finally {
        hideLoading();
    }
}

function getWhaleTier(amount) {
    if (amount >= 10) return { name: 'Humpback Whale', emoji: '🐋', color: '#FFD700' };
    if (amount >= 5) return { name: 'Whale', emoji: '🐳', color: '#C0C0C0' };
    if (amount >= 1) return { name: 'Shark', emoji: '🦈', color: '#CD7F32' };
    if (amount >= 0.5) return { name: 'Dolphin', emoji: '🐬', color: '#4169E1' };
    if (amount >= 0.1) return { name: 'Fish', emoji: '🐟', color: '#32CD32' };
    if (amount >= 0.05) return { name: 'Octopus', emoji: '🐙', color: '#9370DB' };
    if (amount >= 0.01) return { name: 'Crab', emoji: '🦀', color: '#FF6347' };
    return { name: 'Shrimp', emoji: '🦐', color: '#FFA500' };
}

function showProofBadge(tier, shareLink) {
    const container = document.getElementById('pof-badge-container');
    const badge = document.getElementById('pof-badge');
    const linkDisplay = document.getElementById('share-link');
    
    // Update badge content
    badge.innerHTML = `
        <span class="text-4xl">${tier.emoji}</span>
        <span>Certified ${tier.name}</span>
    `;
    badge.style.background = `linear-gradient(135deg, ${tier.color} 0%, ${tier.color}dd 100%)`;
    
    // Update share link
    linkDisplay.textContent = shareLink;
    
    // Show container
    container.classList.remove('hidden');
    
    // Scroll to badge
    container.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function celebrateProof() {
    // More confetti!
    confetti({
        particleCount: 100,
        spread: 70,
        origin: { y: 0.6 },
        colors: ['#f7931a', '#e8830f', '#FFD700']
    });
}

// ============================================================================
// SHARING & TWEET TEMPLATES
// ============================================================================

function showTweetTemplate(type) {
    let tweetText = '';
    
    if (type === 'login') {
        tweetText = `Just logged into @hodlxxi playground with my Lightning wallet in 4 seconds. This is the future. ${window.location.origin}/play`;
    } else if (type === 'pof' && currentUser.proofOfFunds) {
        const tier = currentUser.proofOfFunds.tier;
        tweetText = `Just proved I'm a ₿${pofSettings.amount}+ ${tier.emoji} on @hodlxxi\n\nNo KYC. No emails. Just cryptographic proof.\n\n${currentUser.proofOfFunds.shareLink}`;
    }
    
    // For now, just copy to clipboard and show success
    // In production, you'd open Twitter intent URL
    if (tweetText) {
        copyToClipboard(tweetText);
        showSuccess('Tweet template copied! Open Twitter to paste.');
    }
}

document.getElementById('share-twitter-btn')?.addEventListener('click', () => {
    showTweetTemplate('pof');
    
    // Also open Twitter intent
    const tweetText = encodeURIComponent(`Just proved I'm a ₿${pofSettings.amount}+ holder on @hodlxxi 🐳\n\nNo KYC. No emails. Just cryptographic proof.\n\n${currentUser.proofOfFunds.shareLink}`);
    window.location.href = `https://twitter.com/intent/tweet?text=${tweetText}`;
});

document.getElementById('copy-link-btn')?.addEventListener('click', () => {
    if (currentUser.proofOfFunds) {
        copyToClipboard(currentUser.proofOfFunds.shareLink);
        showSuccess('Link copied to clipboard!');
    }
});

// ============================================================================
// GATED EXPERIENCES (TEMPLATES)
// ============================================================================

function initGatedTemplates() {
    document.querySelectorAll('.template-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const template = btn.dataset.template;
            createGatedExperience(template);
        });
    });
}

async function createGatedExperience(template) {
    if (!currentUser.authenticated) {
        showError('Please login with Lightning first!');
        return;
    }
    
    showLoading('Creating your gated experience...');
    
    try {
        const response = await fetch(`${API_BASE}/api/gated/create`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('hodlxxi_token')}`
            },
            body: JSON.stringify({
                template: template,
                threshold: 0.1, // Default threshold
                creator: currentUser.npub
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(`Created! Share this link: ${data.url}`);
            
            // Copy link to clipboard
            copyToClipboard(data.url);
        } else {
            throw new Error(data.message);
        }
    } catch (error) {
        console.error('Template creation error:', error);
        showError('Failed to create experience. Coming Q1 2026!');
    } finally {
        hideLoading();
    }
}

// ============================================================================
// BITCOIN SIGNATURE MESSAGE
// ============================================================================

function initSignatureMessage() {
    const messageTemplate = document.getElementById('message-template');
    const messageTextarea = document.getElementById('signature-message');
    
    messageTemplate?.addEventListener('change', (e) => {
        if (e.target.value === 'control') {
            messageTextarea.value = 'I control this npub/key';
        } else if (e.target.value === 'login') {
            const nonce = Math.random().toString(36).substring(7);
            messageTextarea.value = `login:hodlxxi:${nonce}`;
        } else if (e.target.value === 'custom') {
            messageTextarea.value = '';
            messageTextarea.focus();
        }
    });
    
    // Initialize with default message
    if (messageTextarea) {
        messageTextarea.value = 'I control this npub/key';
    }
    
    document.getElementById('sign-message-btn')?.addEventListener('click', signMessage);
}

async function signMessage() {
    if (!currentUser.authenticated) {
        showError('Please login with Lightning first!');
        return;
    }
    
    const message = document.getElementById('signature-message').value;
    
    if (!message.trim()) {
        showError('Please enter a message to sign');
        return;
    }
    
    try {
        showLoading('Signing message...');
        
        // Try WebLN signMessage if available
        if (typeof window.webln !== 'undefined') {
            const result = await window.webln.signMessage(message);
            
            showSignatureResult(message, result.signature);
        } else {
            // Fall back to API
            const response = await fetch(`${API_BASE}/api/signature/create`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('hodlxxi_token')}`
                },
                body: JSON.stringify({ message })
            });
            
            const data = await response.json();
            
            if (data.signature) {
                showSignatureResult(message, data.signature);
            } else {
                throw new Error('Failed to sign message');
            }
        }
        
    } catch (error) {
        console.error('Signing error:', error);
        showError('Failed to sign message. Please try again.');
    } finally {
        hideLoading();
    }
}

function showSignatureResult(message, signature) {
    const resultDiv = document.getElementById('signature-result');
    document.getElementById('signed-message').textContent = message;
    document.getElementById('signature-value').textContent = signature;
    
    resultDiv.classList.remove('hidden');
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
    
    showSuccess('Message signed successfully!');
}

// ============================================================================
// SOCKET.IO LIVE FEED
// ============================================================================

function initLiveFeed() {
    const socket = io(SOCKET_URL);
    
    socket.on('connect', () => {
        console.log('Connected to live feed');
    });
    
    socket.on('activity', (data) => {
        addFeedItem(data);
    });
    
    socket.on('disconnect', () => {
        console.log('Disconnected from live feed');
    });
}

function addFeedItem(data) {
    const feed = document.getElementById('live-feed');
    
    let itemHTML = '';
    
    if (data.type === 'proof_of_funds') {
        itemHTML = `
            <div class="feed-item glass rounded-lg p-4 text-sm">
                <span class="text-gray-400">Someone just proved</span>
                <span class="text-bitcoin font-bold">₿${data.amount}+</span>
                <span class="text-gray-400">holdings</span>
            </div>
        `;
    } else if (data.type === 'covenant') {
        itemHTML = `
            <div class="feed-item glass rounded-lg p-4 text-sm">
                <span class="text-gray-400">New covenant created:</span>
                <span class="text-bitcoin font-bold">${data.description}</span>
            </div>
        `;
    } else if (data.type === 'login') {
        itemHTML = `
            <div class="feed-item glass rounded-lg p-4 text-sm">
                <span class="text-bitcoin font-bold">New user</span>
                <span class="text-gray-400">just logged in with Lightning</span>
            </div>
        `;
    }
    
    if (itemHTML) {
        feed.insertAdjacentHTML('afterbegin', itemHTML);
        
        // Keep only last 10 items
        const items = feed.querySelectorAll('.feed-item');
        if (items.length > 10) {
            items[items.length - 1].remove();
        }
    }
}

// ============================================================================
// WALLET BUTTON HANDLERS
// ============================================================================

function initWalletButtons() {
    document.querySelectorAll('.wallet-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const wallet = btn.dataset.wallet;
            loginWithLightning(wallet);
        });
    });
    
    // Main login button
    document.getElementById('main-login-btn')?.addEventListener('click', () => {
        loginWithLightning('webln');
    });
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function formatNpub(npub) {
    if (!npub) return 'Unknown';
    if (npub.length <= 16) return npub;
    return `${npub.substring(0, 8)}...${npub.substring(npub.length - 8)}`;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        console.log('Copied to clipboard');
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

function showLoading(message = 'Loading...') {
    // Simple loading implementation
    // In production, use a proper modal/overlay
    console.log('Loading:', message);
}

function hideLoading() {
    console.log('Loading complete');
}

function showError(message) {
    // Simple error notification
    // In production, use a toast notification library
    alert(message);
}

function showSuccess(message) {
    // Simple success notification
    // In production, use a toast notification library
    alert(message);
}

// ============================================================================
// GITHUB STARS
// ============================================================================

async function loadGitHubStars() {
    try {
        const response = await fetch('https://api.github.com/repos/hodlxxi/Universal-Bitcoin-Identity-Layer');
        const data = await response.json();
        
        if (data.stargazers_count) {
            document.getElementById('github-stars').textContent = `★ ${data.stargazers_count} Stars`;
        }
    } catch (error) {
        console.error('Failed to load GitHub stars:', error);
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('HODLXXI Playground initialized');
    
    // Initialize all components
    initMatrixBackground();
    initAccordion();
    initWalletButtons();
    initProofOfFunds();
    initGatedTemplates();
    initSignatureMessage();
    initLiveFeed();
    loadGitHubStars();
    
    // Check if user is already authenticated
    const token = localStorage.getItem('hodlxxi_token');
    if (token) {
        // Validate token and restore session
        // This would be an API call to your backend
        console.log('Token found, validating...');
    }
});

// ============================================================================
// EXPORT FOR TESTING
// ============================================================================

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        loginWithLightning,
        proveFunds,
        getWhaleTier,
        formatNpub
    };
}
