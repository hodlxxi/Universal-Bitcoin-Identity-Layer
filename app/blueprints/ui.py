"""
UI Blueprint - Frontend Routes (Dashboard, Playground, Chat)

Serves frontend HTML pages and handles user interface routes.
"""

import logging

from flask import Blueprint, current_app, render_template_string, session

logger = logging.getLogger(__name__)

ui_bp = Blueprint("ui", __name__)


@ui_bp.route("/")
def index():
    """
    Application home page.

    Returns:
        HTML homepage
    """
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KeyAuth Protocol | Bitcoin Authentication & Identity for Web3</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg: #0b0f10;
            --panel: #11171a;
            --fg: #e6f1ef;
            --accent: #00ff88;
            --muted: #86a3a1;
            --bitcoin-orange: #f7931a;
            --dark-bg: #0b0f10;
            --darker-bg: #000000;
            --card-bg: rgba(17, 23, 26, 0.92);
            --text-light: #e6f1ef;
            --text-muted: #86a3a1;
            --border-color: #0f2a24;
            --border-hover: #184438;
            --input-bg: #0e1315;
            --hover-bg: #12352d;
            --gradient-1: linear-gradient(135deg, #00ff88 0%, #00cc66 100%);
            --gradient-2: linear-gradient(135deg, #f7931a 0%, #ff6b35 100%);
            --glow-green: rgba(0, 255, 136, 0.2);
            --glow-orange: rgba(247, 147, 26, 0.2);
        }

        body {
            font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg);
            color: var(--fg);
            line-height: 1.6;
            overflow-x: hidden;
        }

        /* Matrix Background Canvases */
        .matrix-canvas {
            position: fixed;
            inset: 0;
            z-index: 0;
            pointer-events: none;
        }

        @media (prefers-reduced-motion: reduce) {
            .matrix-canvas {
                display: none !important;
            }
        }

        @media print {
            .matrix-canvas {
                display: none !important;
            }
        }

        /* Ensure all content stays above Matrix canvases */
        body > *:not(.matrix-canvas) {
            position: relative;
            z-index: 1;
        }

        .container {
            max-width: 1280px;
            margin: 0 auto;
            padding: 0 20px;
        }

        /* Navigation */
        nav {
            position: fixed;
            top: 0;
            width: 100%;
            background: rgba(11, 15, 16, 0.95);
            backdrop-filter: blur(10px);
            z-index: 999;
            border-bottom: 1px solid var(--border-color);
        }

        .nav-content {
            max-width: 1280px;
            margin: 0 auto;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 24px;
            font-weight: 800;
            color: var(--accent);
            text-shadow: 0 0 20px var(--glow-green);
        }

        .nav-links {
            display: flex;
            gap: 30px;
            list-style: none;
        }

        .nav-links a {
            color: var(--fg);
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s;
        }

        .nav-links a:hover {
            color: var(--accent);
            text-shadow: 0 0 10px var(--glow-green);
        }

        .cta-button {
            background: var(--gradient-2);
            color: white;
            padding: 12px 28px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s;
            display: inline-block;
            border: 1px solid var(--bitcoin-orange);
        }

        .cta-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px var(--glow-orange);
        }

        /* Hero Section */
        .hero {
            min-height: 100vh;
            display: flex;
            align-items: center;
            position: relative;
            padding-top: 80px;
            background: radial-gradient(ellipse at top, rgba(0, 255, 136, 0.08) 0%, transparent 50%);
        }

        .hero-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 60px;
            align-items: center;
        }

        .hero-content h1 {
            font-size: 64px;
            font-weight: 900;
            line-height: 1.1;
            margin-bottom: 24px;
            color: var(--accent);
            text-shadow: 0 0 40px var(--glow-green);
        }

        .hero-content .subtitle {
            font-size: 24px;
            color: var(--bitcoin-orange);
            margin-bottom: 32px;
            font-weight: 600;
        }

        .hero-content .description {
            font-size: 18px;
            color: var(--muted);
            margin-bottom: 40px;
            line-height: 1.8;
        }

        .hero-buttons {
            display: flex;
            gap: 20px;
        }

        .secondary-button {
            background: transparent;
            color: var(--accent);
            padding: 12px 28px;
            border: 2px solid var(--accent);
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s;
        }

        .secondary-button:hover {
            background: var(--accent);
            color: var(--bg);
            transform: translateY(-2px);
            box-shadow: 0 10px 30px var(--glow-green);
        }

        .hero-visual {
            position: relative;
        }

        .protocol-diagram {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 40px;
            position: relative;
            overflow: hidden;
            box-shadow: 0 0 10px #003a2b, 0 0 20px var(--glow-green);
            animation: pulse-glow 2.4s ease-in-out infinite;
        }

        @keyframes pulse-glow {
            0%, 100% {
                box-shadow: 0 0 10px #003a2b, 0 0 20px var(--glow-green);
            }
            50% {
                box-shadow: 0 0 18px #00664c, 0 0 30px rgba(0, 255, 136, 0.3);
            }
        }

        .protocol-diagram::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 200%;
            height: 200%;
            background: conic-gradient(from 0deg, transparent, var(--accent), transparent);
            animation: rotate 8s linear infinite;
            opacity: 0.08;
        }

        @keyframes rotate {
            100% { transform: rotate(360deg); }
        }

        .protocol-layers {
            position: relative;
            z-index: 1;
        }

        .protocol-layer {
            background: rgba(14, 21, 22, 0.6);
            border: 1px solid var(--border-hover);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            transition: all 0.3s;
        }

        .protocol-layer:hover {
            background: rgba(0, 255, 136, 0.05);
            border-color: var(--accent);
            transform: translateX(10px);
            box-shadow: 0 0 20px var(--glow-green);
        }

        .protocol-layer h4 {
            font-size: 16px;
            color: var(--accent);
            margin-bottom: 8px;
        }

        .protocol-layer p {
            font-size: 14px;
            color: var(--muted);
        }

        /* A to Z Section */
        .a-to-z-section {
            padding: 120px 0;
            background: var(--darker-bg);
        }

        .section-header {
            text-align: center;
            max-width: 800px;
            margin: 0 auto 80px;
        }

        .section-header h2 {
            font-size: 48px;
            font-weight: 800;
            margin-bottom: 20px;
        }

        .section-header .highlight {
            color: var(--accent);
            text-shadow: 0 0 30px var(--glow-green);
        }

        .section-header p {
            font-size: 20px;
            color: var(--muted);
        }

        .a-to-z-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 30px;
            margin-top: 60px;
        }

        .capability-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }

        .capability-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: var(--gradient-1);
            transform: scaleX(0);
            transition: transform 0.3s;
        }

        .capability-card:hover {
            transform: translateY(-8px);
            border-color: var(--accent);
            box-shadow: 0 0 30px var(--glow-green);
        }

        .capability-card:hover::before {
            transform: scaleX(1);
        }

        .capability-icon {
            width: 60px;
            height: 60px;
            background: var(--gradient-1);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            margin-bottom: 20px;
            box-shadow: 0 0 20px var(--glow-green);
        }

        .capability-card h3 {
            font-size: 20px;
            margin-bottom: 12px;
            color: var(--fg);
        }

        .capability-card p {
            color: var(--muted);
            font-size: 15px;
            line-height: 1.6;
        }

        /* Use Cases Section */
        .use-cases-section {
            padding: 120px 0;
        }

        .use-case-tabs {
            display: flex;
            gap: 20px;
            margin-bottom: 60px;
            flex-wrap: wrap;
            justify-content: center;
        }

        .tab-button {
            background: var(--card-bg);
            border: 2px solid var(--border-hover);
            color: var(--fg);
            padding: 16px 32px;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }

        .tab-button:hover, .tab-button.active {
            background: var(--hover-bg);
            border-color: var(--accent);
            color: var(--accent);
            transform: translateY(-2px);
            box-shadow: 0 0 20px var(--glow-green);
        }

        .use-case-content {
            display: none;
        }

        .use-case-content.active {
            display: block;
        }

        .use-case-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
        }

        .use-case-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
            transition: all 0.3s;
        }

        .use-case-card:hover {
            border-color: var(--accent);
            transform: translateY(-4px);
            box-shadow: 0 0 30px var(--glow-green);
        }

        .use-case-badge {
            display: inline-block;
            background: rgba(0, 255, 136, 0.1);
            color: var(--accent);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 16px;
            border: 1px solid var(--accent);
        }

        .use-case-card h4 {
            font-size: 22px;
            margin-bottom: 12px;
            color: var(--fg);
        }

        .use-case-card .scenario {
            color: var(--muted);
            font-size: 15px;
            line-height: 1.7;
            margin-bottom: 20px;
        }

        .use-case-features {
            list-style: none;
            margin-top: 20px;
        }

        .use-case-features li {
            color: var(--muted);
            font-size: 14px;
            padding: 8px 0;
            padding-left: 28px;
            position: relative;
        }

        .use-case-features li::before {
            content: '✓';
            position: absolute;
            left: 0;
            color: var(--accent);
            font-weight: bold;
        }

        /* How It Works */
        .how-it-works {
            padding: 120px 0;
            background: var(--darker-bg);
        }

        .timeline {
            position: relative;
            max-width: 900px;
            margin: 0 auto;
        }

        .timeline::before {
            content: '';
            position: absolute;
            left: 50%;
            transform: translateX(-50%);
            width: 2px;
            height: 100%;
            background: linear-gradient(180deg, var(--accent) 0%, rgba(0, 255, 136, 0.1) 100%);
        }

        .timeline-item {
            display: flex;
            margin-bottom: 60px;
            position: relative;
        }

        .timeline-item:nth-child(odd) {
            flex-direction: row-reverse;
        }

        .timeline-content {
            width: 45%;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
        }

        .timeline-number {
            position: absolute;
            left: 50%;
            transform: translateX(-50%);
            width: 60px;
            height: 60px;
            background: var(--gradient-1);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            font-weight: 800;
            color: var(--bg);
            box-shadow: 0 0 0 8px var(--darker-bg), 0 0 30px var(--glow-green);
        }

        .timeline-content h3 {
            font-size: 22px;
            margin-bottom: 12px;
            color: var(--accent);
        }

        .timeline-content p {
            color: var(--muted);
            line-height: 1.7;
        }

        /* Trust Indicators */
        .trust-section {
            padding: 120px 0;
            text-align: center;
        }

        .trust-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 40px;
            margin-top: 60px;
        }

        .metric {
            padding: 32px;
        }

        .metric-value {
            font-size: 56px;
            font-weight: 900;
            color: var(--accent);
            text-shadow: 0 0 30px var(--glow-green);
            margin-bottom: 12px;
        }

        .metric-label {
            font-size: 18px;
            color: var(--muted);
            font-weight: 600;
        }

        /* Features Grid */
        .features-section {
            padding: 120px 0;
            background: var(--darker-bg);
        }

        /* Developer Portal Section */
        .developer-section {
            padding: 120px 0;
            background: var(--bg);
        }

        .portal-links {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 30px;
            margin-top: 60px;
            margin-bottom: 80px;
        }

        .portal-card {
            background: var(--card-bg);
            border: 2px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
            text-decoration: none;
            color: var(--fg);
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }

        .portal-card:hover {
            border-color: var(--accent);
            transform: translateY(-8px);
            box-shadow: 0 0 30px var(--glow-green);
        }

        .portal-icon {
            font-size: 48px;
            margin-bottom: 16px;
        }

        .portal-card h3 {
            font-size: 22px;
            margin-bottom: 8px;
            color: var(--accent);
        }

        .portal-card p {
            color: var(--muted);
            font-size: 14px;
            line-height: 1.6;
            margin-bottom: 16px;
        }

        .portal-arrow {
            position: absolute;
            bottom: 20px;
            right: 20px;
            font-size: 24px;
            color: var(--accent);
            transition: transform 0.3s;
        }

        .portal-card:hover .portal-arrow {
            transform: translateX(5px);
        }

        /* API Documentation Styles */
        .api-docs {
            max-width: 1000px;
            margin: 0 auto;
        }

        .api-section-title {
            font-size: 28px;
            color: var(--accent);
            margin-bottom: 32px;
            margin-top: 60px;
        }

        .api-block {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 30px;
        }

        .api-block h4 {
            font-size: 20px;
            color: var(--fg);
            margin-bottom: 8px;
        }

        .api-description {
            color: var(--muted);
            margin-bottom: 24px;
            font-size: 15px;
        }

        .endpoint-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .endpoint-item {
            display: flex;
            align-items: center;
            gap: 12px;
            background: var(--input-bg);
            border: 1px solid var(--border-hover);
            border-radius: 8px;
            padding: 12px 16px;
        }

        .http-method {
            padding: 4px 12px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .http-method.get {
            background: rgba(16, 185, 129, 0.1);
            color: #10b981;
            border: 1px solid #10b981;
        }

        .http-method.post {
            background: rgba(59, 130, 246, 0.1);
            color: #3b82f6;
            border: 1px solid #3b82f6;
        }

        .endpoint-url {
            flex: 1;
            color: var(--accent);
            font-family: 'Courier New', monospace;
            font-size: 14px;
            word-break: break-all;
        }

        .copy-btn {
            background: transparent;
            border: 1px solid var(--border-hover);
            color: var(--muted);
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 16px;
        }

        .copy-btn:hover {
            background: var(--hover-bg);
            border-color: var(--accent);
            color: var(--accent);
        }

        .api-note {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-top: 16px;
            padding: 12px;
            background: rgba(247, 147, 26, 0.05);
            border-left: 3px solid var(--bitcoin-orange);
            border-radius: 6px;
            color: var(--muted);
            font-size: 14px;
        }

        .note-icon {
            font-size: 20px;
        }

        .api-note code {
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 6px;
            border-radius: 4px;
            color: var(--bitcoin-orange);
            font-family: monospace;
        }

        /* Code Examples */
        .code-examples {
            margin-top: 60px;
        }

        .code-block {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 24px;
        }

        .code-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            background: var(--input-bg);
            border-bottom: 1px solid var(--border-hover);
        }

        .code-title {
            color: var(--accent);
            font-weight: 600;
            font-size: 15px;
        }

        .copy-code-btn {
            background: var(--accent);
            color: var(--bg);
            border: none;
            padding: 6px 16px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .copy-code-btn:hover {
            box-shadow: 0 0 20px var(--glow-green);
            transform: translateY(-2px);
        }

        .code-block pre {
            margin: 0;
            padding: 20px;
            overflow-x: auto;
            background: var(--bg);
        }

        .code-block code {
            color: var(--accent);
            font-family: 'Courier New', Consolas, monospace;
            font-size: 13px;
            line-height: 1.6;
        }

        /* Live Test Section */
        .live-test-section {
            margin-top: 60px;
        }

        .test-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
            margin-top: 32px;
        }

        .test-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
        }

        .test-card h4 {
            font-size: 20px;
            color: var(--fg);
            margin-bottom: 8px;
        }

        .test-card p {
            color: var(--muted);
            margin-bottom: 20px;
            font-size: 14px;
        }

        .test-button {
            width: 100%;
            background: var(--gradient-1);
            color: var(--bg);
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 15px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .test-button:hover {
            box-shadow: 0 0 30px var(--glow-green);
            transform: translateY(-2px);
        }

        .test-result {
            margin-top: 16px;
            padding: 16px;
            background: var(--input-bg);
            border: 1px solid var(--border-hover);
            border-radius: 8px;
            color: var(--accent);
            font-family: monospace;
            font-size: 12px;
            max-height: 300px;
            overflow-y: auto;
            display: none;
        }

        .test-result:not(:empty) {
            display: block;
        }

        /* Code block scrollbar styling */
        .code-block pre::-webkit-scrollbar {
            height: 8px;
        }

        .code-block pre::-webkit-scrollbar-track {
            background: var(--input-bg);
        }

        .code-block pre::-webkit-scrollbar-thumb {
            background: var(--border-hover);
            border-radius: 4px;
        }

        .code-block pre::-webkit-scrollbar-thumb:hover {
            background: var(--accent);
        }

        .test-result::-webkit-scrollbar {
            width: 8px;
        }

        .test-result::-webkit-scrollbar-track {
            background: var(--input-bg);
        }

        .test-result::-webkit-scrollbar-thumb {
            background: var(--border-hover);
            border-radius: 4px;
        }

        .test-result::-webkit-scrollbar-thumb:hover {
            background: var(--accent);
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
            margin-top: 60px;
        }

        .feature-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 40px;
            text-align: center;
            transition: all 0.3s;
        }

        .feature-card:hover {
            border-color: var(--accent);
            transform: translateY(-8px);
            box-shadow: 0 0 30px var(--glow-green);
        }

        .feature-icon {
            width: 80px;
            height: 80px;
            background: var(--gradient-1);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            margin: 0 auto 24px;
            box-shadow: 0 0 30px var(--glow-green);
        }

        .feature-card h3 {
            font-size: 20px;
            margin-bottom: 12px;
        }

        .feature-card p {
            color: var(--muted);
            line-height: 1.7;
        }

        /* CTA Section */
        .cta-section {
            padding: 120px 0;
            text-align: center;
        }

        .cta-box {
            background: var(--gradient-2);
            border-radius: 24px;
            padding: 80px 40px;
            max-width: 900px;
            margin: 0 auto;
            position: relative;
            overflow: hidden;
            border: 2px solid var(--bitcoin-orange);
        }

        .cta-box::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255, 255, 255, 0.1) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 0.5; }
            50% { transform: scale(1.1); opacity: 0.8; }
        }

        .cta-box h2 {
            font-size: 42px;
            font-weight: 900;
            margin-bottom: 20px;
            color: white;
            position: relative;
            z-index: 1;
        }

        .cta-box p {
            font-size: 20px;
            color: rgba(255, 255, 255, 0.9);
            margin-bottom: 40px;
            position: relative;
            z-index: 1;
        }

        .cta-buttons-large {
            display: flex;
            gap: 20px;
            justify-content: center;
            position: relative;
            z-index: 1;
            flex-wrap: wrap;
        }

        .white-button {
            background: white;
            color: var(--bg);
            padding: 16px 40px;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 700;
            font-size: 18px;
            transition: all 0.3s;
        }

        .white-button:hover {
            transform: translateY(-4px);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }

        .cta-buttons-large .secondary-button {
            padding: 16px 40px;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 700;
            font-size: 18px;
            transition: all 0.3s;
        }

        .cta-buttons-large .secondary-button:hover {
            transform: translateY(-4px);
        }

        /* Footer */
        footer {
            background: var(--darker-bg);
            border-top: 1px solid var(--border-color);
            padding: 60px 0 30px;
        }

        .footer-content {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr;
            gap: 60px;
            margin-bottom: 40px;
        }

        .footer-brand h3 {
            font-size: 24px;
            margin-bottom: 16px;
            color: var(--accent);
            text-shadow: 0 0 20px var(--glow-green);
        }

        .footer-brand p {
            color: var(--muted);
            line-height: 1.7;
        }

        .footer-links h4 {
            font-size: 16px;
            margin-bottom: 20px;
            color: var(--accent);
        }

        .footer-links ul {
            list-style: none;
        }

        .footer-links ul li {
            margin-bottom: 12px;
        }

        .footer-links a {
            color: var(--muted);
            text-decoration: none;
            transition: color 0.3s;
        }

        .footer-links a:hover {
            color: var(--accent);
        }

        .footer-bottom {
            text-align: center;
            padding-top: 30px;
            border-top: 1px solid var(--border-color);
            color: var(--muted);
        }

        /* Responsive */
        @media (max-width: 968px) {
            .hero-grid {
                grid-template-columns: 1fr;
            }

            .hero-content h1 {
                font-size: 48px;
            }

            .nav-links {
                display: none;
            }

            .portal-links {
                grid-template-columns: 1fr;
            }

            .test-grid {
                grid-template-columns: 1fr;
            }

            .endpoint-item {
                flex-direction: column;
                align-items: flex-start;
            }

            .code-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 12px;
            }

            .copy-code-btn {
                width: 100%;
            }

            .code-block pre {
                font-size: 12px;
                padding: 16px;
            }

            .cta-buttons-large {
                flex-direction: column;
                align-items: stretch;
            }

            .white-button,
            .cta-buttons-large .secondary-button {
                width: 100%;
                text-align: center;
            }

            .timeline::before {
                left: 30px;
            }

            .timeline-item,
            .timeline-item:nth-child(odd) {
                flex-direction: row;
            }

            .timeline-content {
                width: calc(100% - 80px);
                margin-left: 80px;
            }

            .timeline-number {
                left: 30px;
            }

            .footer-content {
                grid-template-columns: 1fr;
            }

            .a-to-z-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Animations */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .animate-in {
            animation: fadeInUp 0.8s ease-out;
        }
    </style>
</head>
<body>
    <!-- Matrix Background Canvas - Warp Effect Only -->
    <canvas id="matrix-warp" class="matrix-canvas" aria-hidden="true"></canvas>

    <!-- Navigation -->
    <nav>
        <div class="nav-content">
            <div class="logo">⚡ KeyAuth Protocol</div>
            <ul class="nav-links">
    <li><a href="/playground">Playground</a></li>
    <li><a href="/pof/">Proof of Funds</a></li>
    <li><a href="/pof/leaderboard">Whale Leaderboard</a></li>
    <li><a href="/login">Login</a></li>
</ul>
            <a href="#contact" class="cta-button">Get Started</a>
        </div>
    </nav>

    <!-- Hero Section -->
    <section class="hero">
        <div class="container">
            <div class="hero-grid">
                <div class="hero-content animate-in">
                    <h1>The Universal Bitcoin Identity Layer</h1>
                    <p class="subtitle">From A to Z: White Glove Solutions for the Web3 Future</p>
                    <p class="description">
                        Bridge your Web2 business into the Bitcoin economy with enterprise-grade authentication,
                        proof-of-funds, and identity services. No custody. No compromise. Just cryptographic truth.
                    </p>
                    <div class="hero-buttons">
                        <a href="#contact" class="cta-button">Request Consultation</a>
                        <a href="#developer" class="secondary-button">Try API Now</a>
                    </div>
                </div>
                <div class="hero-visual">
                    <div class="protocol-diagram">
                        <div class="protocol-layers">
                            <div class="protocol-layer">
                                <h4>🌐 OAuth2 / OpenID Connect</h4>
                                <p>Standards-based SSO for seamless integration</p>
                            </div>
                            <div class="protocol-layer">
                                <h4>⚡ LNURL Authentication</h4>
                                <p>Instant Lightning Network login without passwords</p>
                            </div>
                            <div class="protocol-layer">
                                <h4>🔐 Bitcoin Signature Auth</h4>
                                <p>Cryptographic identity tied to Bitcoin keys</p>
                            </div>
                            <div class="protocol-layer">
                                <h4>💰 Proof of Funds (PSBT)</h4>
                                <p>Non-custodial verification of Bitcoin holdings</p>
                            </div>
                            <div class="protocol-layer">
                                <h4>👥 Covenant Groups</h4>
                                <p>Multi-party coordination with threshold controls</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- A to Z Capabilities -->
    <section id="capabilities" class="a-to-z-section">
        <div class="container">
            <div class="section-header">
                <h2>From <span class="highlight">A to Z</span>, We've Got You Covered</h2>
                <p>Like Amazon for goods, KeyAuth Protocol covers every need in the Bitcoin authentication and identity space</p>
            </div>

            <div class="a-to-z-grid">
                <div class="capability-card">
                    <div class="capability-icon">🔐</div>
                    <h3>Authentication Services</h3>
                    <p>LNURL-auth, Bitcoin signature verification, OAuth2/OIDC integration for passwordless, cryptographic authentication</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">💰</div>
                    <h3>Proof of Funds</h3>
                    <p>Non-custodial PSBT verification with privacy levels (boolean/threshold/aggregate) for lending, trading, and more</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">🌐</div>
                    <h3>SSO Integration</h3>
                    <p>Drop-in replacement for Auth0, Okta, or Firebase - but with Bitcoin identity at the core</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">👥</div>
                    <h3>Covenant Groups</h3>
                    <p>Multi-party coordination, governance, and access control with cryptographic membership verification</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">💬</div>
                    <h3>Real-Time Chat</h3>
                    <p>WebSocket-powered chat with Bitcoin-native identity, perfect for trading desks or DAO coordination</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">🎟️</div>
                    <h3>Access Control</h3>
                    <p>Token-gated content, tiered memberships, and threshold-based permissions tied to Bitcoin holdings</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">📊</div>
                    <h3>Enterprise Analytics</h3>
                    <p>Track authentication events, covenant activity, and user behavior with privacy-preserving analytics</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">🔗</div>
                    <h3>API Integration</h3>
                    <p>RESTful APIs and WebSocket endpoints for seamless integration with your existing infrastructure</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">🛡️</div>
                    <h3>Security Auditing</h3>
                    <p>Comprehensive logging, challenge-response verification, and cryptographic audit trails</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">⚙️</div>
                    <h3>Custom Solutions</h3>
                    <p>White glove service for bespoke authentication flows, multi-sig coordination, and specialized use cases</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">🚀</div>
                    <h3>Migration Services</h3>
                    <p>Migrate from Web2 auth providers to Bitcoin-native identity with zero downtime</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">📱</div>
                    <h3>Mobile & Desktop</h3>
                    <p>SDK support for iOS, Android, and desktop applications with unified Bitcoin identity</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Use Cases by Industry -->
    <section id="use-cases" class="use-cases-section">
        <div class="container">
            <div class="section-header">
                <h2>Real-World <span class="highlight">Solutions</span></h2>
                <p>Proven implementations across industries</p>
            </div>

            <div class="use-case-tabs">
                <button class="tab-button active">💼 Finance</button>
                <button class="tab-button">🏢 Enterprise</button>
                <button class="tab-button">🌐 Web3</button>
                <button class="tab-button">👥 Community</button>
            </div>

            <!-- Finance Use Cases -->
            <div id="finance" class="use-case-content active">
                <div class="use-case-grid">
                    <div class="use-case-card">
                        <div class="use-case-badge">Trading Platforms</div>
                        <h4>Exclusive Trading Communities</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Prevent spam and bots in premium trading groups while maintaining privacy.<br><br>
                            <strong>Solution:</strong> LNURL-auth for instant signup, PSBT proof-of-funds for tiered access (e.g., 1 BTC minimum for whale rooms), real-time chat with cryptographic identities.
                        </p>
                        <ul class="use-case-features">
                            <li>No email required, full pseudonymity</li>
                            <li>Automatic tier assignment based on holdings</li>
                            <li>Non-custodial verification</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">P2P Lending</div>
                        <h4>Non-Custodial Lending Platforms</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Verify collateral without taking custody of user funds.<br><br>
                            <strong>Solution:</strong> Borrowers prove funds via PSBT, lenders authenticate with Bitcoin keys, smart contracts triggered by cryptographic proofs.
                        </p>
                        <ul class="use-case-features">
                            <li>Prove up to X BTC without moving coins</li>
                            <li>Privacy-preserving verification (boolean/threshold modes)</li>
                            <li>Integration with multi-sig escrow</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">Wealth Management</div>
                        <h4>Bitcoin Private Banking</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Wealthy clients want white-glove service with full privacy.<br><br>
                            <strong>Solution:</strong> Covenant groups for family offices, threshold-based access to advisors, encrypted chat with proof-of-identity.
                        </p>
                        <ul class="use-case-features">
                            <li>Multi-party governance for family offices</li>
                            <li>Selective disclosure to advisors</li>
                            <li>Audit trail for compliance</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Enterprise Use Cases -->
            <div id="enterprise" class="use-case-content">
                <div class="use-case-grid">
                    <div class="use-case-card">
                        <div class="use-case-badge">HR & Payroll</div>
                        <h4>Bitcoin-Paid Contractor Platforms</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Verify contractor payment capabilities and company solvency before engagement.<br><br>
                            <strong>Solution:</strong> Both parties prove funds, establish covenant for escrow, integrated chat for project coordination.
                        </p>
                        <ul class="use-case-features">
                            <li>Reduce payment disputes by 90%</li>
                            <li>Cryptographic work agreements</li>
                            <li>Milestone-based fund verification</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">Supply Chain</div>
                        <h4>Bitcoin-Settled B2B Networks</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Coordinate multi-party supply chains with Bitcoin settlements.<br><br>
                            <strong>Solution:</strong> Each stakeholder authenticates with Bitcoin identity, covenants per shipment, real-time status updates via WebSocket.
                        </p>
                        <ul class="use-case-features">
                            <li>Immutable identity tied to payment rails</li>
                            <li>Automated settlement triggers</li>
                            <li>Multi-party chat per shipment</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">SaaS Migration</div>
                        <h4>Replace Auth0 with Bitcoin Auth</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Existing SaaS wants to add Bitcoin-native identity without rewriting auth.<br><br>
                            <strong>Solution:</strong> Drop-in OAuth2/OIDC provider, migrate existing users to Bitcoin keys, maintain legacy auth during transition.
                        </p>
                        <ul class="use-case-features">
                            <li>Standards-compliant OIDC endpoints</li>
                            <li>Zero downtime migration</li>
                            <li>Dual auth during transition</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Web3 Use Cases -->
            <div id="web3" class="use-case-content">
                <div class="use-case-grid">
                    <div class="use-case-card">
                        <div class="use-case-badge">DAO Governance</div>
                        <h4>Bitcoin-Native DAO Coordination</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Sybil-resistant voting with transparent stake verification.<br><br>
                            <strong>Solution:</strong> Covenant-based membership, voting weight from PoF, real-time proposal discussions, OAuth for off-chain tools.
                        </p>
                        <ul class="use-case-features">
                            <li>Cryptographic voting with PoF weight</li>
                            <li>Integrate with Snapshot, Discourse, etc.</li>
                            <li>Threshold-based proposal rights</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">Content Platforms</div>
                        <h4>Bitcoin-Gated Content & Subscriptions</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Monetize content without payment processors or censorship risk.<br><br>
                            <strong>Solution:</strong> LNURL login, threshold-based access tiers (e.g., 0.01 BTC for premium), OAuth for cross-platform access.
                        </p>
                        <ul class="use-case-features">
                            <li>No Stripe, PayPal, or card fees</li>
                            <li>Censorship-resistant monetization</li>
                            <li>Automatic tier upgrades via PoF</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">NFT & Gaming</div>
                        <h4>Bitcoin-Authenticated Gaming</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Prove ownership of high-value NFTs or game assets without centralized servers.<br><br>
                            <strong>Solution:</strong> Bitcoin signature verification for asset ownership, PSBT for in-game tournaments with real stakes.
                        </p>
                        <ul class="use-case-features">
                            <li>Cryptographic proof of asset ownership</li>
                            <li>Escrow-free tournaments</li>
                            <li>Cross-game identity</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Community Use Cases -->
            <div id="community" class="use-case-content">
                <div class="use-case-grid">
                    <div class="use-case-card">
                        <div class="use-case-badge">Education</div>
                        <h4>Bitcoin Learning Platforms</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Progressive course access tied to Bitcoin acquisition milestones.<br><br>
                            <strong>Solution:</strong> Free tier (LNURL auth), Premium (0.1 BTC PoF), Whale Class (1+ BTC PoF) - incentivize learning through acquisition.
                        </p>
                        <ul class="use-case-features">
                            <li>Gamified learning paths</li>
                            <li>Proof-of-progress via holdings</li>
                            <li>Peer-to-peer mentorship matching</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">Local Communities</div>
                        <h4>Regional Bitcoin Meetup Networks</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Coordinate local meetups without email/phone collection.<br><br>
                            <strong>Solution:</strong> Covenant per city, LNURL-auth for quick entry, event chat, privacy-preserving coordination.
                        </p>
                        <ul class="use-case-features">
                            <li>No PII collection required</li>
                            <li>Regional reputation building</li>
                            <li>Cross-city collaboration</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">Crowdfunding</div>
                        <h4>KYC-Free Bitcoin Crowdfunding</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Global crowdfunding without payment processor restrictions.<br><br>
                            <strong>Solution:</strong> Founders prove credibility via PoF, backers authenticate with LNURL, covenant for multi-sig escrow, real-time updates via chat.
                        </p>
                        <ul class="use-case-features">
                            <li>Permissionless global fundraising</li>
                            <li>Cryptographic accountability</li>
                            <li>Milestone-based fund releases</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- How It Works -->
    <section id="how-it-works" class="how-it-works">
        <div class="container">
            <div class="section-header">
                <h2>How <span class="highlight">It Works</span></h2>
                <p>From consultation to deployment in 4 simple steps</p>
            </div>

            <div class="timeline">
                <div class="timeline-item">
                    <div class="timeline-content">
                        <h3>Discovery & Consultation</h3>
                        <p>We meet with your team to understand your specific needs - whether it's migrating from Auth0, adding Bitcoin payments, or building a new Web3 product. We assess your current infrastructure and design a custom integration plan.</p>
                    </div>
                    <div class="timeline-number">1</div>
                </div>

                <div class="timeline-item">
                    <div class="timeline-content">
                        <h3>Custom Configuration</h3>
                        <p>Our engineers configure the KeyAuth Protocol for your use case - setting up OAuth scopes, covenant structures, PoF thresholds, and privacy levels. We provide sandbox environments for testing before production.</p>
                    </div>
                    <div class="timeline-number">2</div>
                </div>

                <div class="timeline-item">
                    <div class="timeline-content">
                        <h3>Integration & Migration</h3>
                        <p>Seamless integration with your existing systems via our RESTful API, WebSocket endpoints, or OAuth2/OIDC flows. We handle data migration from legacy auth providers with zero downtime.</p>
                    </div>
                    <div class="timeline-number">3</div>
                </div>

                <div class="timeline-item">
                    <div class="timeline-content">
                        <h3>Launch & Ongoing Support</h3>
                        <p>Go live with 24/7 monitoring, dedicated support, and continuous optimization. We provide analytics dashboards, security audits, and proactive scaling recommendations.</p>
                    </div>
                    <div class="timeline-number">4</div>
                </div>
            </div>
        </div>
    </section>

    <!-- Features -->
    <section id="features" class="features-section">
        <div class="container">
            <div class="section-header">
                <h2>Why <span class="highlight">KeyAuth Protocol</span></h2>
                <p>Built for enterprise, secured by Bitcoin</p>
            </div>

            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">🔒</div>
                    <h3>Non-Custodial</h3>
                    <p>Users never give up control of their Bitcoin. All verification happens via PSBT and signatures - no custody, no counterparty risk.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">🎭</div>
                    <h3>Privacy First</h3>
                    <p>Multiple privacy levels (boolean/threshold/aggregate). Prove holdings without revealing exact amounts. Pseudonymous by default.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <h3>Lightning Fast</h3>
                    <p>LNURL-auth for instant onboarding. WebSocket real-time updates. Sub-second authentication flows.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">🌐</div>
                    <h3>Standards Compliant</h3>
                    <p>OAuth2, OpenID Connect, LNURL, PSBT - we speak the language of both Web2 and Web3.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">🛡️</div>
                    <h3>Sybil Resistant</h3>
                    <p>Real economic cost to create accounts. Proof-of-funds as spam protection. Covenant-based access control.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">📊</div>
                    <h3>Enterprise Grade</h3>
                    <p>99.9% uptime SLA. SOC 2 compliant. Comprehensive audit logs. 24/7 support for critical deployments.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Trust Indicators -->
    <section class="trust-section">
        <div class="container">
            <div class="section-header">
                <h2>Trusted by <span class="highlight">Bitcoin Natives</span></h2>
                <p>Powering the next generation of Bitcoin-first applications</p>
            </div>

            <div class="trust-metrics">
                <div class="metric">
                    <div class="metric-value">100%</div>
                    <div class="metric-label">Non-Custodial</div>
                </div>
                <div class="metric">
                    <div class="metric-value">24/7</div>
                    <div class="metric-label">White Glove Support</div>
                </div>
                <div class="metric">
                    <div class="metric-value">99.9%</div>
                    <div class="metric-label">Uptime SLA</div>
                </div>
                <div class="metric">
                    <div class="metric-value">A-Z</div>
                    <div class="metric-label">Full Coverage</div>
                </div>
            </div>
        </div>
    </section>

    <!-- Developer Portal / API Documentation -->
    <section id="developer" class="developer-section">
        <div class="container">
            <div class="section-header">
                <h2>Try the <span class="highlight">Protocol</span></h2>
                <p>Explore our live dashboard, playground, and comprehensive API documentation</p>
            </div>

            <!-- Quick Access Buttons -->
            <div class="portal-links">
                <a href="https://hodlxxi.com/dashboard" target="_blank" class="portal-card">
                    <div class="portal-icon">📊</div>
                    <h3>Dashboard</h3>
                    <p>Monitor your authentication metrics and usage</p>
                    <span class="portal-arrow">→</span>
                </a>

                <a href="https://hodlxxi.com/playground" target="_blank" class="portal-card">
                    <div class="portal-icon">🎮</div>
                    <h3>Playground</h3>
                    <p>Test authentication flows in real-time</p>
                    <span class="portal-arrow">→</span>
                </a>

                <a href="/health" target="_blank" class="portal-card">
                    <div class="portal-icon">🔍</div>
                    <h3>System Status</h3>
                    <p>Check service health and uptime</p>
                    <span class="portal-arrow">→</span>
                </a>

                <a href="https://hodlxxi.com/oauthx/docs" target="_blank" class="portal-card">
                    <div class="portal-icon">📚</div>
                    <h3>Documentation</h3>
                    <p>Complete API reference and guides</p>
                    <span class="portal-arrow">→</span>
                </a>
            </div>

            <!-- API Documentation -->
            <div class="api-docs">
                <h3 class="api-section-title">🔌 Quick Start Guide</h3>

                <!-- Well-Known Endpoints -->
                <div class="api-block">
                    <h4>🌐 Discovery Endpoints</h4>
                    <p class="api-description">OpenID Connect discovery and JWKS endpoints</p>
                    <div class="endpoint-list">
                        <div class="endpoint-item">
                            <span class="http-method get">GET</span>
                            <code class="endpoint-url">https://hodlxxi.com/.well-known/openid-configuration</code>
                            <button class="copy-btn" onclick="copyToClipboard('https://hodlxxi.com/.well-known/openid-configuration')">📋</button>
                        </div>
                        <div class="endpoint-item">
                            <span class="http-method get">GET</span>
                            <code class="endpoint-url">https://hodlxxi.com/oauth/jwks.json</code>
                            <button class="copy-btn" onclick="copyToClipboard('https://hodlxxi.com/oauth/jwks.json')">📋</button>
                        </div>
                    </div>
                </div>

                <!-- Metered API -->
                <div class="api-block">
                    <h4>⚡ Metered API (Pay per Use)</h4>
                    <p class="api-description">Lightning-metered verification endpoint - pay only for what you use</p>
                    <div class="endpoint-list">
                        <div class="endpoint-item">
                            <span class="http-method post">POST</span>
                            <code class="endpoint-url">https://hodlxxi.com/v1/verify</code>
                            <button class="copy-btn" onclick="copyToClipboard('https://hodlxxi.com/v1/verify')">📋</button>
                        </div>
                    </div>
                    <div class="api-note">
                        <span class="note-icon">💡</span>
                        <span>Returns <code>402 Payment Required</code> with BOLT11 invoice when credits depleted</span>
                    </div>
                </div>

                <!-- Code Examples -->
                <div class="code-examples">
                    <h3 class="api-section-title">💻 Integration Examples</h3>

                    <!-- Example 1: Configure OIDC -->
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-title">1. Configure OIDC Provider</span>
                            <button class="copy-code-btn" onclick="copyCode('code-oidc-config')">Copy</button>
                        </div>
                        <pre id="code-oidc-config"><code class="language-javascript">// Example: Next.js / NextAuth.js
import NextAuth from "next-auth";

export default NextAuth({
  providers: [
    {
      id: "hodlxxi",
      name: "HODLXXI",
      type: "oauth",
      wellKnown: "https://hodlxxi.com/.well-known/openid-configuration",
      authorization: { params: { scope: "openid profile" } },
      clientId: process.env.HODLXXI_CLIENT_ID,
      clientSecret: process.env.HODLXXI_CLIENT_SECRET,
      profile(profile) {
        return {
          id: profile.sub,
          name: profile.name,
          email: profile.email,
        }
      }
    }
  ]
});</code></pre>
                    </div>

                    <!-- Example 2: Token Exchange -->
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-title">2. Exchange Authorization Code for Token</span>
                            <button class="copy-code-btn" onclick="copyCode('code-token-exchange')">Copy</button>
                        </div>
                        <pre id="code-token-exchange"><code class="language-bash">curl -X POST https://hodlxxi.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=https://yourapp.com/callback"</code></pre>
                    </div>

                    <!-- Example 3: Verify Proof -->
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-title">3. Verify Bitcoin Signature (Metered)</span>
                            <button class="copy-code-btn" onclick="copyCode('code-verify-proof')">Copy</button>
                        </div>
                        <pre id="code-verify-proof"><code class="language-bash">curl -X POST https://hodlxxi.com/v1/verify \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "bip322",
    "pubkey": "02ab1234567890abcdef...",
    "message": "login:nonce:abc123",
    "signature": "H+Xy9..."
  }'</code></pre>
                    </div>

                    <!-- Discovery Response -->
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-title">📡 Discovery Endpoint Response</span>
                            <button class="copy-code-btn" onclick="copyCode('code-discovery')">Copy</button>
                        </div>
                        <pre id="code-discovery"><code class="language-json">{
  "issuer": "https://hodlxxi.com",
  "authorization_endpoint": "https://hodlxxi.com/oauth/authorize",
  "token_endpoint": "https://hodlxxi.com/oauth/token",
  "jwks_uri": "https://hodlxxi.com/oauth/jwks.json",
  "userinfo_endpoint": "https://hodlxxi.com/oauth/userinfo",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"]
}</code></pre>
                    </div>
                </div>

                <!-- Live Test Section -->
                <div class="live-test-section">
                    <h3 class="api-section-title">🚀 Test Live Endpoints</h3>
                    <div class="test-grid">
                        <div class="test-card">
                            <h4>Discovery Endpoint</h4>
                            <p>Fetch OpenID configuration</p>
                            <button class="test-button" onclick="testEndpoint('discovery')">
                                <span id="discovery-status">Test Now</span>
                            </button>
                            <pre id="discovery-result" class="test-result"></pre>
                        </div>
                        <div class="test-card">
                            <h4>System Status</h4>
                            <p>Check service health</p>
                            <button class="test-button" onclick="testEndpoint('status')">
                                <span id="status-status">Test Now</span>
                            </button>
                            <pre id="status-result" class="test-result"></pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- CTA Section -->
    <section id="contact" class="cta-section">
        <div class="container">
            <div class="cta-box">
                <h2>Ready to Build on Bitcoin?</h2>
                <p>Schedule a consultation with our team to discuss your specific needs</p>
                <div class="cta-buttons-large">
                    <a href="mailto:hodlxxi@proton.me" class="white-button">E-mail</a>
                    <a href="https://hodlxxi.com/oauthx/docs" target="_blank" class="secondary-button" style="background: rgba(255,255,255,0.2); color: white; border-color: white;">Verify</a>
                    <a href="/login" target="_blank" class="secondary-button" style="background: rgba(0,255,136,0.2); color: white; border: 2px solid var(--accent);">Login</a>
                </div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer>
        <div class="container">
            <div class="footer-content">
                <div class="footer-brand">
                    <h3>⚡ KeyAuth Protocol ⚡</h3>
                    <p>The universal Bitcoin identity layer bridging Web2 to Web3. Non-custodial authentication, proof-of-funds, and covenant coordination for the Bitcoin economy.</p>
                </div>
                <div class="footer-links">
                    <h4>Product</h4>
                    <ul>
                        <li><a href="#capabilities">Capabilities</a></li>
                        <li><a href="#use-cases">Use Cases</a></li>
                        <li><a href="#developer">Developer Portal</a></li>
                        <li><a href="#features">Features</a></li>
                        <li><a href="https://hodlxxi.com/oauthx/docs" target="_blank">Documentation</a></li>
                        <li><a href="https://hodlxxi.com/playground" target="_blank">API Playground</a></li>
                    </ul>
                </div>
                <div class="footer-links">
                    <h4>Company</h4>
                    <ul>
                        <li><a href="#">About</a></li>
                        <li><a href="#">Blog</a></li>
                        <li><a href="#">Careers</a></li>
                        <li><a href="#">Contact</a></li>
                    </ul>
                </div>
                <div class="footer-links">
                    <h4>Resources</h4>
                    <ul>
                        <li><a href="#">GitHub</a></li>
                        <li><a href="#">Support</a></li>
                        <li><a href="#">Privacy Policy</a></li>
                        <li><a href="#">Terms of Service</a></li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <p>&copy; 2025 KeyAuth Protocol. All rights reserved. Built on Bitcoin.</p>
            </div>
        </div>
    </footer>

    <script>
        // Tab switching for use cases - Fixed for mobile
        function showTab(tabName) {
            // Hide all content
            document.querySelectorAll('.use-case-content').forEach(content => {
                content.classList.remove('active');
            });

            // Remove active from all buttons
            document.querySelectorAll('.tab-button').forEach(button => {
                button.classList.remove('active');
            });

            // Show selected content
            const targetContent = document.getElementById(tabName);
            if (targetContent) {
                targetContent.classList.add('active');
            }

            // Add active to clicked button - find button by matching text or data attribute
            document.querySelectorAll('.tab-button').forEach(button => {
                const buttonText = button.textContent.toLowerCase();
                if (buttonText.includes(tabName.toLowerCase()) ||
                    button.getAttribute('data-tab') === tabName) {
                    button.classList.add('active');
                }
            });
        }

        // Add click handlers to buttons (better than inline onclick for mobile)
        document.addEventListener('DOMContentLoaded', function() {
            const tabButtons = [
                { button: document.querySelectorAll('.tab-button')[0], tab: 'finance' },
                { button: document.querySelectorAll('.tab-button')[1], tab: 'enterprise' },
                { button: document.querySelectorAll('.tab-button')[2], tab: 'web3' },
                { button: document.querySelectorAll('.tab-button')[3], tab: 'community' }
            ];

            tabButtons.forEach(({ button, tab }) => {
                if (button) {
                    button.setAttribute('data-tab', tab);
                    button.addEventListener('click', function(e) {
                        e.preventDefault();
                        showTab(tab);
                    });
                }
            });
        });

        // Smooth scroll
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });

        // Intersection Observer for animations
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -100px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, observerOptions);

        // Observe all cards
        document.querySelectorAll('.capability-card, .use-case-card, .feature-card, .timeline-item').forEach(el => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(30px)';
            el.style.transition = 'all 0.6s ease-out';
            observer.observe(el);
        });

        // ============================================================================
        // MATRIX BACKGROUND ANIMATION - WARP EFFECT
        // ============================================================================

        /* --- Matrix: Warp (0s and 1s flying toward camera) --- */
        function startMatrixWarp(canvas) {
            if (!canvas) return () => {};
            const ctx = canvas.getContext('2d');
            const CHARS = ['0', '1'];
            let width = 0, height = 0, particles = [], raf = null;

            function resize() {
                width = window.innerWidth;
                height = window.innerHeight;
                canvas.width = width;
                canvas.height = height;
                particles = [];
                for (let i = 0; i < 400; i++) {
                    particles.push({
                        x: (Math.random() - 0.5) * width,
                        y: (Math.random() - 0.5) * height,
                        z: Math.random() * 800 + 100
                    });
                }
            }

            function draw() {
                ctx.fillStyle = 'rgba(0,0,0,0.25)';
                ctx.fillRect(0, 0, width, height);
                ctx.fillStyle = '#00ff88';
                for (const p of particles) {
                    const scale = 200 / p.z;
                    const x2 = width / 2 + p.x * scale;
                    const y2 = height / 2 + p.y * scale;
                    const size = Math.max(8 * scale, 1);
                    ctx.font = size + 'px monospace';
                    ctx.fillText(CHARS[Math.random() > 0.5 ? 1 : 0], x2, y2);
                    p.z -= 5;
                    if (p.z < 1) {
                        p.x = (Math.random() - 0.5) * width;
                        p.y = (Math.random() - 0.5) * height;
                        p.z = 800;
                    }
                }
                raf = requestAnimationFrame(draw);
            }

            function onVis() {
                if (document.hidden) {
                    if (raf) cancelAnimationFrame(raf), raf = null;
                } else {
                    if (!raf) raf = requestAnimationFrame(draw);
                }
            }

            function onResize() {
                resize();
            }

            window.addEventListener('resize', onResize);
            document.addEventListener('visibilitychange', onVis);
            resize();
            raf = requestAnimationFrame(draw);
            return function stop() {
                if (raf) cancelAnimationFrame(raf), raf = null;
                window.removeEventListener('resize', onResize);
                document.removeEventListener('visibilitychange', onVis);
            };
        }

        /* --- Initialize Matrix Warp Background --- */
        (function initMatrix() {
            const warpCanvas = document.getElementById('matrix-warp');
            if (!warpCanvas) return;

            let stopWarp = startMatrixWarp(warpCanvas);

            // Cleanup on page unload
            window.addEventListener('beforeunload', () => {
                if (stopWarp) stopWarp();
            });
        })();

        // ============================================================================
        // DEVELOPER PORTAL FUNCTIONS
        // ============================================================================

        // Copy text to clipboard
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                // Visual feedback
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = '✓';
                btn.style.color = 'var(--accent)';
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.color = '';
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy:', err);
            });
        }

        // Copy code block
        function copyCode(elementId) {
            const codeElement = document.getElementById(elementId);
            if (!codeElement) return;

            const text = codeElement.textContent;
            navigator.clipboard.writeText(text).then(() => {
                // Visual feedback
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(() => {
                    btn.textContent = originalText;
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy:', err);
            });
        }

        // Test live endpoints
        async function testEndpoint(type) {
            const statusElement = document.getElementById(`${type}-status`);
            const resultElement = document.getElementById(`${type}-result`);

            statusElement.textContent = 'Testing...';
            resultElement.textContent = '';

            try {
                let url;
                if (type === 'discovery') {
                    url = 'https://hodlxxi.com/.well-known/openid-configuration';
                } else if (type === 'status') {
                    url = '/health';
                }

                const response = await fetch(url);
                const data = await response.json();

                statusElement.textContent = `✓ ${response.status} ${response.statusText}`;
                resultElement.textContent = JSON.stringify(data, null, 2);
                resultElement.style.display = 'block';
            } catch (error) {
                statusElement.textContent = '✗ Error';
                resultElement.textContent = `Error: ${error.message}

This might be due to CORS restrictions. Try accessing the URL directly in a new tab.`;
                resultElement.style.display = 'block';
                resultElement.style.color = 'var(--bitcoin-orange)';
            }
        }
    </script>
</body>
</html>
"""
    return render_template_string(html)


@ui_bp.route("/dashboard")
def dashboard():
    """
    User dashboard (requires authentication).

    Returns:
        HTML dashboard
    """
    pubkey = session.get("logged_in_pubkey")
    access_level = session.get("access_level", "guest")

    if not pubkey:
        return """
        <html>
        <body>
            <h1>Not Authenticated</h1>
            <p>Please <a href="/login">login</a> first.</p>
        </body>
        </html>
        """, 401

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <style>
        body {{ margin: 0; padding: 2rem; font-family: system-ui; background: #0b0f10; color: #e6f1ef; }}
        .card {{ background: #11171a; border: 1px solid #00ff88; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; }}
        h1 {{ color: #00ff88; }}
        .pubkey {{ font-family: monospace; word-break: break-all; }}
    </style>
</head>
<body>
    <h1>Dashboard</h1>
    <div class="card">
        <h3>Authentication Status</h3>
        <p><strong>Public Key:</strong> <span class="pubkey">{pubkey}</span></p>
        <p><strong>Access Level:</strong> {access_level}</p>
    </div>
    <div class="card">
        <h3>Quick Links</h3>
        <p>
            <a href="/playground">API Playground</a> |
            <a href="/oauth/clients">OAuth Clients</a> |
            <a href="/logout">Logout</a>
        </p>
    </div>
</body>
</html>
    """
    return render_template_string(html)


@ui_bp.route("/playground")
def playground():
    """
    API testing playground.

    Returns:
        HTML API playground
    """
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>API Playground</title>
    <style>
        body { margin: 0; padding: 2rem; font-family: system-ui; background: #0b0f10; color: #e6f1ef; }
        .endpoint { background: #11171a; border: 1px solid #00ff88; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; }
        h1 { color: #00ff88; }
        button { background: #00ff88; color: #0b0f10; border: none; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; }
        button:hover { opacity: 0.8; }
        pre { background: #000; padding: 1rem; border-radius: 6px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>API Playground</h1>

    <div class="endpoint">
        <h3>Health Check</h3>
        <button onclick="fetchEndpoint('/health', 'health-result')">GET /health</button>
        <pre id="health-result">Click to fetch</pre>
    </div>

    <div class="endpoint">
        <h3>Metrics</h3>
        <button onclick="fetchEndpoint('/metrics', 'metrics-result')">GET /metrics</button>
        <pre id="metrics-result">Click to fetch</pre>
    </div>

    <div class="endpoint">
        <h3>OIDC Discovery</h3>
        <button onclick="fetchEndpoint('/.well-known/openid-configuration', 'oidc-result')">GET /.well-known/openid-configuration</button>
        <pre id="oidc-result">Click to fetch</pre>
    </div>

    <div class="endpoint">
        <h3>JWKS</h3>
        <button onclick="fetchEndpoint('/oauth/jwks.json', 'jwks-result')">GET /oauth/jwks.json</button>
        <pre id="jwks-result">Click to fetch</pre>
    </div>

    <script>
        async function fetchEndpoint(url, resultId) {
            const resultEl = document.getElementById(resultId);
            resultEl.textContent = 'Loading...';
            try {
                const response = await fetch(url);
                const data = await response.json();
                resultEl.textContent = JSON.stringify(data, null, 2);
            } catch (error) {
                resultEl.textContent = 'Error: ' + error.message;
            }
        }
    </script>
</body>
</html>
    """
    return render_template_string(html)
