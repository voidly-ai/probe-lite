#!/usr/bin/env node
// Voidly Probe Lite — lightweight censorship probe for Raspberry Pi & headless Linux
// Usage: node probe.mjs [--register] [--interval 300] [--country US]

import { createHash, createHmac, randomUUID } from 'crypto';
import dns from 'dns/promises';
import https from 'https';
import http from 'http';
import os from 'os';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = join(__dirname, '.probe-config.json');
const API = 'https://api.voidly.ai';

// ── Domain List (62 targets, same as desktop app) ──
const DOMAINS = {
  social: ['x.com','twitter.com','facebook.com','instagram.com','youtube.com','tiktok.com','reddit.com','linkedin.com','pinterest.com','tumblr.com','snapchat.com','discord.com'],
  messaging: ['whatsapp.com','telegram.org','signal.org','viber.com','messenger.com','line.me','wechat.com','skype.com'],
  news: ['bbc.com','nytimes.com','reuters.com','theguardian.com','washingtonpost.com','cnn.com','aljazeera.com','dw.com','rferl.org','voanews.com','medium.com','substack.com'],
  privacy: ['torproject.org','nordvpn.com','expressvpn.com','protonvpn.com','mullvad.net','surfshark.com','vpngate.net','psiphon.ca','getlantern.org','proton.me'],
  rights: ['amnesty.org','hrw.org','rsf.org','eff.org','accessnow.org','freedomhouse.org','article19.org','cpj.org'],
  tech: ['google.com','duckduckgo.com','bing.com','wikipedia.org','archive.org','wikileaks.org','github.com','gitlab.com','stackoverflow.com','hackerone.com','pastebin.com','dropbox.com'],
};

const ALL_DOMAINS = Object.entries(DOMAINS).flatMap(([cat, domains]) =>
  domains.map(d => ({ domain: d, category: cat }))
);

// ── Config ──
function loadConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); }
  catch { return null; }
}
function saveConfig(cfg) { fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2)); }

// ── HTTP helper ──
function fetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.request(url, {
      method: opts.method || 'GET',
      headers: opts.headers || {},
      timeout: opts.timeout || 10000,
    }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

// ── Register as community probe ──
async function registerNode(country) {
  const nodeId = `pi-${os.hostname()}-${randomUUID().slice(0, 8)}`;
  const token = randomUUID();

  try {
    const resp = await fetch(`${API}/v1/probe/community/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        node_id: nodeId,
        country: country || 'XX',
        node_type: 'community',
        label: `Pi ${os.hostname()}`,
      }),
    });
    const data = JSON.parse(resp.body);
    const cfg = {
      nodeId: data.node_id || nodeId,
      token: data.token || token,
      country: country || 'XX',
      registeredAt: new Date().toISOString(),
    };
    saveConfig(cfg);
    console.log(`✅ Registered as ${cfg.nodeId} (country: ${cfg.country})`);
    return cfg;
  } catch (e) {
    // Fallback — register locally and submit without auth
    const cfg = { nodeId, token, country: country || 'XX', registeredAt: new Date().toISOString() };
    saveConfig(cfg);
    console.log(`⚠️  API registration failed (${e.message}), using local ID: ${nodeId}`);
    return cfg;
  }
}

// ── Probe a single domain ──
async function probeDomain(domain, category) {
  const result = {
    domain,
    targetUrl: `https://${domain}`,
    category,
    success: false,
    isBlocked: false,
    latencyMs: 0,
    httpStatus: 0,
    errorType: null,
    errorDetail: null,
    blockType: null,
    confidence: 0,
    dnsResolved: false,
    timestamp: new Date().toISOString(),
  };

  const start = Date.now();

  // Step 1: DNS resolution
  try {
    const addrs = await dns.resolve4(domain);
    result.dnsResolved = addrs.length > 0;
    if (!result.dnsResolved) {
      result.isBlocked = true;
      result.blockType = 'nxdomain';
      result.confidence = 0.8;
      result.errorType = 'nxdomain';
      result.latencyMs = Date.now() - start;
      return result;
    }
  } catch (e) {
    result.errorType = 'dns-error';
    result.errorDetail = e.code || e.message;
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') {
      result.isBlocked = true;
      result.blockType = 'nxdomain';
      result.confidence = 0.7;
    } else if (e.code === 'ETIMEOUT' || e.code === 'EAI_AGAIN') {
      result.isBlocked = true;
      result.blockType = 'dns-timeout';
      result.confidence = 0.5;
    }
    result.latencyMs = Date.now() - start;
    return result;
  }

  // Step 2: HTTPS request
  try {
    const resp = await fetch(`https://${domain}`, { timeout: 10000 });
    result.httpStatus = resp.status;
    result.latencyMs = Date.now() - start;

    if (resp.status === 451) {
      result.isBlocked = true;
      result.blockType = 'http-451';
      result.confidence = 0.95;
    } else if (resp.status >= 200 && resp.status < 400) {
      result.success = true;
    } else if (resp.status === 403) {
      // Could be CDN rate limit, low confidence
      result.success = true; // Treat as accessible
    }

    // Check for suspicious redirects
    if (resp.status >= 300 && resp.status < 400 && resp.headers.location) {
      const loc = resp.headers.location;
      if (!loc.includes(domain) && !loc.startsWith('/')) {
        result.isBlocked = true;
        result.blockType = 'redirect';
        result.confidence = 0.6;
        result.errorDetail = `Redirect to ${loc.slice(0, 100)}`;
      }
    }

    // Block page fingerprint (hash first 10KB)
    if (resp.body && resp.status === 200) {
      const hash = createHash('sha256').update(resp.body.slice(0, 10240)).digest('hex');
      result.blockpageHash = hash;
    }
  } catch (e) {
    result.latencyMs = Date.now() - start;
    result.errorDetail = e.message;

    if (e.message.includes('timeout') || e.code === 'ETIMEDOUT') {
      result.errorType = 'tcp-timeout';
      result.isBlocked = true;
      result.blockType = 'tcp-timeout';
      result.confidence = 0.6;
    } else if (e.code === 'ECONNRESET') {
      result.errorType = 'tcp-reset';
      result.isBlocked = true;
      result.blockType = 'tcp-reset';
      result.confidence = 0.9;
    } else if (e.code === 'ECONNREFUSED') {
      result.errorType = 'tcp-refused';
      result.isBlocked = true;
      result.blockType = 'tcp-refused';
      result.confidence = 0.7;
    } else if (e.message.includes('certificate') || e.message.includes('SSL') || e.message.includes('TLS')) {
      result.errorType = 'tls-error';
      result.isBlocked = true;
      result.blockType = 'tls-reset';
      result.confidence = 0.8;
    } else {
      result.errorType = 'network-error';
    }
  }

  return result;
}

// ── Submit results ──
async function submitResults(config, results) {
  const payload = {
    nodeId: config.nodeId,
    nodeCountry: config.country,
    nodeType: 'community',
    timestamp: new Date().toISOString(),
    submissionId: randomUUID(),
    probeMode: 'direct',
    results,
  };

  const body = JSON.stringify(payload);
  const sig = createHmac('sha256', config.token).update(body).digest('hex');

  try {
    const resp = await fetch(`${API}/v1/probe/results`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.token}`,
        'X-Voidly-Signature': `sha256=${sig}`,
        'User-Agent': 'VoidlyProbe-Lite/1.0',
      },
      body,
      timeout: 15000,
    });
    return resp.status >= 200 && resp.status < 300;
  } catch (e) {
    console.error(`  ⚠️  Submit failed: ${e.message}`);
    return false;
  }
}

// ── Run a probe cycle ──
async function runCycle(config, batchSize = 20) {
  // Rotate through domains
  const offset = Math.floor(Date.now() / 60000) % ALL_DOMAINS.length;
  const batch = [];
  for (let i = 0; i < batchSize; i++) {
    batch.push(ALL_DOMAINS[(offset + i) % ALL_DOMAINS.length]);
  }

  console.log(`\n[${new Date().toLocaleTimeString()}] Probing ${batch.length} domains...`);

  // Probe all in parallel
  const results = await Promise.all(
    batch.map(({ domain, category }) => probeDomain(domain, category))
  );

  const ok = results.filter(r => r.success).length;
  const blocked = results.filter(r => r.isBlocked).length;
  const errors = results.filter(r => !r.success && !r.isBlocked).length;

  console.log(`  ✅ ${ok} accessible  🚫 ${blocked} blocked  ⚠️  ${errors} errors`);

  if (blocked > 0) {
    for (const r of results.filter(r => r.isBlocked)) {
      console.log(`  🚫 ${r.domain} — ${r.blockType} (${Math.round(r.confidence * 100)}%)`);
    }
  }

  // Submit
  const submitted = await submitResults(config, results);
  console.log(submitted ? '  📡 Results submitted to relay' : '  ⚠️  Submission failed (will retry)');

  return results;
}

// ── Main ──
async function main() {
  const args = process.argv.slice(2);
  const interval = parseInt(args.find((_, i, a) => a[i - 1] === '--interval') || '300');
  const country = args.find((_, i, a) => a[i - 1] === '--country') || undefined;
  const registerFlag = args.includes('--register');

  console.log('╔══════════════════════════════════════╗');
  console.log('║     Voidly Probe Lite v1.0           ║');
  console.log('║     Censorship monitoring node       ║');
  console.log('╚══════════════════════════════════════╝');
  console.log(`  Platform: ${os.platform()} ${os.arch()}`);
  console.log(`  Hostname: ${os.hostname()}`);
  console.log(`  Interval: ${interval}s`);
  console.log(`  Domains:  ${ALL_DOMAINS.length}`);

  let config = loadConfig();
  if (!config || registerFlag) {
    config = await registerNode(country);
  } else {
    console.log(`  Node ID:  ${config.nodeId}`);
    console.log(`  Country:  ${config.country}`);
  }

  // Run first cycle immediately
  await runCycle(config);

  // Then loop
  console.log(`\nRunning every ${interval}s. Press Ctrl+C to stop.`);
  setInterval(() => runCycle(config), interval * 1000);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
