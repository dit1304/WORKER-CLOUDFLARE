// ============================================
// Environment variables are injected by Wrangler
// from GitHub Secrets via wrangler.toml [vars]
// DO NOT hardcode secrets here!
// ============================================


// ============================================
// GitHub Sync: Auto-update users.json di GitHub
// ketika ada user baru daftar atau dihapus
// ============================================
async function syncUsersToGitHub(users) {
  try {
    if (typeof GITHUB_TOKEN_ENV === 'undefined' || !GITHUB_TOKEN_ENV ||
        typeof GITHUB_REPO_ENV === 'undefined' || !GITHUB_REPO_ENV) {
      console.log('GitHub sync disabled: GITHUB_TOKEN or GITHUB_REPO not set');
      return;
    }
    const repo = GITHUB_REPO_ENV;
    const filePath = 'users.json';
    const apiUrl = `https://api.github.com/repos/${repo}/contents/${filePath}`;

    const kvBulk = users.map(id => ({ key: id, value: JSON.stringify({ registered: true }) }));
    const newContent = btoa(unescape(encodeURIComponent(JSON.stringify(kvBulk, null, 2))));

    let sha = null;
    try {
      const existing = await fetch(apiUrl, {
        headers: {
          'Authorization': `Bearer ${GITHUB_TOKEN_ENV}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'CF-Worker-Bot'
        }
      });
      if (existing.ok) {
        const data = await existing.json();
        sha = data.sha;
      }
    } catch (e) {
      console.log('Could not fetch existing users.json, will create new');
    }

    const body = {
      message: `Auto-sync: update users.json (${users.length} users)`,
      content: newContent,
      branch: 'main'
    };
    if (sha) body.sha = sha;

    const response = await fetch(apiUrl, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${GITHUB_TOKEN_ENV}`,
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
        'User-Agent': 'CF-Worker-Bot'
      },
      body: JSON.stringify(body)
    });

    if (response.ok) {
      console.log(`GitHub sync OK: ${users.length} users synced to ${repo}/users.json`);
    } else {
      const errText = await response.text();
      console.error('GitHub sync failed:', response.status, errText);
    }
  } catch (error) {
    console.error('GitHub sync error:', error);
  }
}

// Bot configuration
const BOT_TOKEN = BOT_TOKEN_ENV;
const ADMIN_USERNAME = ADMIN_USERNAME_ENV;

// Server configuration
const servervless = SERVER_VLESS_ENV;
const servertrojan = SERVER_TROJAN_ENV;
const serverwildcard = SERVER_WILDCARD_ENV;
const passuid = PASS_UID_ENV;
const API_URL = API_URL_ENV;
const WATERMARK = "\n*᠌* ";

// Cloudflare configuration
const CLOUDFLARE_API_TOKEN = CF_API_TOKEN_ENV;
const CLOUDFLARE_ZONE_ID = CF_ZONE_ID_ENV;
const CLOUDFLARE_ACCOUNT_ID = CF_ACCOUNT_ID_ENV;


//document
async function sendDocument(chatId, file, caption = '') {
  const formData = new FormData();
  formData.append('chat_id', chatId);
  formData.append('document', file);
  if (caption) formData.append('caption', caption);

  await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendDocument`, {
    method: 'POST',
    body: formData
  });
}

// ==== V2RAY → CLASH CONVERTER (pure JS, tanpa UI) ====

// kecil-kecil berguna
const removeEmoji = s => s.replace(/[\p{Extended_Pictographic}\p{Emoji_Presentation}\uFE0F]/gu, '').trim();
const safeInt = v => (v && !Number.isNaN(Number(v)) ? Number(v) : 0);

// --- Parsers ---
function parseVmess(url) {
  const raw = url.trim();
  if (!raw.startsWith('vmess://')) throw new Error('Invalid VMESS');
  const jsonStr = atob(raw.slice('vmess://'.length));
  const cfg = JSON.parse(jsonStr);

  const proxy = {
    name: cfg.ps || 'Vmess Server',
    type: 'vmess',
    server: cfg.add,
    port: safeInt(cfg.port),
    uuid: cfg.id,
    alterId: safeInt(cfg.aid) || 0,
    cipher: cfg.scy || 'auto',
    tls: cfg.tls === 'tls',
    network: cfg.net || 'tcp',
    'skip-cert-verify': true,
    udp: true,
  };

  if (cfg.net === 'ws') {
    proxy['ws-opts'] = {
      path: cfg.path || '/',
      headers: { Host: cfg.host || cfg.add }
    };
  }
  if (cfg.net === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': cfg.path || '' };
  }
  if (cfg.tls === 'tls') {
    proxy.servername = cfg.sni || cfg.host || cfg.add;
  }
  return proxy;
}

function parseVless(url) {
  const raw = url.trim();
  if (!raw.startsWith('vless://')) throw new Error('Invalid VLESS');
  const u = new URL(raw.replace('vless://', 'http://'));
  const q = u.searchParams;
  const name = decodeURIComponent(u.hash.slice(1)) || 'Vless Server';

  const proxy = {
    name,
    type: 'vless',
    server: u.hostname,
    port: safeInt(u.port),
    uuid: u.username,
    cipher: 'none',
    tls: q.get('security') === 'tls',
    network: q.get('type') || 'tcp',
    'skip-cert-verify': true,
    udp: true,
  };

  if (proxy.network === 'ws') {
    proxy['ws-opts'] = {
      path: decodeURIComponent(q.get('path') || '/'),
      headers: { Host: q.get('host') || u.hostname }
    };
  }
  if (proxy.network === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': q.get('serviceName') || '' };
  }
  if (proxy.tls) proxy.servername = q.get('sni') || u.hostname;

  return proxy;
}

function parseTrojan(url) {
  const raw = url.trim();
  if (!raw.startsWith('trojan://')) throw new Error('Invalid TROJAN');
  const u = new URL(raw.replace('trojan://', 'http://'));
  const q = u.searchParams;
  const name = decodeURIComponent(u.hash.slice(1)) || 'Trojan Server';

  const proxy = {
    name,
    type: 'trojan',
    server: u.hostname,
    port: safeInt(u.port),
    password: u.username,
    sni: q.get('sni') || u.hostname,
    'skip-cert-verify': true,
    udp: true,
  };

  if (q.get('type') === 'ws') {
    proxy.network = 'ws';
    proxy['ws-opts'] = {
      path: decodeURIComponent(q.get('path') || '/'),
      headers: { Host: q.get('host') || u.hostname }
    };
  }
  return proxy;
}

function parseSS(url) {
  const raw = url.trim();
  if (!raw.startsWith('ss://')) throw new Error('Invalid SS');
  const u = new URL(raw.replace('ss://', 'http://'));
  const name = decodeURIComponent(u.hash.slice(1)) || 'SS Server';

  let cipher, password;
  try {
    const decoded = atob(u.username);
    [cipher, password] = decoded.split(':');
  } catch {
    [cipher, password] = u.username.split(':');
  }
  return {
    name, type: 'ss',
    server: u.hostname,
    port: safeInt(u.port),
    cipher, password,
    udp: true
  };
}

function parseLine(url) {
  const s = url.trim();
  if (!s) throw new Error('Empty');
  if (s.startsWith('vmess://')) return parseVmess(s);
  if (s.startsWith('vless://')) return parseVless(s);
  if (s.startsWith('trojan://')) return parseTrojan(s);
  if (s.startsWith('ss://'))     return parseSS(s);
  throw new Error('Unsupported protocol');
}

// --- Transform & YAML ---
function dedup(proxies) {
  const seen = new Set();
  return proxies.filter(p => {
    const key = `${p.type}|${p.server}|${p.port}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function applyNameDecor(p, { prefix = '', suffix = '', stripEmoji = false }) {
  let name = p.name || `${p.type.toUpperCase()} ${p.server}`;
  if (stripEmoji) name = removeEmoji(name);
  if (prefix) name = prefix + name;
  if (suffix) name = name + suffix;
  return { ...p, name };
}

function filterByOptions(list, { filter = '', exclude = '', protocol = 'all' }) {
  let out = [...list];
  const incs = (filter || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
  const excs = (exclude || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);

  if (incs.length) {
    out = out.filter(p => {
      const hay = `${p.name} ${p.server}`.toLowerCase();
      return incs.some(k => hay.includes(k));
    });
  }
  if (excs.length) {
    out = out.filter(p => {
      const hay = `${p.name} ${p.server}`.toLowerCase();
      return !excs.some(k => hay.includes(k));
    });
  }
  if (protocol !== 'all') {
    out = out.filter(p => p.type === protocol);
  }
  // sort by name for stability
  out.sort((a,b)=> (a.name||'').localeCompare(b.name||''));
  return out;
}

function generateClashYAML(proxies, {
  groupName = '🚀 Proxy',
  httpPort = 7890,
  socksPort = 7891,
  mixedPort = 0,
  allowLan = false,
  enableIPv6 = false,
  dnsEnable = true,
  adblock = true,
  chinaDirect = true,
  loadBalance = false,
} = {}) {
  const proxyNames = proxies.map(p => p.name);
  let yaml = `port: ${httpPort}
socks-port: ${socksPort}
${mixedPort ? `mixed-port: ${mixedPort}\n` : ''}allow-lan: ${allowLan}
mode: rule
log-level: info
ipv6: ${enableIPv6}
external-controller: 127.0.0.1:9090
`;

  if (dnsEnable) {
    yaml += `
    dns:
    enable: true
    listen: 0.0.0.0:53
    ipv6: ${enableIPv6}
    enhanced-mode: fake-ip
    fake-ip-range: 198.18.0.1/16
    nameserver: [112.215.203.254, 112.215.203.248]
  fallback:
    - https://dns.google/dns-query
    - https://cloudflare-dns.com/dns-query
  fallback-filter: { geoip: true, geoip-code: CN }
`;
  }

  // proxies
  yaml += `\nproxies:\n`;
  for (const p of proxies) {
    // bersihkan undefined/empty
    const clean = {};
    for (const k of Object.keys(p)) {
      const v = p[k];
      if (v !== undefined && v !== '') clean[k] = v;
    }
    yaml += '  - ' + JSON.stringify(clean, null, 2).split('\n').join('\n    ') + '\n';
  }

  // proxy-groups
  yaml += `
proxy-groups:
  - name: "${groupName}"
    type: select
    proxies:
      - ♻️ Auto
      - ⚡ Fallback
${loadBalance ? '      - ⚖️ LoadBalance\n' : ''}${proxyNames.map(n => `      - "${n}"`).join('\n')}
      - DIRECT

  - name: "♻️ Auto"
    type: url-test
    proxies:
${proxyNames.map(n => `      - "${n}"`).join('\n')}
    url: 'http://www.gstatic.com/generate_204'
    interval: 300

  - name: "⚡ Fallback"
    type: fallback
    proxies:
${proxyNames.map(n => `      - "${n}"`).join('\n')}
    url: 'http://www.gstatic.com/generate_204'
    interval: 300
`;

  if (loadBalance) {
    yaml += `
  - name: "⚖️ LoadBalance"
    type: load-balance
    proxies:
${proxyNames.map(n => `      - "${n}"`).join('\n')}
    url: 'http://www.gstatic.com/generate_204'
    interval: 300
`;
  }

  yaml += `
  - name: "🎯 Direct"
    type: select
    proxies: [DIRECT, "${groupName}"]

  - name: "🛑 Reject"
    type: select
    proxies: [REJECT, DIRECT]

  - name: "🌍 Global"
    type: select
    proxies: ["${groupName}", ♻️ Auto, DIRECT]

  - name: "📺 Streaming"
    type: select
    proxies: ["${groupName}", ♻️ Auto${proxyNames.slice(0,3).map(n=>`, "${n}"`).join('')}]

  - name: "🎮 Gaming"
    type: select
    proxies: [DIRECT, "${groupName}"]

  - name: "📱 Telegram"
    type: select
    proxies: ["${groupName}", ♻️ Auto]

  - name: "🤖 AI"
    type: select
    proxies: ["${groupName}", ♻️ Auto]

rules:
  - IP-CIDR,127.0.0.0/8,DIRECT
  - IP-CIDR,192.168.0.0/16,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - IP-CIDR,172.16.0.0/12,DIRECT
  - IP-CIDR,100.64.0.0/10,DIRECT
  - IP-CIDR,224.0.0.0/4,DIRECT
  - IP-CIDR,fe80::/10,DIRECT
  - DOMAIN-SUFFIX,local,DIRECT
`;

  if (adblock) {
    yaml += `  - DOMAIN-SUFFIX,doubleclick.net,🛑 Reject
  - DOMAIN-SUFFIX,googleadservices.com,🛑 Reject
  - DOMAIN-SUFFIX,googlesyndication.com,🛑 Reject
  - DOMAIN-KEYWORD,adservice,🛑 Reject
  - DOMAIN-KEYWORD,analytics,🛑 Reject
  - DOMAIN-KEYWORD,pagead,🛑 Reject
`;
  }

  yaml += `  - DOMAIN-SUFFIX,openai.com,🤖 AI
  - DOMAIN-SUFFIX,claude.ai,🤖 AI
  - DOMAIN-SUFFIX,t.me,📱 Telegram
  - DOMAIN-SUFFIX,telegram.org,📱 Telegram
  - DOMAIN-SUFFIX,netflix.com,📺 Streaming
  - DOMAIN-SUFFIX,youtube.com,📺 Streaming
  - DOMAIN-SUFFIX,spotify.com,📺 Streaming
  - DOMAIN-SUFFIX,steampowered.com,🎮 Gaming
  - DOMAIN-SUFFIX,discord.com,🎮 Gaming
`;

  if (chinaDirect) {
    yaml += `  - GEOIP,CN,🎯 Direct
  - DOMAIN-SUFFIX,cn,🎯 Direct
  - DOMAIN-KEYWORD,baidu,🎯 Direct
  - DOMAIN-KEYWORD,qq,🎯 Direct
  - DOMAIN-KEYWORD,alipay,🎯 Direct
  - DOMAIN-KEYWORD,taobao,🎯 Direct
  - DOMAIN-KEYWORD,bilibili,🎯 Direct
`;
  }

  yaml += `  - MATCH,🌍 Global\n`;
  return yaml;
}

// ---- API utama untuk bot ----
function convertV2rayToClash(text, opts = {}) {
  // parse opsi baris pertama (flag optional)
  // contoh: /clash --filter=HK,SG --exclude=expired --group="🚀 Proxy" --prefix="[PRO] "
  const lines = text.split('\n').map(s => s.trim()).filter(Boolean);
  const flags = {};
  // kumpulkan flags di awal baris yang dimulai --key=
  while (lines.length && lines[0].startsWith('--')) {
    const m = lines.shift().match(/^--([^=\s]+)=(.*)$/);
    if (m) flags[m[1]] = m[2].replace(/^"|"$/g, '');
    else {
      // boolean flags
      const f = lines[0].slice(2);
      flags[f] = true;
      lines.shift();
    }
  }
  const cfg = {
    filter: flags.filter || '',
    exclude: flags.exclude || '',
    protocol: flags.protocol || 'all',
    prefix: flags.prefix || '',
    suffix: flags.suffix || '',
    stripEmoji: flags['no-emoji'] ? true : (opts.stripEmoji || false),
    dedup: flags['no-dedup'] ? false : (opts.dedup !== false),
    groupName: flags.group || opts.groupName || '🚀 Proxy',
    httpPort: Number(flags.httpPort || opts.httpPort || 7890),
    socksPort: Number(flags.socksPort || opts.socksPort || 7891),
    mixedPort: Number(flags.mixedPort || opts.mixedPort || 0),
    allowLan: flags.allowLan ? true : !!opts.allowLan,
    enableIPv6: flags.enableIPv6 ? true : !!opts.enableIPv6,
    dnsEnable: flags.dnsEnable ? true : (opts.dnsEnable !== false),
    adblock: flags.adblock ? true : (opts.adblock !== false),
    chinaDirect: flags.chinaDirect ? true : (opts.chinaDirect !== false),
    loadBalance: flags.loadBalance ? true : !!opts.loadBalance,
  };

  // parse tiap baris URL
  let proxies = [];
  const errors = [];
  lines.forEach((line, i) => {
    try { proxies.push(parseLine(line)); }
    catch (e) { errors.push(`Line ${i+1}: ${e.message}`); }
  });
  if (!proxies.length) throw new Error(errors[0] || 'No valid proxies.');

  // dekorasi nama
  proxies = proxies.map(p => applyNameDecor(p, {
    prefix: cfg.prefix, suffix: cfg.suffix, stripEmoji: cfg.stripEmoji
  }));

  if (cfg.dedup) proxies = dedup(proxies);
  proxies = filterByOptions(proxies, {
    filter: cfg.filter, exclude: cfg.exclude, protocol: cfg.protocol
  });
  if (!proxies.length) throw new Error('Semua node terfilter/habis.');

  const yaml = generateClashYAML(proxies, {
    groupName: cfg.groupName,
    httpPort: cfg.httpPort,
    socksPort: cfg.socksPort,
    mixedPort: cfg.mixedPort,
    allowLan: cfg.allowLan,
    enableIPv6: cfg.enableIPv6,
    dnsEnable: cfg.dnsEnable,
    adblock: cfg.adblock,
    chinaDirect: cfg.chinaDirect,
    loadBalance: cfg.loadBalance,
  });

  return { yaml, count: proxies.length, errors };
}

// KV namespace binding
const KV_NAMESPACE = 'BOT_USERS';

// Storage implementation using Cloudflare KV
const storage = {
  // === User Profile Storage ===
  async saveUserProfile(userId, userInfo) {
    try {
      const profile = {
        id: userId,
        username: userInfo.username || '',
        firstName: userInfo.first_name || '',
        lastName: userInfo.last_name || '',
        fullName: [userInfo.first_name, userInfo.last_name].filter(Boolean).join(' ') || '',
        lastSeen: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      
      await BOT_USERS.put(`profile_${userId}`, JSON.stringify(profile));
      return profile;
    } catch (error) {
      console.error('Error saving user profile:', error);
      return null;
    }
  },

  async getUserProfile(userId) {
    try {
      const profile = await BOT_USERS.get(`profile_${userId}`, 'json');
      return profile || null;
    } catch (error) {
      console.error('Error getting user profile:', error);
      return null;
    }
  },

  async getAllUserProfiles() {
    try {
      // This is a simplified approach - in production you might want to use KV list operations
      const users = await this.getAllUsers();
      const profiles = [];
      
      for (const userId of users) {
        const profile = await this.getUserProfile(userId);
        if (profile) {
          profiles.push(profile);
        }
      }
      
      return profiles;
    } catch (error) {
      console.error('Error getting all user profiles:', error);
      return [];
    }
  },

  // === Access Tracking Storage ===
  async recordAccess(userId, username = '', userInfo = null) {
    try {
      // Save/update user profile if info provided
      if (userInfo) {
        await this.saveUserProfile(userId, userInfo);
      }

      const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
      const month = today.substring(0, 7); // YYYY-MM
      
      // Get user profile for enhanced data
      const profile = await this.getUserProfile(userId);
      const userData = {
        username: username || profile?.username || '-',
        fullName: profile?.fullName || '-',
        lastAccess: new Date().toISOString(),
        count: 1
      };
      
      // Record daily access
      const dailyKey = `access_daily_${today}`;
      const dailyData = await BOT_USERS.get(dailyKey, 'json') || {};
      if (dailyData[userId]) {
        userData.count = (dailyData[userId].count || 0) + 1;
      }
      dailyData[userId] = userData;
      await BOT_USERS.put(dailyKey, JSON.stringify(dailyData), { expirationTtl: 86400 * 32 }); // 32 days
      
      // Record monthly access
      const monthlyKey = `access_monthly_${month}`;
      const monthlyData = await BOT_USERS.get(monthlyKey, 'json') || {};
      if (monthlyData[userId]) {
        userData.count = (monthlyData[userId].count || 0) + 1;
      }
      monthlyData[userId] = userData;
      await BOT_USERS.put(monthlyKey, JSON.stringify(monthlyData), { expirationTtl: 86400 * 400 }); // ~13 months
      
      return true;
    } catch (error) {
      console.error('Error recording access:', error);
      return false;
    }
  },

  async getDailyAccess(date = null) {
    try {
      const targetDate = date || new Date().toISOString().split('T')[0];
      const dailyKey = `access_daily_${targetDate}`;
      const data = await BOT_USERS.get(dailyKey, 'json');
      return data || {};
    } catch (error) {
      console.error('Error getting daily access:', error);
      return {};
    }
  },

  async getMonthlyAccess(month = null) {
    try {
      const targetMonth = month || new Date().toISOString().substring(0, 7);
      const monthlyKey = `access_monthly_${targetMonth}`;
      const data = await BOT_USERS.get(monthlyKey, 'json');
      return data || {};
    } catch (error) {
      console.error('Error getting monthly access:', error);
      return {};
    }
  },

  async getAccessStats(days = 7) {
    try {
      const stats = [];
      const today = new Date();
      
      for (let i = 0; i < days; i++) {
        const date = new Date(today);
        date.setDate(date.getDate() - i);
        const dateStr = date.toISOString().split('T')[0];
        
        const dailyData = await this.getDailyAccess(dateStr);
        const uniqueUsers = Object.keys(dailyData).length;
        const totalInteractions = Object.values(dailyData).reduce((sum, user) => sum + (user.count || 0), 0);
        
        stats.push({
          date: dateStr,
          uniqueUsers,
          totalInteractions
        });
      }
      
      return stats.reverse(); // oldest first
    } catch (error) {
      console.error('Error getting access stats:', error);
      return [];
    }
  },

  // === Giveaway Storage ===
  async addGiveParticipant(user) {
    try {
      const key = 'give_participants';
      const list = await BOT_USERS.get(key, 'json') || [];
      const set = new Map(list.map(p => [String(p.id), p])); // dedup by id

      const name = [user.first_name, user.last_name].filter(Boolean).join(' ') || '-';
      set.set(String(user.id), {
        id: String(user.id),
        username: user.username || '-',
        name,
        joinedAt: new Date().toISOString(),
      });

      const updated = Array.from(set.values());
      await BOT_USERS.put(key, JSON.stringify(updated));
      return { added: true, total: updated.length };
    } catch (e) {
      console.error('addGiveParticipant error:', e);
      return { added: false, total: 0 };
    }
  },

  async getGiveParticipants() {
    try {
      const list = await BOT_USERS.get('give_participants', 'json');
      return Array.isArray(list) ? list : [];
    } catch (e) {
      console.error('getGiveParticipants error:', e);
      return [];
    }
  },

  async clearGiveParticipants() {
    try {
      await BOT_USERS.put('give_participants', JSON.stringify([]));
      return true;
    } catch (e) {
      console.error('clearGiveParticipants error:', e);
      return false;
    }
  },

  // === Broadcast State Storage ===
  async setBroadcastState(chatId, isActive, metadata = {}) {
    try {
      const key = `broadcast_state_${chatId}`;
      if (isActive) {
        const stateData = {
          active: true,
          startedAt: new Date().toISOString(),
          ...metadata
        };
        await BOT_USERS.put(key, JSON.stringify(stateData), { expirationTtl: 7200 }); // 2 hours max
      } else {
        await BOT_USERS.delete(key);
      }
      return true;
    } catch (error) {
      console.error('Error setting broadcast state:', error);
      return false;
    }
  },

  async getBroadcastState(chatId) {
    try {
      const key = `broadcast_state_${chatId}`;
      const state = await BOT_USERS.get(key, 'json');
      return state || null;
    } catch (error) {
      console.error('Error getting broadcast state:', error);
      return null;
    }
  },

  // === Broadcast Progress Storage ===
  async setBroadcastProgress(chatId, progress) {
    try {
      const key = `broadcast_progress_${chatId}`;
      const data = {
        ...progress,
        lastUpdated: new Date().toISOString()
      };
      await BOT_USERS.put(key, JSON.stringify(data), { expirationTtl: 3600 }); // 1 hour
      return true;
    } catch (error) {
      console.error('Error setting broadcast progress:', error);
      return false;
    }
  },

  async getBroadcastProgress(chatId) {
    try {
      const key = `broadcast_progress_${chatId}`;
      const data = await BOT_USERS.get(key, 'json');
      return data || null;
    } catch (error) {
      console.error('Error getting broadcast progress:', error);
      return null;
    }
  },

  async deleteBroadcastProgress(chatId) {
    try {
      const key = `broadcast_progress_${chatId}`;
      await BOT_USERS.delete(key);
      return true;
    } catch (error) {
      console.error('Error deleting broadcast progress:', error);
      return false;
    }
  },

  // === Chat/session helpers ===
  async setChatData(chatId, data, expirationMs = 3600000) {
    try {
      await BOT_USERS.put(`chat_${chatId}`, JSON.stringify({
        data,
        expireAt: Date.now() + expirationMs
      }), { expirationTtl: Math.floor(expirationMs / 1000) });
    } catch (error) {
      console.error('Error setting chat data:', error);
    }
  },

  async getChatData(chatId) {
    try {
      const entry = await BOT_USERS.get(`chat_${chatId}`, 'json');
      if (entry && entry.expireAt > Date.now()) return entry.data;
    } catch (error) {
      console.error('Error getting chat data:', error);
    }
    return null;
  },

  async addUser(chatId) {
    try {
      const users = await this.getAllUsers();
      if (!users.includes(chatId.toString())) {
        users.push(chatId.toString());
        await BOT_USERS.put('users', JSON.stringify(users));
        syncUsersToGitHub(users);
      }
    } catch (error) {
      console.error('Error adding user:', error);
      await BOT_USERS.put('users', JSON.stringify([chatId.toString()]));
      syncUsersToGitHub([chatId.toString()]);
    }
  },

  async removeUser(chatId) {
    try {
      const users = await this.getAllUsers();
      const updated = users.filter(u => u !== chatId.toString());
      await BOT_USERS.put('users', JSON.stringify(updated));
      console.log(`User ${chatId} dihapus dari daftar users`);
      syncUsersToGitHub(updated);
    } catch (error) {
      console.error('Error removing user:', error);
    }
  },

  async getAllUsers() {
    try {
      const users = await BOT_USERS.get('users', 'json');
      return users || [];
    } catch (error) {
      console.error('Error getting users:', error);
      return [];
    }
  }
};

// Enhanced stats command with detailed user information
async function handleStatsCommand(chatId, username, args = '') {
  try {
    // Check admin access
    const userNameNorm = String(username || '').replace('@', '').toLowerCase();
    const adminNameNorm = String(ADMIN_USERNAME || '').replace('@', '').toLowerCase();
    const isAdmin = (userNameNorm === adminNameNorm);

    if (!isAdmin) {
      await sendMessage(chatId, '⚠️ *Akses Ditolak*\n\nPerintah ini hanya untuk admin.');
      return;
    }

    const parts = args.trim().split(/\s+/).filter(Boolean);
    const command = parts[0]?.toLowerCase() || '';
    const param = parts[1] || '';

    const today = new Date().toISOString().split('T')[0];
    const currentMonth = new Date().toISOString().substring(0, 7);

    if (command === 'today') {
      // Enhanced today stats with complete user details
      const todayData = await storage.getDailyAccess(today);
      const users = Object.entries(todayData);
      const uniqueUsers = users.length;
      const totalInteractions = users.reduce((sum, [_, user]) => sum + (user.count || 0), 0);

      let message = `📊 *Statistik Hari Ini* (${today})\n\n`;
      message += `👥 Pengguna Unik: ${uniqueUsers}\n`;
      message += `💬 Total Interaksi: ${totalInteractions}\n`;
      
      if (uniqueUsers > 0) {
        message += `📈 Rata-rata: ${(totalInteractions / uniqueUsers).toFixed(1)} interaksi/user\n\n`;
        message += `📋 *Detail Pengguna Hari Ini:*\n`;
        
        // Sort by interaction count
        const sortedUsers = users.sort((a, b) => (b[1].count || 0) - (a[1].count || 0));
        
        for (const [userId, userData] of sortedUsers.slice(0, 25)) { // Limit to top 25
          const fullName = userData.fullName && userData.fullName !== '-' ? userData.fullName : '';
          const username = userData.username && userData.username !== '-' ? `@${userData.username}` : '';
          const displayName = fullName || username || 'Anonymous';
          
          const lastAccess = new Date(userData.lastAccess).toLocaleTimeString('id-ID', { 
            hour: '2-digit', 
            minute: '2-digit',
            second: '2-digit'
          });
          
          message += `👤 *${displayName}*\n`;
          message += `   📱 ID: \`${userId}\`\n`;
          if (username && fullName) message += `   🏷 Username: ${username}\n`;
          message += `   📊 Aktivitas: ${userData.count}x (${lastAccess})\n\n`;
        }
        
        if (sortedUsers.length > 25) {
          message += `... dan ${sortedUsers.length - 25} pengguna lainnya\n`;
        }
      }

      await sendMessage(chatId, message);
      return;
    }

    if (command === 'users') {
      // Complete user list with profiles
      const allUsers = await storage.getAllUsers();
      const profiles = await storage.getAllUserProfiles();
      
      let message = `👥 *Daftar Lengkap Pengguna Bot*\n\n`;
      message += `📊 Total Pengguna: ${allUsers.length}\n`;
      message += `📋 Profil Tersimpan: ${profiles.length}\n\n`;
      
      if (profiles.length > 0) {
        message += `📋 *Detail Pengguna:*\n`;
        
        // Sort by last seen (most recent first)
        const sortedProfiles = profiles.sort((a, b) => 
          new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0)
        );
        
        for (const [index, profile] of sortedProfiles.slice(0, 30).entries()) {
          const displayName = profile.fullName || (profile.username ? `@${profile.username}` : 'Anonymous');
          const lastSeen = profile.lastSeen ? 
            new Date(profile.lastSeen).toLocaleDateString('id-ID', { 
              day: '2-digit', 
              month: '2-digit',
              year: 'numeric'
            }) : 'Unknown';
            
          message += `${index + 1}. *${displayName}*\n`;
          message += `   📱 ID: \`${profile.id}\`\n`;
          if (profile.username) message += `   🏷 Username: @${profile.username}\n`;
          message += `   👁 Terakhir: ${lastSeen}\n\n`;
        }
        
        if (sortedProfiles.length > 30) {
          message += `... dan ${sortedProfiles.length - 30} pengguna lainnya\n`;
        }
      }

      await sendMessage(chatId, message);
      return;
    }

    if (command === 'week') {
      // 7 days 
      const stats = await storage.getAccessStats(7);
      let message = `📊 *Statistik 7 Hari Terakhir*\n\n`;
      
      let totalUniqueUsers = 0;
      let totalInteractions = 0;
      
      for (const stat of stats) {
        const date = new Date(stat.date).toLocaleDateString('id-ID', { 
          weekday: 'short', 
          day: '2-digit', 
          month: '2-digit' 
        });
        message += `📅 ${date}: ${stat.uniqueUsers} users, ${stat.totalInteractions} interaksi\n`;
        totalUniqueUsers += stat.uniqueUsers;
        totalInteractions += stat.totalInteractions;
      }
      
      message += `\n📈 *Total 7 Hari:*\n`;
      message += `👥 Total User Sessions: ${totalUniqueUsers}\n`;
      message += `💬 Total Interaksi: ${totalInteractions}\n`;
      message += `📊 Rata-rata Harian: ${(totalInteractions / 7).toFixed(1)} interaksi/hari`;

      await sendMessage(chatId, message);
      return;
    }

    if (command === 'month') {
      // Enhanced monthly stats with top users
      const monthlyData = await storage.getMonthlyAccess(currentMonth);
      const users = Object.entries(monthlyData);
      const uniqueUsers = users.length;
      const totalInteractions = users.reduce((sum, [_, user]) => sum + (user.count || 0), 0);

      let message = `📊 *Statistik Bulan Ini* (${currentMonth})\n\n`;
      message += `👥 Pengguna Unik: ${uniqueUsers}\n`;
      message += `💬 Total Interaksi: ${totalInteractions}\n`;
      
      if (uniqueUsers > 0) {
        message += `📈 Rata-rata: ${(totalInteractions / uniqueUsers).toFixed(1)} interaksi/user\n\n`;
        message += `🏆 *Top 15 Pengguna Aktif Bulan Ini:*\n`;
        
        // Sort by interaction count
        const sortedUsers = users.sort((a, b) => (b[1].count || 0) - (a[1].count || 0));
        
        for (let i = 0; i < Math.min(15, sortedUsers.length); i++) {
          const [userId, userData] = sortedUsers[i];
          const fullName = userData.fullName && userData.fullName !== '-' ? userData.fullName : '';
          const username = userData.username && userData.username !== '-' ? `@${userData.username}` : '';
          const displayName = fullName || username || 'Anonymous';
          
          const lastAccess = new Date(userData.lastAccess).toLocaleDateString('id-ID');
          
          message += `${i + 1}. *${displayName}*\n`;
          message += `   📱 ID: \`${userId}\`\n`;
          message += `   📊 Aktivitas: ${userData.count}x (${lastAccess})\n\n`;
        }
      }

      await sendMessage(chatId, message);
      return;
    }

    if (command === 'date' && param) {
      // Specific date stats with enhanced user info
      if (!/^\d{4}-\d{2}-\d{2}$/.test(param)) {
        await sendMessage(chatId, '❌ Format tanggal salah. Gunakan: YYYY-MM-DD\nContoh: /stats date 2024-01-15');
        return;
      }

      const dateData = await storage.getDailyAccess(param);
      const users = Object.entries(dateData);
      const uniqueUsers = users.length;
      const totalInteractions = users.reduce((sum, [_, user]) => sum + (user.count || 0), 0);

      let message = `📊 *Statistik Tanggal* ${param}\n\n`;
      
      if (uniqueUsers === 0) {
        message += `📭 Tidak ada aktivitas pada tanggal ini.`;
      } else {
        message += `👥 Pengguna Unik: ${uniqueUsers}\n`;
        message += `💬 Total Interaksi: ${totalInteractions}\n`;
        message += `📈 Rata-rata: ${(totalInteractions / uniqueUsers).toFixed(1)} interaksi/user\n\n`;
        message += `📋 *Pengguna Aktif pada ${param}:*\n`;
        
        // Sort by interaction count
        const sortedUsers = users.sort((a, b) => (b[1].count || 0) - (a[1].count || 0));
        
        for (const [userId, userData] of sortedUsers.slice(0, 20)) {
          const fullName = userData.fullName && userData.fullName !== '-' ? userData.fullName : '';
          const username = userData.username && userData.username !== '-' ? `@${userData.username}` : '';
          const displayName = fullName || username || 'Anonymous';
          
          message += `👤 *${displayName}*\n`;
          message += `   📱 ID: \`${userId}\`\n`;
          message += `   📊 Aktivitas: ${userData.count}x\n\n`;
        }
        
        if (sortedUsers.length > 20) {
          message += `... dan ${sortedUsers.length - 20} pengguna lainnya`;
        }
      }

      await sendMessage(chatId, message);
      return;
    }

    // Default: Enhanced summary stats
    const todayData = await storage.getDailyAccess(today);
    const monthlyData = await storage.getMonthlyAccess(currentMonth);
    const weekStats = await storage.getAccessStats(7);
    const totalUsers = await storage.getAllUsers();
    const profiles = await storage.getAllUserProfiles();
    
    const todayUsers = Object.keys(todayData).length;
    const todayInteractions = Object.values(todayData).reduce((sum, user) => sum + (user.count || 0), 0);
    
    const monthlyUsers = Object.keys(monthlyData).length;
    const monthlyInteractions = Object.values(monthlyData).reduce((sum, user) => sum + (user.count || 0), 0);
    
    const weekInteractions = weekStats.reduce((sum, day) => sum + day.totalInteractions, 0);

    let message = `📊 *Ringkasan Statistik Bot Enhanced*\n\n`;
    
    message += `👥 *Data Pengguna:*\n`;
    message += `📱 Total Pengguna Terdaftar: ${totalUsers.length}\n`;
    message += `👤 Profil Tersimpan: ${profiles.length}\n\n`;
    
    message += `📅 *Hari Ini (${today}):*\n`;
    message += `👥 ${todayUsers} pengguna unik\n`;
    message += `💬 ${todayInteractions} interaksi\n\n`;
    
    message += `📅 *Bulan Ini (${currentMonth}):*\n`;
    message += `👥 ${monthlyUsers} pengguna unik\n`;
    message += `💬 ${monthlyInteractions} interaksi\n\n`;
    
    message += `📅 *7 Hari Terakhir:*\n`;
    message += `💬 ${weekInteractions} total interaksi\n`;
    message += `📊 ${(weekInteractions / 7).toFixed(1)} rata-rata/hari\n\n`;
    
    message += `📋 *Command Tersedia:*\n`;
    message += `• \`/stats today\` - Detail hari ini dengan info pengguna\n`;
    message += `• \`/stats users\` - Daftar lengkap semua pengguna\n`;
    message += `• \`/stats week\` - Statistik 7 hari\n`;
    message += `• \`/stats month\` - Top pengguna bulan ini\n`;
    message += `• \`/stats date YYYY-MM-DD\` - Tanggal tertentu`;

    await sendMessage(chatId, message);

  } catch (error) {
    console.error('Error handling stats command:', error);
    await sendMessage(chatId, '❌ Terjadi kesalahan saat mengambil statistik.');
  }
}

// Function to handle /users command
async function handleUsersCommand(chatId, username, mode = 'summary') {
  try {
    // Normalisasi username & cek admin
    const userNameNorm = String(username || '').replace('@', '').toLowerCase();
    const adminNameNorm = String(ADMIN_USERNAME || '').replace('@', '').toLowerCase();
    const isAdmin = (userNameNorm === adminNameNorm);

    // Ambil & rapikan daftar users dari KV
    let users = await storage.getAllUsers();
    if (!Array.isArray(users)) users = [];
    // pastikan string, unik, terurut
    users = [...new Set(users.map(u => u != null ? u.toString() : ''))]
              .filter(Boolean)
              .sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));

    // Mode ringkas (siapa saja boleh)
    if (mode === 'summary') {
      await sendMessage(chatId, `📊 *Total Pengguna Bot:* ${users.length}`);
      return;
    }

    // Mode lain: hanya admin
    if (!isAdmin) {
      await sendMessage(chatId, '⚠️ *Akses Ditolak*\n\nPerintah ini hanya untuk admin.');
      return;
    }

    if (mode === 'ids') {
      const header = `📊 *Daftar ID Pengguna Bot* (total ${users.length}):`;
      const lines = users; // sudah string semua
      for (const chunk of chunkBySize([header, ...lines], 3800)) {
        await sendMessage(chatId, chunk.join('\n'));
      }
      return;
    }

    if (mode === 'detail') {
      const header = `📋 *Detail Pengguna* (total ${users.length}):`;
      const lines = users.map((u, i) => `${i + 1}. \`${u}\``);
      for (const chunk of chunkBySize([header, ...lines], 3800)) {
        await sendMessage(chatId, chunk.join('\n'));
      }
      return;
    }

    // Fallback
    await sendMessage(chatId, `📊 *Total Pengguna Bot:* ${users.length}`);
  } catch (error) {
    console.error('Error handling users command:', error);
    await sendMessage(chatId, '❌ Terjadi kesalahan saat mengambil daftar pengguna.');
  }
}

// Enhanced broadcast function with better state management
async function handleBroadcastCommand(chatId, username) {
  if (username !== ADMIN_USERNAME.replace('@', '')) {
    await sendMessage(chatId, '⚠️ *Akses Ditolak*\n\nMaaf, perintah /broadcast hanya dapat digunakan oleh admin bot.');
    return;
  }

  // Check if there's an active broadcast
  const currentState = await storage.getBroadcastState(chatId);
  if (currentState?.active) {
    await sendMessage(chatId, 
      `⚠️ *Broadcast sedang berjalan!*\n\n` +
      `📅 Dimulai: ${new Date(currentState.startedAt).toLocaleString('id-ID')}\n` +
      `🔄 Gunakan /cancel untuk membatalkan broadcast yang sedang berjalan.`
    );
    return;
  }

  // Set broadcast state
  await storage.setBroadcastState(chatId, true);
  await storage.setChatData(chatId, { isBroadcastMode: true });
  
  const users = await storage.getAllUsers();
  const estimatedTime = Math.ceil(users.length / 15); // More realistic estimate (15 msg/batch)
  
  const message = `📣 *Mode Broadcast Aktif*\n\n` +
    `👥 Total Pengguna: ${users.length}\n` +
    `⏰ Perkiraan waktu: ~${estimatedTime} menit\n` +
    `🔄 Kecepatan: ~15 pesan/menit\n\n` +
    `📝 *Cara Penggunaan:*\n` +
    `• Kirim pesan teks untuk broadcast text\n` +
    `• Kirim foto dengan caption untuk broadcast gambar\n` +
    `• Kirim dokumen gambar untuk broadcast media\n\n` +
    `⚠️ *PENTING:* Selama mode broadcast aktif, semua perintah lain akan diabaikan.\n` +
    `Gunakan /cancel untuk keluar dari mode broadcast.\n\n` +
    `💡 *Tips:* Pastikan pesan sudah siap sebelum mengirim untuk menghindari broadcast yang salah.\n\n` +
    `📊 *Progress real-time* akan ditampilkan selama broadcast berlangsung.`;
    
  await sendMessage(chatId, message);
}

// Enhanced broadcast process with real-time progress updates and better notifications
// =====================================================
// REPLIT BROADCAST CONFIG - GANTI DENGAN URL DAN SECRET ANDA
// =====================================================
const REPLIT_BROADCAST_URL = 'https://zerostore-api.replit.app/api/broadcast';
const BROADCAST_SECRET = 'zerostore';

// =====================================================
// FUNGSI BROADCAST VIA REPLIT (SUDAH DIMODIFIKASI)
// =====================================================
async function processBroadcast(chatId, message, photo = null) {
  const startTime = Date.now();
  
  try {
    const users = await storage.getAllUsers();

    if (users.length === 0) {
      await sendMessage(chatId, '❌ Tidak ada pengguna untuk broadcast.');
      await storage.setBroadcastState(chatId, false);
      await storage.setChatData(chatId, { isBroadcastMode: false });
      return;
    }

    // Filter out admin from broadcast list
    const userIds = users.filter(userId => userId !== chatId.toString());
    
    // Validate photo file_id if provided
    if (photo && !isValidFileId(photo)) {
      await sendMessage(chatId, '⚠️ File ID foto tidak valid. Melanjutkan dengan pesan teks saja.');
      photo = null;
    }

    const mediaType = photo ? '📸 Ya' : '📄 Tidak';
    const estimatedSeconds = Math.ceil(userIds.length * 35 / 1000);

    // Kirim notifikasi awal ke admin
    await sendMessage(chatId, 
      `🚀 *BROADCAST DIMULAI*\n\n` +
      `📊 *Detail:*\n` +
      `👥 Total Pengguna: ${userIds.length}\n` +
      `📸 Media: ${mediaType}\n` +
      `⏰ Perkiraan waktu: ~${estimatedSeconds} detik\n` +
      `📅 Waktu mulai: ${new Date().toLocaleTimeString('id-ID')}\n\n` +
      `🔄 *Mengirim ke server Replit...*`
    );

    // Siapkan payload untuk Replit
    const broadcastPayload = {
      userIds: userIds,
      message: photo 
        ? (message || '📢 *PENGUMUMAN*')
        : `📢 PENGUMUMAN\n\n${message || 'Pesan broadcast dari admin'}`,
      parseMode: 'Markdown',
      delayMs: 35
    };

    // Jika ada foto, tambahkan ke payload
    if (photo) {
      broadcastPayload.photo = photo;
    }

    // Kirim request ke Replit
    const response = await fetch(REPLIT_BROADCAST_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${BROADCAST_SECRET}`
      },
      body: JSON.stringify(broadcastPayload)
    });

    const result = await response.json();

    if (response.ok) {
      // Broadcast berhasil dikirim ke Replit
      await sendMessage(chatId,
        `✅ *BROADCAST DITERIMA SERVER*\n\n` +
        `📤 Job broadcast berhasil dikirim ke Replit.\n` +
        `👥 Total target: ${result.total || userIds.length} pengguna\n` +
        `⏱ Estimasi: ~${result.estimatedTimeSeconds || estimatedSeconds} detik\n\n` +
        `📈 *Broadcast sedang diproses di background*\n` +
        `✨ Mode broadcast dinonaktifkan otomatis\n` +
        `🔄 Bot kembali ke mode normal\n\n` +
        `💡 *Catatan:* Hasil broadcast akan dikirim setelah selesai.`
      );
    } else {
      throw new Error(result.error || 'Gagal mengirim ke server Replit');
    }

  } catch (error) {
    console.error('Error in processBroadcast:', error);
    
    const errorTime = Math.round((Date.now() - startTime) / 1000);
    
    await sendMessage(chatId, 
      `❌ *BROADCAST GAGAL*\n\n` +
      `🚨 Terjadi kesalahan:\n` +
      `📝 Error: ${error.message}\n` +
      `⏱ Waktu: ${errorTime} detik\n\n` +
      `🔧 *Kemungkinan penyebab:*\n` +
      `• Server Replit tidak aktif\n` +
      `• BROADCAST_SECRET tidak cocok\n` +
      `• URL Replit salah\n\n` +
      `💡 Pastikan server Replit berjalan dan konfigurasi benar.`
    );
  } finally {
    // Reset broadcast state
    await storage.setBroadcastState(chatId, false);
    await storage.setChatData(chatId, { isBroadcastMode: false });
    await storage.deleteBroadcastProgress(chatId);
  }
}

// Helper function to validate Telegram file_id
function isValidFileId(fileId) {
  if (!fileId || typeof fileId !== 'string') return false;
  return /^[A-Za-z0-9_-]+$/.test(fileId) && fileId.length > 10;
}

// Improved sleep function
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Cancel command - simplified since broadcast runs on Replit
async function handleCancelCommand(chatId) {
  const broadcastState = await storage.getBroadcastState(chatId);
  
  if (!broadcastState?.active) {
    await sendMessage(chatId, '🔄 Bot dalam mode normal. Tidak ada broadcast yang sedang berjalan.');
    return;
  }
  
  // Clean up broadcast state
  await storage.setBroadcastState(chatId, false);
  await storage.setChatData(chatId, { isBroadcastMode: false });
  await storage.deleteBroadcastProgress(chatId);
  
  await sendMessage(chatId, 
    `🛑 *MODE BROADCAST DIBATALKAN*\n\n` +
    `✅ Mode broadcast dinonaktifkan\n` +
    `🔄 Bot kembali ke mode normal\n\n` +
    `⚠️ *Catatan:* Jika broadcast sudah dikirim ke Replit,\n` +
    `proses akan tetap berjalan di server.`
  );
}


// Function to get date from 10 days ago
const getTenDaysAgoDate = () => {
  const date = new Date();
  date.setDate(date.getDate() - 10);
  return date.toISOString().split("T")[0];
};

// Function to handle /start command
async function handleStartCommand(chatId, username, userInfo = null) {
  const welcomeMessage = `👋 *Selamat datang ${username} di Bot Multi-Fungsi!*

🔥 *Fitur Utama:*
1️⃣ *Cek Kuota XL*
   • Kirim nomor telepon untuk cek kuota
   • Contoh: \`081234567890\`
   • Bisa cek multiple nomor dengan spasi/koma
   • Contoh: \`081234567890,082345678901\`

2️⃣ *Cek IP & Proxy*
   • Kirim IP:Port untuk cek status
   • Contoh: \`192.168.1.1:8080\`
   • Port default 443 jika tidak disebutkan

3️⃣ *Cek Bandwidth*
   • Gunakan perintah /bandwidth untuk melihat penggunaan bandwidth

📌 *Perintah Tersedia:*
• /start - Tampilkan pesan ini
• /kuota - Panduan cek kuota
• /proxy - Panduan cek proxy
• /bandwidth - Cek penggunaan bandwidth
• /donate - Informasi donasi
• /help - Bantuan lengkap

🔰 *Catatan:*
• Semua layanan gratis
• Hasil real-time & akurat
• Support 24/7

👨‍💻 *Admin:* [Hubungi Admin](t.me/kakatiri)

Silakan pilih layanan yang Anda butuhkan!`;

  await sendMessage(chatId, welcomeMessage);
  
  // Save user's chat ID and profile info
  await storage.addUser(chatId);
  if (userInfo) {
    await storage.saveUserProfile(chatId, userInfo);
  }
}

// Function to handle /donate command
async function handleDonateCommand(chatId) {
  const donateMessage = `💰 *Dukung Pengembangan Bot*

Jika Anda merasa bot ini bermanfaat, Anda dapat mendukung pengembangannya melalui donasi:

🏧 *QRIS*
Scan QR Code di bawah ini untuk donasi melalui QRIS
(Mendukung semua e-wallet dan mobile banking)

📝 *Catatan:*
• Donasi bersifat sukarela
• Semua donasi akan digunakan untuk pengembangan bot
• Screenshot bukti transfer dapat dikirimkan ke admin

🙏 Terima kasih atas dukungan Anda!`;

  await sendMessage(chatId, donateMessage);

  // Send QRIS image
  const qrisUrl = 'https://api.telegram.org/bot' + BOT_TOKEN + '/sendPhoto';
  const qrisPayload = {
    chat_id: chatId,
    photo: 'https://raw.githubusercontent.com/dit1304/Cloud/main/qris.jpeg',
    caption: '💰 *Scan QRIS di atas untuk melakukan donasi*',
    parse_mode: 'Markdown'
  };

  await fetch(qrisUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(qrisPayload)
  });
}

// Function to handle /bandwidth command
async function handleBandwidthCommand(chatId) {
  try {
    const tenDaysAgo = getTenDaysAgoDate();

    const resp = await fetch("https://api.cloudflare.com/client/v4/graphql", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${CLOUDFLARE_API_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        query: `query($zone: String!, $since: Date!) {
          viewer {
            zones(filter: { zoneTag: $zone }) {
              httpRequests1dGroups(
                limit: 30,
                orderBy: [date_DESC],
                filter: { date_geq: $since }
              ) {
                sum { bytes requests }
                dimensions { date }
              }
            }
          }
        }`,
        variables: { zone: CLOUDFLARE_ZONE_ID, since: tenDaysAgo }
      })
    });

    const result = await resp.json();
    const groups = result?.data?.viewer?.zones?.[0]?.httpRequests1dGroups;

    if (groups && groups.length > 0) {
      let usageText = "*📊 Data Pemakaian 10 Hari Terakhir:*\n\n";
      for (const day of groups.reverse()) {
        const tanggal = day.dimensions.date;
        const totalData = formatBytes(day.sum.bytes);
        const totalRequests = (day.sum.requests ?? 0).toLocaleString();

        usageText += `📅 ${tanggal}\n📦 ${totalData}\n📊 ${totalRequests} requests\n\n`;
      }
      await sendMessage(chatId, usageText);
      return;
    }

    // ❌ Kalau tetap kosong
    await sendMessage(chatId,
      "⚠️ Data pemakaian tidak tersedia.\n" +
      "👉 Kemungkinan akun Cloudflare masih Free Plan (hanya ada data singkat & sampling)."
    );

  } catch (error) {
    console.error(error);
    await sendMessage(chatId, `⚠️ Gagal mengambil data pemakaian.\n\n_Error:_ ${error.message}`);
  }
}

// Function to handle /kuota command
async function handleKuotaCommand(chatId, username) {
  const message = `👋 *Panduan Cek Kuota XL*

📱 *Cara Menggunakan:*
1. Kirim nomor telepon XL Anda
2. Format: \`081234567890\`
3. Bisa cek multiple nomor:
   • Dengan spasi: \`081234567890 082345678901\`
   • Dengan koma: \`081234567890,082345678901\`

ℹ️ *Informasi yang Ditampilkan:*
• Status Kartu
• Masa Aktif
• Kuota Tersisa
• Paket Aktif
• Detail Benefit

🔄 *Update Status:* Real-time`;

  await sendMessage(chatId, message);
}

// Function to handle /proxy command
// /proxy          -> 20 proxy acak global
// /proxy US       -> 20 proxy acak untuk US
// /proxy US 50    -> 50 proxy acak untuk US (dibatasi max 100)
async function handleProxyCommand(chatId, countryArg = '') {
  try {
    // parsing arg: "US 50" atau "50"
    const parts = (countryArg || '').trim().split(/\s+/).filter(Boolean);
    let country = '';
    let count = 30;

    if (parts.length === 1) {
      if (/^\d+$/.test(parts[0])) count = Number(parts[0]);
      else country = parts[0];
    } else if (parts.length >= 2) {
      country = parts[0];
      if (/^\d+$/.test(parts[1])) count = Number(parts[1]);
    }

    count = Math.min(Math.max(count, 1), 100); // 1..100

    const proxies = await getRandomProxies(country, count);
    if (proxies.length === 0) {
      await sendMessage(chatId, `❌ Tidak ada proxy${country ? ` untuk negara ${country}` : ''} yang tersedia saat ini.`);
      return;
    }

    // Format pesan & chunk per 4096 chars
    const header = `🌐 *${proxies.length} Proxy Random${country ? ` (${country.toUpperCase()})` : ''}:*`;
    const lines = proxies.map((p, i) =>
      `${i + 1}. \`${p.ip}:${p.port}\` | ${p.country} | ${p.isp}`
    );

    for (const chunk of chunkBySize([header, '', ...lines], 3800)) {
      await sendMessage(chatId, chunk.join('\n'));
    }
  } catch (error) {
    console.error('Error handling proxy command:', error);
    await sendMessage(chatId, '❌ Terjadi kesalahan saat mengambil daftar proxy.');
  }
}

// Helper: pecah jadi beberapa pesan agar tak lewat 4096 chars
function chunkBySize(lines, maxLen) {
  const chunks = [];
  let buf = [];
  let len = 0;
  for (const line of lines) {
    const add = line.length + 1;
    if (len + add > maxLen && buf.length) {
      chunks.push(buf);
      buf = [];
      len = 0;
    }
    buf.push(line);
    len += add;
  }
  if (buf.length) chunks.push(buf);
  return chunks;
}

// === CF API helpers
const CF_API_BASE = 'https://api.cloudflare.com/client/v4';
const CF_HEADERS = {
  'Authorization': `Bearer ${CLOUDFLARE_API_TOKEN}`,
  'Content-Type': 'application/json'
};

async function cfGet(path) {
  const r = await fetch(`${CF_API_BASE}${path}`, { headers: CF_HEADERS });
  const j = await r.json();
  if (!j.success) throw new Error(j.errors?.[0]?.message || JSON.stringify(j));
  return j.result;
}

async function cfPost(path, body) {
  const r = await fetch(`${CF_API_BASE}${path}`, {
    method: 'POST', headers: CF_HEADERS, body: JSON.stringify(body)
  });
  const j = await r.json();
  if (!j.success) throw new Error(j.errors?.[0]?.message || JSON.stringify(j));
  return j.result;
}

async function cfDelete(path) {
  const r = await fetch(`${CF_API_BASE}${path}`, { method: 'DELETE', headers: CF_HEADERS });
  const j = await r.json();
  if (!j.success) throw new Error(j.errors?.[0]?.message || JSON.stringify(j));
  return j.result;
}

// List semua worker scripts di account
async function cfListScripts() {
  return cfGet(`/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts`);
}

// List routes (custom domain → worker) untuk 1 zone
async function cfListRoutes() {
  return cfGet(`/zones/${CLOUDFLARE_ZONE_ID}/workers/routes`);
}

// Tambah route: pattern "sub.domain.com/*" → script worker
async function cfAddRoute(pattern, scriptName) {
  return cfPost(`/zones/${CLOUDFLARE_ZONE_ID}/workers/routes`, {
    pattern, script: scriptName
  });
}

// Hapus route berdasar routeId
async function cfDeleteRoute(routeId) {
  return cfDelete(`/zones/${CLOUDFLARE_ZONE_ID}/workers/routes/${routeId}`);
}

// === Helper untuk header info akun ===
function buildInfoHeader(d) {
  const quota = 'Unlimited';
  const limitIp = 'Unlimited';
  const aktif = 'LifeTime';
  const ownerbot = '@kakatiri';

  const country = d.country_name || d.country || d.countryName || '';
  const city = d.city || '';
  const location = [city, country].filter(Boolean).join(', ') || (d.flag || '-');
  const isp = d.isp || '-';

  return (
    `*===========================*\n` +
    `*Limit Quota* : ${quota}\n` +
    `*Limit IP*    : ${limitIp}\n` +
    `*Aktif*       : ${aktif}\n` +
    `*ISP*         : ${isp}\n` +
    `*Location*    : ${location}\n` +
    `*Owner Bot*   : ${ownerbot}\n` +
    `*===========================*\n\n`
  );
}

// helper clean users
async function cleanUsersKV() {
  try {
    const users = await BOT_USERS.get('users', 'json') || [];
    const before = users.length;
    const unique = [...new Set(users.map(u => u.toString()))];
    const after = unique.length;

    await BOT_USERS.put('users', JSON.stringify(unique));

    return { before, after, removed: before - after };
  } catch (err) {
    console.error("❌ Error cleaning users:", err);
    return { before: 0, after: 0, removed: 0 };
  }
}

// Function to get random proxies
// Cache 5 menit di KV agar tidak fetch terus
const PROXY_CACHE_TTL = 300; // detik
const PROXY_LIST_URL = 'https://raw.githubusercontent.com/dit1304/proxie/main/proxyList.txt';

async function getRandomProxies(country = '', count = 30) {
  try {
    const key = `proxy_cache_${(country || 'ALL').toUpperCase()}`;
    // coba ambil dari KV
    const cached = await BOT_USERS.get(key, 'json');
    let proxyList;

    if (cached && Array.isArray(cached) && cached.length) {
      proxyList = cached;
    } else {
      // fetch dengan timeout
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 8000);
      const resp = await fetch(PROXY_LIST_URL, { signal: controller.signal });
      clearTimeout(t);

      if (!resp.ok) throw new Error(`Fetch proxy list gagal: ${resp.status}`);
      const text = await resp.text();

      proxyList = text
        .split('\n')
        .map(l => l.trim())
        .filter(Boolean)
        .map(line => {
          // Skema: ip,port,country,isp...
          const parts = line.split(',');
          const [ip, port, countryCode, ...ispParts] = parts;
          const isp = (ispParts.join(' ') || '').trim();
          return { ip, port, country: (countryCode || '').toUpperCase(), isp };
        })
        .filter(p => isValidIP(p.ip) && /^\d+$/.test(p.port) && p.port >= 1 && p.port <= 65535);

      // simpan cache ALL (biar filter negara dilakukan di memori)
      await BOT_USERS.put('proxy_cache_ALL', JSON.stringify(proxyList), { expirationTtl: PROXY_CACHE_TTL });
    }

    // Gunakan cache ALL jika cache negara kosong
    if (!cached) {
      const all = await BOT_USERS.get('proxy_cache_ALL', 'json');
      proxyList = Array.isArray(all) ? all : [];
    }

    // Filter negara: gunakan equality, bukan includes (hindari 'US' match 'RUS')
    let filtered = proxyList;
    if (country) {
      const cc = country.toUpperCase();
      filtered = proxyList.filter(p => p.country === cc || p.country === ` ${cc}`); // toleransi spasi nyasar
    }

    if (!filtered.length) return [];

    // Ambil acak unik
    const pool = filtered.slice();
    const out = [];
    const max = Math.min(count, pool.length);
    for (let i = 0; i < max; i++) {
      const idx = Math.floor(Math.random() * pool.length);
      out.push(pool[idx]);
      pool.splice(idx, 1);
    }

    // Cache khusus negara (opsional)
    const cacheKey = `proxy_cache_${(country || 'ALL').toUpperCase()}`;
    await BOT_USERS.put(cacheKey, JSON.stringify(filtered), { expirationTtl: PROXY_CACHE_TTL });

    return out;
  } catch (error) {
    console.error('Error fetching proxy list:', error);
    return [];
  }
}

// /ikut — user mendaftar giveaway
async function handleIkutGiveaway(chatId, from) {
  const res = await storage.addGiveParticipant(from);
  if (res.added) {
    await sendMessage(
      chatId,
      `✅ *Terdaftar!*\n` +
      `Nama: ${[from.first_name, from.last_name].filter(Boolean).join(' ') || '-'}\n` +
      `Username: ${from.username ? '@' + from.username : '-'}\n` +
      `ID: \`${from.id}\`\n\n` +
      `Total peserta saat ini: *${res.total}*`
    );
  } else {
    await sendMessage(chatId, '⚠️ Gagal mendaftar. Coba lagi nanti.');
  }
}

// /listgive — tampilkan daftar peserta
async function handleListGive(chatId) {
  const list = await storage.getGiveParticipants();
  if (!list.length) {
    await sendMessage(chatId, '📭 Belum ada peserta yang mendaftar.');
    return;
  }

  const header = `🎟️ *Daftar Peserta Giveaway* (${list.length} peserta)\n`;
  const lines = list.map((p, i) =>
    `${i + 1}. ${p.name} ${p.username && p.username !== '-' ? `(@${p.username})` : ''} — \`${p.id}\``
  );

  // kirim terchunk biar aman limit
  for (const chunk of chunkBySize([header, '', ...lines], 3800)) {
    await sendMessage(chatId, chunk.join('\n'));
  }
}

// /undi [N] — admin saja
async function handleUndi(chatId, username, countArg) {
  if (username !== ADMIN_USERNAME.replace('@', '')) {
    await sendMessage(chatId, '⚠️ *Akses Ditolak*\n\nPerintah /undi hanya untuk admin.');
    return;
  }

  const list = await storage.getGiveParticipants();
  if (!list.length) {
    await sendMessage(chatId, '📭 Belum ada peserta untuk diundi.');
    return;
  }

  let n = 1;
  if (countArg && /^\d+$/.test(countArg)) n = Math.max(1, Math.min(50, Number(countArg))); // batasi 1..50

  const winners = pickWinners(list, n);
  const title = n === 1 ? '🎉 *Pemenang*' : '🎉 *Pemenang*';
  const body = winners.map((w, i) =>
    `${i + 1}. ${w.name} ${w.username && w.username !== '-' ? `(@${w.username})` : ''} — \`${w.id}\``
  ).join('\n');

  await sendMessage(
    chatId,
    `${title}\n\n${body}\n\n📌 Selamat!`
  );
}

// Function to validate IP address
function isValidIP(ip) {
  const regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){2}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return regex.test(ip);
}

// CEK KUOTA – khusus schema data_sp + hasil (seperti contohmu)
async function cekKuota(number) {
  const baseURL = 'http://jav.zerostore.org:9000'; // ganti ke https kalau sudah siap
  const url = `${baseURL}/cek_kuota?msisdn=${encodeURIComponent(number)}`;

  try {
    // timeout 10s biar worker nggak ngegantung
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);

    const resp = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Cloudflare Worker)',
        'Accept': 'application/json'
      },
      redirect: 'follow'
    });
    clearTimeout(timer);

    if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);

    // server kadang kirim text → parse aman
    const raw = await resp.text();
    let data;
    try { data = JSON.parse(raw); } catch { data = { raw }; }

    const sp = data?.data?.data_sp;
    const msisdn = data?.data?.msisdn || number;

    if (!sp) {
      // fallback kalau struktur nggak sesuai harapan
      return `❌ Gagal mengambil data untuk ${number}.\n🔍 Respon: ${raw.slice(0, 800)}`;
    }

    // ====== HEADER INFO PELANGGAN ======
    let out = '';
    out += `📱 *Info Pelanggan:*\n`;
    out += `🔢 Nomor: ${msisdn}\n`;
    out += `💳 Tipe Kartu: ${sp.prefix?.value ?? '-'}\n`;
    out += `📶 Status 4G: ${sp.status_4g?.value ?? '-'}\n`;
    out += `📋 Dukcapil: ${sp.dukcapil?.value ?? '-'}\n`;

    // VoLTE (kalau ada di status_volte)
    if (sp.status_volte?.success && typeof sp.status_volte.value === 'object') {
      const v = sp.status_volte.value;
      const yes = '✅', no = '❌';
      out += `📶 VoLTE: Device ${v.device ? yes : no} • Area ${v.area ? yes : no} • SIM ${v.simcard ? yes : no}\n`;
    }

    out += `⌛ Umur Kartu: ${sp.active_card?.value ?? '-'}\n`;
    out += `🗓 Masa Aktif: ${sp.active_period?.value ?? '-'}\n`;
    out += `⏳ Tenggang: ${sp.grace_period?.value ?? '-'}\n`;

    // ====== PAKET AKTIF ======
    out += `\n📦 *Info Paket Aktif:*\n`;
    const daftar = Array.isArray(sp.quotas?.value) ? sp.quotas.value : [];
    if (!daftar.length) {
      out += `Tidak ada paket aktif.\n`;
    } else {
      for (const p of daftar) {
        const nama = (p?.name || '').trim() || '(Tidak diketahui)';
        const exp  = (p?.date_end || '').trim() || '(Tidak diketahui)';
        const det  = Array.isArray(p?.detail_quota) ? p.detail_quota : [];

        // skip benar-benar kosong
        const punyaIsi = det.some(d => d && (d.name || d.type || d.total_text || d.remaining_text));
        if (!nama && !punyaIsi) continue;

        out += `⚡️ Paket: ${nama}\n`;
        out += `📅 Expired: ${exp}\n`;
        for (const d of det) {
          if (!d) continue;
          out += `🎁 Benefit: ${d.name ?? '-'}\n`;
          out += `📊 Tipe: ${d.type ?? '-'}\n`;
          out += `💡 Kuota: ${d.total_text ?? '-'}\n`;
          out += `🌲 Sisa: ${d.remaining_text ?? '-'}\n`;
        }
        out += `------------------------------\n`;
      }
    }

    // ====== CATATAN (RINGKAS) dari field HTML "hasil" ======
    if (data?.data?.hasil) {
      // bersihkan HTML → text
      let h = String(data.data.hasil)
        .replace(/<br\s*\/?>/gi, '\n')
        .replace(/<[^>]+>/g, '')
        .trim();

      // deteksi pesan rate-limit
      const rateMsg = /batas maksimal pengecekan/i.test(h);

      // ambil baris kuota/expiry/pemisah (kalau ada), supaya tidak duplikat header
      const ringkasLines = h.split('\n')
        .map(s => s.trim())
        .filter(s => /^🎁/.test(s) || /^🍂/.test(s) || /^=+$/.test(s));

      const ringkas = ringkasLines.join('\n').trim();

      if (rateMsg) {
        out += `\n⚠️ *Batas pengecekan tercapai.*\nSilakan coba lagi nanti.`;
      }
      if (ringkas) {
        out += `\n📄 *Catatan (ringkas):*\n${ringkas}`;
      }
    }

    out += `\n\n📌 Panduan penggunaan: /start`;
    return out;

  } catch (err) {
    const reason = err.name === 'AbortError' ? 'Timeout: origin lambat' : err.message;
    return `❌ Terjadi kesalahan saat cek kuota ${number}: ${reason}`;
  }
}

// broadcast
async function sendBroadcastText(chatId, text) {
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
  const payload = {
    chat_id: chatId,
    text: String(text || '').trim(),   // no WATERMARK
    // no parse_mode => underscore aman
    disable_web_page_preview: true
  };
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || body.ok === false) {
    const err = new Error(body.description || `HTTP ${res.status}`);
    err.status = res.status;
    err.retry_after = body?.parameters?.retry_after;
    throw err;
  }
  return body;
}

// Function to process messages
async function processMessage(message, chatId) {
  const parts = message.split(':');
  const ip = parts[0].trim();
  const port = parts[1] ? parts[1].trim() : '443';

  if (!isValidIP(ip)) {
    return 'Error: IP address is invalid. Please provide a valid IP.';
  }

  if (isNaN(port) || port < 1 || port > 65535) {
    return 'Error: Port must be a number between 1 and 65535.';
  }

  const apiUrl = `${API_URL}${ip}:${port}`;

  try {
    const response = await fetch(apiUrl);
    if (!response.ok) {
      return 'Error fetching data from API: Please provide valid IP';
    }
    const data = await response.json();
    await storage.setChatData(chatId, data);

    return formatApiResponse(data);
  } catch (error) {
    return 'Error fetching data from API: ' + error.message;
  }
}

// Function to format API response
function formatApiResponse(data) {
  let responseMessage = `*IP Address Information:*
\`\`\`
-🌐 Proxy Host: ${data.proxyHost}
- 🚪Proxy Port: ${data.proxyPort}
- 📡Origin IP: ${data.OriginIp}
- 🏢ISP: ${data.isp}
- 📍Country: ${data.isp} ${data.flag}
- City: ${data.city}
- ASN: ${data.asn}
- Proxy Status: ${data.proxyStatus}
- Delay: ${data.delay}
\`\`\`
`;

  if (data.proxyStatus.includes('✅ ALIVE ✅')) {
    responseMessage += `*IP yang kamu berikan berstatus proxy ACTIVE kamu bisa membuat akun menggunakan proxy tersebut, Pilihlah protocol mana yang ingin kamu buat :*`;
    return {
      text: responseMessage,
      replyMarkup: {
        inline_keyboard: [
          [
            { text: "VLESS", callback_data: "info_1" },
            { text: "TROJAN", callback_data: "info_2" }
          ]
        ]
      }
    };
  }
  return responseMessage;
}

// Function to handle /help command
async function handleHelpCommand(chatId) {
  const helpMessage = `🔍 *Panduan Lengkap Bot*

*Perintah Utama:*
• /start - Memulai bot dan melihat pesan selamat datang
• /kuota - Panduan untuk cek kuota XL
• /proxy - Mendapatkan daftar proxy random
• /proxy [kode negara] - Mendapatkan proxy dari negara tertentu
• /bandwidth - Cek penggunaan bandwidth 10 hari terakhir
• /donate - Informasi cara berdonasi
• /help - Menampilkan pesan bantuan ini

*Cara Menggunakan:*

1️⃣ *Cek Kuota XL*
   • Kirim nomor telepon XL: \`081234567890\`
   • Cek multiple nomor: \`081234567890,082345678901\`

2️⃣ *Cek Proxy*
   • Kirim IP dan port: \`192.168.1.1:8080\`
   • Jika tanpa port, default 443: \`192.168.1.1\`

3️⃣ *Random Proxy*
   • Gunakan: /proxy untuk proxy random
   • Gunakan: /proxy US untuk proxy dari Amerika

📌 *Catatan Penting:*
• Bot ini gratis untuk digunakan
• Semua data diproses secara real-time
• Untuk bantuan lebih lanjut, hubungi admin

👨‍💻 *Admin:* [Hubungi Admin](t.me/kakatiri)`;

  await sendMessage(chatId, helpMessage);
}

// Function to handle callback queries
async function handleCallbackQuery(callbackQuery) {
  const chatId = callbackQuery.message.chat.id;
  const callbackData = callbackQuery.data;
  
  const storedData = await storage.getChatData(chatId);
  if (!storedData) {
    return sendMessage(chatId, "Data not found. Please send a message with IP and Port first.");
  }
  
  const data = storedData;
  
  if (callbackData === "info_1" || callbackData === "info_2") {
    const protocol = callbackData === "info_1" ? "VLESS" : "TROJAN";
    const encodedISP = encodeURIComponent(data.isp);
    const server = protocol === "VLESS" ? servervless : servertrojan;
    
    let responseText = `[===========${protocol}===========]
${data.isp} ${data.flag}
${data.proxyHost}:${data.proxyPort}
[===========${protocol}===========]

*${protocol} TLS*
\`\`\`
${protocol.toLowerCase()}://${passuid}@${server}:443?encryption=none&security=tls&sni=${server}&fp=randomized&type=ws&host=${server}&path=%2F${protocol.toLowerCase()}%3D${data.proxyHost}%3D${data.proxyPort}#${encodedISP}%20${data.flag}
\`\`\`
*${protocol} NTLS*
\`\`\`
${protocol.toLowerCase()}://${passuid}@${server}:80?path=%2F${protocol.toLowerCase()}%3D${data.proxyHost}%3D${data.proxyPort}&security=none&encryption=none&host=${server}&fp=randomized&type=ws&sni=${server}#${encodedISP}%20${data.flag}
\`\`\`
*CLASH ${protocol}*
\`\`\`
proxies:
- name: ${data.isp} ${data.flag}
  server: ${server}
  port: 443
  type: ${protocol.toLowerCase()}
  ${protocol === "VLESS" ? "uuid" : "password"}: ${passuid}
  ${protocol === "VLESS" ? "cipher: auto\n  " : ""}skip-cert-verify: true
  network: ws
  servername: ${server}
  ws-opts:
    path: /${protocol.toLowerCase()}=${data.proxyHost}=${data.proxyPort}
    headers:
      Host: ${server}
  udp: true
\`\`\`
`;

    await sendMessage(chatId, {
      text: "*Apakah Anda ingin menggunakan wildcard?*",
      replyMarkup: {
        inline_keyboard: [
          [
            { text: "GUNAKAN WILDCARD", callback_data: `use_bug_${protocol.toLowerCase()}` },
            { text: "JANGAN GUNAKAN", callback_data: `dont_use_bug_${protocol.toLowerCase()}` }
          ]
        ]
      }
    });
  } else if (callbackData.startsWith("use_bug_")) {
    const protocol = callbackData === "use_bug_vless" ? "vless" : "trojan";
    const bugOptions = [
      { text: "ava.game.naver.com", value: "ava" },
      { text: "df.game.naver.com", value: "df" },
      { text: "quiz.vidio.com", value: "quiz" },
      { text: "quiz.int.vidio.com", value: "quiz_int" },
      { text: "img.email1.vidio.com", value: "img1" },
      { text: "img.email2.vidio.com", value: "img2" },
      { text: "img.email3.vidio.com", value: "img3" },
      { text: "graph.instagram.com", value: "graph" },
      { text: "investors.spotify.com", value: "investors" },
      { text: "cache.netflix.com", value: "cache" },
      { text: "creativeservices.netflix.com", value: "creative" },
      { text: "support.zoom.us", value: "support" },
      { text: "zaintest.vuclip.com", value: "zaintest" },
      { text: "live.iflix.com", value: "live" },
      { text: "io.ruangguru.com", value: "ruangguru" },
      { text: "data.mt", value: "data" },
      { text: "www.udemy.com", value: "udemy" },
      { text: "beta.zoom.us", value: "beta" },
      { text: "bakrie.ac.id", value: "bakrie" },
      { text: "untar.ac.id", value: "untar" },
      { text: "investor.fb.com", value: "fb" },
      { text: "chat.sociomile.com", value: "socio" },
      { text: "cdn.who.int", value: "cdn"},
      { text: "cdn.opensignal.com", value: "cdn2"},
      { text: "grabacademyportal.grab.com", value: "grab"},
      { text: "upload.iflix.com", value: "uploadiflix"},
      { text: "api24-normal-alisg.tiktokv.com", value: "tiktok"},
      { text: "teaching.udemy.com", value: "teach"},
      { text: "collection.linefriends.com", value: "collection"},
      { text: "speedtest.net", value: "speedtest"},
      { text: "app.midtrans.com", value: "midtrans"}
    ];

    await sendMessage(chatId, {
      text: `*Pilih salah satu wildcard untuk* *${protocol.toUpperCase()}:*`,
      replyMarkup: {
        inline_keyboard: bugOptions.map(option => [
          { text: option.text, callback_data: `${protocol}_${option.value}` }
        ])
      }
    });
  } else if (callbackData.startsWith("dont_use_bug_")) {
  let responseText;
  const protocol = callbackData === "dont_use_bug_vless" ? "VLESS" : "TROJAN";
  const encodedISP = encodeURIComponent(data.isp);
    
  const header = buildInfoHeader(data);

  if (protocol === "VLESS") {
    const text = `${header}[===========VLESS===========]
${data.isp} ${data.flag}
${data.proxyHost}:${data.proxyPort}
[===========VLESS===========]

*VLESS TLS*
\`\`\`
vless://${passuid}@${servervless}:443?encryption=none&security=tls&sni=${servervless}&fp=randomized&type=ws&host=${servervless}&path=%2Fvless%3D${data.proxyHost}%3D${data.proxyPort}#${encodedISP}%20${data.flag}
\`\`\`
*VLESS NTLS*
\`\`\`
vless://${passuid}@${servervless}:80?path=%2Fvless%3D${data.proxyHost}%3D${data.proxyPort}&security=none&encryption=none&host=${servervless}&fp=randomized&type=ws&sni=${servervless}#${encodedISP}%20${data.flag}
\`\`\`
*CLASH VLESS*
\`\`\`
proxies:
- name: ${data.isp || '-'} ${data.flag || ''}
  server: ${servervless}
  port: 443
  type: vless
  uuid: ${passuid}
  cipher: auto
  tls: true
  skip-cert-verify: true
  network: ws
  servername: ${servervless}
  ws-opts:
    path: /vless=${data.proxyHost}=${data.proxyPort}
    headers:
      Host: ${servervless}
  udp: true
\`\`\`
`;
    await sendMessage(chatId, text);
  } else {
    const text = `${header}[===========TROJAN===========]
${data.isp} ${data.flag}
${data.proxyHost}:${data.proxyPort}
[===========TROJAN===========]

*TROJAN TLS*
\`\`\`
trojan://${passuid}@${servertrojan}:443?encryption=none&security=tls&sni=${servertrojan}&fp=randomized&type=ws&host=${servertrojan}&path=%2Ftrojan%3D${data.proxyHost}%3D${data.proxyPort}#${encodedISP}%20${data.flag}
\`\`\`
*TROJAN NTLS*
\`\`\`
trojan://${passuid}@${servertrojan}:80?path=%2Ftrojan%3D${data.proxyHost}%3D${data.proxyPort}&security=none&encryption=none&host=${servertrojan}&fp=randomized&type=ws&sni=${servertrojan}#${encodedISP}%20${data.flag}
\`\`\`
*CLASH TROJAN*
\`\`\`
proxies:
- name: ${data.isp || '-'} ${data.flag || ''}
  server: ${servertrojan}
  port: 443
  type: trojan
  password: ${passuid}
  skip-cert-verify: true
  network: ws
  sni: ${servertrojan}
  ws-opts:
    path: /trojan=${data.proxyHost}=${data.proxyPort}
    headers:
      Host: ${servertrojan}
  udp: true
\`\`\`
`;
    await sendMessage(chatId, text);
  }
  
  } else if (callbackData.startsWith("vless_") || callbackData.startsWith("trojan_")) {
    const protocol = callbackData.startsWith("vless") ? "VLESS" : "TROJAN";
    const bugKey = callbackData.split("_")[1];

    const hostMapping = {
      ava: "ava.game.naver.com",
      df: "df.game.naver.com",
      quiz: "quiz.vidio.com",
      quiz_int: "quiz.int.vidio.com",
      img1: "img.email1.vidio.com",
      img2: "img.email2.vidio.com",
      img3: "img.email3.vidio.com",
      graph: "graph.instagram.com",
      investors: "investors.spotify.com",
      cache: "cache.netflix.com",
      creative: "creativeservices.netflix.com",
      support: "support.zoom.us",
      zaintest: "zaintest.vuclip.com",
      live: "live.iflix.com",
      ruangguru: "io.ruangguru.com",
      data: "data.mt",
      udemy: "www.udemy.com",
      beta: "beta.zoom.us",
      bakrie: "bakrie.ac.id",
      untar: "untar.ac.id",
      fb: "investor.fb.com",
      socio: "chat.sociomile.com",
      cdn: "cdn.who.int",
      cdn2: "cdn.opensignal.com",
      grab: "grabacademyportal.grab.com",
      uploadiflix: "upload.iflix.com",
      tiktok: "api24-normal-alisg.tiktokv.com",
      teach: "teaching.udemy.com",
      collection: "collection.linefriends.com",
      speedtest: "speedtest.net",
      midtrans: "app.midtrans.com"
    };

    const selectedHost = hostMapping[bugKey];
    if (!selectedHost) {
      return sendMessage(chatId, "❌ Bug tidak dikenal.");
    }

    const encodedISP = encodeURIComponent(data.isp);
    const serverWithHost = `${selectedHost}.${serverwildcard}`;
    const path = `%2F${protocol.toLowerCase()}%3D${data.proxyHost}%3D${data.proxyPort}`;

    let result = '';
    
    const header= buildInfoHeader(data);

    if (protocol === "VLESS") {
      result = header + `*VLESS TLS*
\`\`\`
vless://${passuid}@${selectedHost}:443?encryption=none&security=tls&sni=${serverWithHost}&fp=randomized&type=ws&host=${serverWithHost}&path=${path}#${encodedISP}%20${data.flag}
\`\`\`
*VLESS NTLS*
\`\`\`
vless://${passuid}@${selectedHost}:80?path=${path}&security=none&encryption=none&host=${serverWithHost}&fp=randomized&type=ws&sni=${serverWithHost}#${encodedISP}%20${data.flag}
\`\`\`
*CLASH VLESS*
\`\`\`
proxies:
- name: ${data.isp} ${data.flag}
  server: ${selectedHost}
  port: 443
  type: vless
  uuid: ${passuid}
  cipher: auto
  tls: true
  skip-cert-verify: true
  network: ws
  servername: ${serverWithHost}
  ws-opts:
    path: /vless=${data.proxyHost}=${data.proxyPort}
    headers:
      Host: ${serverWithHost}
  udp: true
\`\`\`
`;
    } else {
      result = header + `*TROJAN TLS*
\`\`\`
trojan://${passuid}@${selectedHost}:443?encryption=none&security=tls&sni=${serverWithHost}&fp=randomized&type=ws&host=${serverWithHost}&path=${path}#${encodedISP}%20${data.flag}
\`\`\`
*TROJAN NTLS*
\`\`\`
trojan://${passuid}@${selectedHost}:80?path=${path}&security=none&encryption=none&host=${serverWithHost}&fp=randomized&type=ws&sni=${serverWithHost}#${encodedISP}%20${data.flag}
\`\`\`
*CLASH TROJAN*
\`\`\`
proxies:
- name: ${data.isp} ${data.flag}
  server: ${selectedHost}
  port: 443
  type: trojan
  password: ${passuid}
  skip-cert-verify: true
  network: ws
  sni: ${serverWithHost}
  ws-opts:
    path: /trojan=${data.proxyHost}=${data.proxyPort}
    headers:
      Host: ${serverWithHost}
  udp: true
\`\`\`
`;
    }

    await sendMessage(chatId, result);
  }
}

// Improved sendMessage function with better error handling
async function sendMessage(chatId, response, inlineKeyboard = null) {
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;

  let messageText = '';
  if (typeof response === 'string') messageText = response + WATERMARK;
  else if (response.text) messageText = response.text + WATERMARK;
  else messageText = JSON.stringify(response) + WATERMARK;

  const payload = {
    chat_id: chatId,
    text: messageText,
    parse_mode: 'Markdown',
    reply_markup: response.replyMarkup
      ? response.replyMarkup
      : (inlineKeyboard ? { inline_keyboard: inlineKeyboard } : undefined)
  };

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  // Better error handling for sendMessage
  const body = await res.json().catch(() => ({}));

  if (!res.ok || body.ok === false) {
    const desc = body.description || `HTTP ${res.status}`;
    const err = new Error(desc);
    err.status = res.status;
    err.retry_after = body.parameters?.retry_after;
    
    // Log error for debugging
    console.error(`sendMessage error for chat ${chatId}: ${desc}`);
    throw err;
  }

  return body;
}

// Improved sendPhoto function with better validation and error handling
async function sendPhoto(chatId, fileIdOrUrl, caption = '', replyMarkup = undefined) {
  // Validate photo parameter
  if (!fileIdOrUrl || typeof fileIdOrUrl !== 'string') {
    throw new Error('Invalid photo file ID or URL');
  }

  const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendPhoto`;
  const payload = {
    chat_id: chatId,
    photo: fileIdOrUrl,
    caption: (caption + WATERMARK).substring(0, 1024), // Telegram caption limit
    parse_mode: 'Markdown',
    reply_markup: replyMarkup
  };

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  const body = await res.json().catch(() => ({}));

  if (!res.ok || body.ok === false) {
    const desc = body.description || `HTTP ${res.status}`;
    const err = new Error(desc);
    err.status = res.status;
    err.retry_after = body?.parameters?.retry_after;
    
    console.error(`sendPhoto error for chat ${chatId}: ${desc}`);
    
    // If photo sending fails, try to fallback to text message
    if (desc.includes('photo') || desc.includes('media') || desc.includes('file')) {
      console.log(`Photo send failed, falling back to text for chat ${chatId}`);
      return await sendMessage(chatId, caption || '📢 Media tidak dapat dikirim');
    }
    
    throw err;
  }

  return body;
}

// === Helper: normalisasi objek "message" dari berbagai tipe update ===
function extractMessage(update) {
  return (
    update.message ||
    update.edited_message ||
    update.channel_post ||
    update.edited_channel_post ||
    null
  );
}

// Shuffle (Fisher–Yates) dengan crypto supaya fair
function shuffleArray(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const r = new Uint32Array(1);
    crypto.getRandomValues(r);
    const j = r[0] % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// Ambil N pemenang unik secara acak
function pickWinners(participants, n = 1) {
  const shuffled = shuffleArray(participants);
  return shuffled.slice(0, Math.min(n, shuffled.length));
}

// Format bytes → B/KB/MB/GB/TB/PB (basis 1024). 
// Contoh: 957.34 GB, 1.12 TB, dll.
function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0, val = bytes;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i++;
  }
  // 2 desimal normal, tapi kalau angkanya besar pakai 1 desimal biar rapi
  const fixed = val >= 100 ? val.toFixed(1) : val.toFixed(2);
  return `${fixed} ${units[i]}`;
}

// ---- Idempotency: hindari proses update yang sama berulang (retry Telegram) ----
async function isDuplicateUpdate(updateId) {
  if (typeof updateId === 'undefined' || updateId === null) return false;
  const key = `upd_${updateId}`;
  const seen = await BOT_USERS.get(key);
  if (seen) return true; // sudah diproses
  await BOT_USERS.put(key, '1', { expirationTtl: 600 }); // tandai 10 menit
  return false;
}

// === Handler perintah /clash (versi kirim file YAML) ===
async function handleClashCommand(chatId, rawText) {
  try {
    const { yaml, count, errors } = convertV2rayToClash(rawText, {
      groupName: '🚀 Proxy',
      dedup: true,
      stripEmoji: false,
      loadBalance: false,
    });

    // --- kirim info singkat ---
    await sendMessage(chatId, `✅ Berhasil konversi *${count}* node ke Clash YAML.`);

    // --- kirim sebagai file document ---
    const fileBlob = new Blob([yaml], { type: 'text/yaml' });
    const file = new File([fileBlob], 'clash.yaml', { type: 'text/yaml' });

    await sendDocument(chatId, file, '📎 Ini hasil konversi Clash.yaml');

    // kalau ada error parsing sebagian baris
    if (errors.length) {
      const errTxt = errors.slice(0, 10).join('\n');
      await sendMessage(chatId, `⚠️ Beberapa baris dilewati:\n${errTxt}`);
    }

  } catch (e) {
    await sendMessage(chatId, `❌ Gagal konversi: ${e.message}`);
  }
}

// Main request handler
async function handleRequest(request, event) {
  const { pathname } = new URL(request.url);

  if (pathname !== '/webhook') {
    return new Response('Not Found', { status: 404 });
  }
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const update = await request.json();

  // Idempotency: jika Telegram retry update yang sama, abaikan
  if (await isDuplicateUpdate(update.update_id)) {
    return new Response('OK', { status: 200 });
  }

  // 1) Prioritaskan callback_query (inline keyboard)
  if (update.callback_query) {
    await handleCallbackQuery(update.callback_query);
    return new Response('OK', { status: 200 });
  }

  // 2) Ambil objek pesan dari berbagai tipe update
  const msg = extractMessage(update);
  if (!msg || !msg.chat) {
    // Bukan tipe yang ditangani; jangan crash
    console.log('Unsupported update shape:', JSON.stringify(update));
    return new Response('OK', { status: 200 });
  }

  const chatId = msg.chat.id;
  const text = (msg.text ?? msg.caption ?? '').trim();
  const username = (msg.from?.username || msg.from?.first_name || 'Pengguna');

  // Enhanced access tracking with user profile info
  await storage.recordAccess(chatId, msg.from?.username || '', msg.from);

  // Simpan ID user agar fitur lain tetap berfungsi
  await storage.addUser(chatId);

  // 3) Enhanced broadcast mode detection with better state management
  const broadcastState = await storage.getBroadcastState(chatId);
  const chatData = await storage.getChatData(chatId);
  
  if ((broadcastState?.active) || chatData?.isBroadcastMode) {
    if (text === '/cancel') {
      await handleCancelCommand(chatId);
    } else {
      // Enhanced photo handling for broadcast
      let photoId = null;
      if (msg.photo && Array.isArray(msg.photo) && msg.photo.length > 0) {
        // Get the largest photo size for better quality
        photoId = msg.photo[msg.photo.length - 1].file_id;
        console.log(`Broadcast photo detected: ${photoId}`);
      } else if (msg.document && msg.document.mime_type?.startsWith('image/')) {
        // Handle document images
        photoId = msg.document.file_id;
        console.log(`Broadcast document image detected: ${photoId}`);
      }
      // Jalankan broadcast di background agar webhook cepat balas OK
      if (event && typeof event.waitUntil === 'function') {
        event.waitUntil((async () => {
          try {
            await processBroadcast(chatId, text, photoId);
          } catch (err) {
            console.error('Background broadcast failed:', err);
          }
        })());
      } else {
        // Fallback jika event tidak tersedia (mis. testing)
        await processBroadcast(chatId, text, photoId);
      }
}
    return new Response('OK', { status: 200 });
  }

// === Handlers Admin: /routes & /route ===
// /routes                → tampilkan semua route di zone saat ini
// /routes scripts        → tampilkan daftar worker script
// /route add {pattern} {scriptName}
// /route del {routeId}

// ----- /routes scripts -----
async function handleRoutesScriptsCommand(chatId, username) {
  // optional debug
  console.log('DEBUG: masuk /routes scripts handler oleh', username);

  try {
    const url = `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts`;
    const resp = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json'
      }
    });

    if (!resp.ok) {
      const txt = await resp.text().catch(()=> '');
      throw new Error(`HTTP ${resp.status} ${resp.statusText} ${txt}`);
    }

    const json = await resp.json();
    const items = Array.isArray(json?.result) ? json.result : [];

    if (!items.length) {
      await sendMessage(chatId, 'ℹ️ Tidak ada Worker script ditemukan di account ini.');
      return;
    }

    // helper untuk ambil nama yang tersedia
    const getName = s =>
      s?.name || s?.id || s?.tag || s?.script || s?.display_name || '(no-name)';

    // tampilkan maksimal 50 agar tidak melewati limit pesan
    const lines = items.slice(0, 50).map((s, i) => {
      const name = getName(s);
      const last = s?.modified_on || s?.created_on || s?.uploaded_on || '';
      return `${i + 1}. ${name}${last ? ` — ${new Date(last).toISOString().slice(0,10)}` : ''}`;
    });

    await sendMessage(chatId, `🧩 *Worker Scripts* (${items.length})\n${lines.join('\n')}`);
  } catch (e) {
    console.error('handleRoutesScriptsCommand error:', e);
    await sendMessage(chatId, `❌ Gagal memuat worker scripts.\nError: ${e.message}`);
  }
}

async function handleRouteCommand(chatId, fromUsername, args = '') {
  const isAdmin = (String(fromUsername || '').replace('@','') === String(ADMIN_USERNAME||'').replace('@',''));
  if (!isAdmin) {
    await sendMessage(chatId, '⚠️ *Akses Ditolak*\n\nPerintah ini hanya untuk admin.');
    return;
  }

  const [sub, ...rest] = args.trim().split(/\s+/);
  const subcmd = (sub || '').toLowerCase();

  if (subcmd === 'add') {
    // /route add {pattern} {scriptName}
    const pattern = rest[0];
    const scriptName = rest.slice(1).join(' ');
    if (!pattern || !scriptName) {
      await sendMessage(chatId, '❌ Format:\n`/route add sub.domain.com/* script_name`');
      return;
    }
    try {
      const res = await cfAddRoute(pattern, scriptName);
      await sendMessage(chatId, `✅ *Route ditambahkan*\n• id: \`${res.id}\`\n• pattern: \`${res.pattern}\`\n• script: \`${res.script}\``);
    } catch (e) {
      await sendMessage(chatId, `❌ Gagal menambah route.\nError: ${e.message || e}`);
    }
    return;
  }

  if (subcmd === 'del' || subcmd === 'delete' || subcmd === 'rm') {
    // /route del {routeId}
    const routeId = rest[0];
    if (!routeId) {
      await sendMessage(chatId, '❌ Format:\n`/route del ROUTE_ID` (lihat `\n/routes` untuk dapat ID).');
      return;
    }
    try {
      await cfDeleteRoute(routeId);
      await sendMessage(chatId, `🗑️ *Route dihapus* (id: \`${routeId}\`).`);
    } catch (e) {
      await sendMessage(chatId, `❌ Gagal menghapus route.\nError: ${e.message || e}`);
    }
    return;
  }

  // Help
  await sendMessage(
    chatId,
    '🛠️ *Route Manager*\n' +
    '• `/routes` — list routes\n' +
    '• `/routes scripts` — list worker scripts\n' +
    '• `/route add sub.domain.com/* script_name` — tambah route\n' +
    '• `/route del ROUTE_ID` — hapus route'
  );
}

// === /ping: cek latensi bot ke Telegram API ===
async function handlePingCommand(chatId) {
  const t0 = Date.now();
  let status = '❌ Gagal';
  try {
    const res = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getMe`);
    status = res.ok ? '✅ OK' : `❌ ${res.status}`;
  } catch (e) {
    status = `❌ ${e.message}`;
  }
  const ms = Date.now() - t0;

  // Ambil waktu lokal Jakarta (ganti "Asia/Jakarta" sesuai kebutuhan)
  const localTime = new Date().toLocaleString('id-ID', {
    timeZone: 'Asia/Jakarta',
    hour12: false
  });

  const msg =
    `🏓 *PONG!*\n` +
    `• ᠌ℤ𝔼ℝ𝕆 Server: *${ms} ms* (${status})\n` +
    `• Waktu server: ${localTime} (WIB)`;

  await sendMessage(chatId, msg);
}

  // === 4) Routing perintah ===
  const fromUsername = msg.from?.username || '';
  const isAdmin = fromUsername === ADMIN_USERNAME.replace('@', '');

  if (text === '/start') {
    await handleStartCommand(chatId, username, msg.from);
    
  } else if (text === '/ping') {
  await handlePingCommand(chatId);

  } else if (text === '/ikut') {
    await handleIkutGiveaway(chatId, msg.from);

  } else if (text === '/listgive') {
    await handleListGive(chatId);

  } else if (text.startsWith('/undi')) {
    if (!isAdmin) {
      await sendMessage(chatId, '⚠️ *Akses Ditolak*\n\nPerintah /undi hanya untuk admin.');
      return;
    }
    // /undi atau /undi 3
    const parts = text.split(/\s+/);
    const countArg = parts[1]; // bisa undefined
    await handleUndi(chatId, fromUsername, countArg);

  } else if (text === '/resetgive') {
    if (!isAdmin) {
      await sendMessage(chatId, '⚠️ *Akses Ditolak*\n\nPerintah /resetgive hanya untuk admin.');
      return;
    }
    const ok = await storage.clearGiveParticipants();
    await sendMessage(
      chatId,
      ok ? '🧹 Daftar peserta giveaway sudah dikosongkan.'
         : '⚠️ Gagal mengosongkan daftar.'
    );

  } else if (text === '/bandwidth') {
    await handleBandwidthCommand(chatId);
  
  } else if (text === '/route') {
  await sendMessage(chatId, 
`🛠️ *Route Manager*
• /routes — list routes
• /routes scripts — list worker scripts
• /route add sub.domain.com/* script_name — tambah route
• /route del ROUTE_ID — hapus route`);
} else if (text === '/routes') {
  await handleRoutesListCommand(chatId, username);
} else if (text === '/routes scripts') {
  await handleRoutesScriptsCommand(chatId, username);
} else if (text.startsWith('/route add')) {
  await handleRouteAddCommand(chatId, text, username);
} else if (text.startsWith('/route del')) {
  await handleRouteDeleteCommand(chatId, text, username);

  } else if (text === '/kuota') {
    await handleKuotaCommand(chatId, username);

  } else if (text === '/donate') {
    await handleDonateCommand(chatId);

  } else if (text === '/help') {
    await handleHelpCommand(chatId);

  } else if (text === '/broadcast') {
    await handleBroadcastCommand(chatId, username);

  } else if (text?.startsWith('/users')) {
    const arg = text.split(/\s+/)[1]?.toLowerCase() || ''; // '' | 'id' | 'ids' | 'detail'
    let mode = 'summary';
    if (arg === 'id' || arg === 'ids') mode = 'ids';
    else if (arg === 'detail') mode = 'detail';
    await handleUsersCommand(chatId, fromUsername, mode);

  } else if (text?.startsWith('/stats')) {
    const args = text.slice('/stats'.length).trim();
    await handleStatsCommand(chatId, fromUsername, args);

  } else if (text === '/cleanusers') {
    if (!isAdmin) {
      await sendMessage(chatId, '⚠️ *Akses Ditolak*\n\nPerintah /cleanusers hanya untuk admin.');
      return;
    }
    const result = await cleanUsersKV();
    await sendMessage(
      chatId,
      `🧹 *Clean Users*\n` +
      `Sebelum: ${result.before}\n` +
      `Sesudah: ${result.after}\n` +
      `Duplikat dihapus: ${result.removed}`
    );

  } else if (text === '/cancel') {
    await handleCancelCommand(chatId);
    
  } else if (text?.startsWith('/clash')) {
  // ambil seluruh teks setelah /clash (termasuk baris-baris URL)
  const payload = text.slice('/clash'.length).trim();
  if (!payload) {
    await sendMessage(chatId,
`📥 Kirim daftar URL V2ray setelah perintah.

/clash
vmess://...
vless://...
trojan://...
ss://...`
    );
  } else {
    await handleClashCommand(chatId, payload);
  }
    
  } else if (text?.startsWith('/proxy')) {
    const args = text.slice('/proxy'.length).trim(); // ambil seluruh argumen setelah /proxy
    await handleProxyCommand(chatId, args);          // biar "ID 50" kebaca
    
  } else if (text && (text.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(text))) {
    // Input IP:Port → pakai logic cek proxy kamu yang sudah ada
    const responseMessage = await processMessage(text, chatId);
    await sendMessage(chatId, responseMessage);
    
  } else if (text) {
    // Treat sebagai daftar nomor XL (dipakai di handler kuota kamu)
    const numbers = text.split(/[\s,]+/).filter(num => /^\d+$/.test(num));
    if (numbers.length > 0) {
      const greeting = `👋 Halo ${username}!\n\n`;
      await sendMessage(chatId, greeting);
      for (const number of numbers) {
        const quotaInfo = await cekKuota(number);
        await sendMessage(chatId, '```\n' + quotaInfo + '\n```', [
          [{ text: '🎯 Dor Paket XL', url: `https://t.me/kakatiri` }]
        ]);
      }
    } else {
      await sendMessage(
        chatId,
        '❌ Format tidak valid.\n\n' +
        'Untuk cek kuota: Kirim nomor telepon\n' +
        'Untuk cek proxy: Kirim IP:Port\n\n' +
        'Gunakan /help untuk bantuan.'
      );
    }
  }

  return new Response('OK', { status: 200 });
}

// Add event listener for fetch events
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request, event));
});