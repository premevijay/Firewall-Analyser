import { useState, useCallback, useRef, useEffect, useMemo } from "react";

// ═══════════════════════════════════════════
// IP UTILITIES
// ═══════════════════════════════════════════

function ipToInt(ip) {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const x of parts) {
    const v = parseInt(x, 10);
    if (isNaN(v) || v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

function parseCIDR(cidr) {
  const [ip, pre] = cidr.split("/");
  const base = ipToInt(ip);
  if (base === null) return null;
  const bits = pre === undefined ? 32 : parseInt(pre, 10);
  if (isNaN(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (base & mask) >>> 0, mask, bits };
}

function ipInCIDR(ipStr, cidrStr) {
  const ip = ipToInt(ipStr.split("/")[0]);
  if (ip === null) return false;
  const c = parseCIDR(cidrStr);
  if (!c) return false;
  return (ip & c.mask) >>> 0 === c.base;
}

function cidrsOverlap(a, b) {
  const ca = parseCIDR(a);
  const cb = parseCIDR(b);
  if (!ca || !cb) return false;
  const m = ca.bits < cb.bits ? ca.mask : cb.mask;
  return ((ca.base & m) >>> 0) === ((cb.base & m) >>> 0);
}

function addrMatchesDecomm(ruleAddr, decommAddr) {
  if (!ruleAddr || !decommAddr) return false;
  const rH = ruleAddr.includes("/");
  const dH = decommAddr.includes("/");
  if (!rH && !dH) return ruleAddr.trim() === decommAddr.trim();
  if (rH && !dH) return ipInCIDR(decommAddr, ruleAddr);
  if (!rH && dH) return ipInCIDR(ruleAddr, decommAddr);
  return cidrsOverlap(ruleAddr, decommAddr);
}

function looksLikeIP(s) {
  return /^[\d./]+$/.test(s.trim());
}

// ═══════════════════════════════════════════
// OBJECT / GROUP RESOLUTION
// ═══════════════════════════════════════════

function buildStores(rawObjects, rawGroups) {
  const objStore = {};
  for (const o of rawObjects) {
    const n = o.name.trim().toLowerCase();
    if (!objStore[n]) objStore[n] = [];
    const v = o.value.trim();
    if (v) objStore[n].push(v); // preserve original casing for IP/subnet values
  }

  const grpStore = {};
  for (const g of rawGroups) {
    const n = g.name.trim().toLowerCase();
    if (!grpStore[n]) grpStore[n] = [];
    for (const m of g.members) {
      const mv = m.trim();
      if (!mv) continue;
      // Preserve original casing: IPs/subnets stay as-is, names go lowercase
      grpStore[n].push(looksLikeIP(mv) ? mv : mv.toLowerCase());
    }
  }
  return { objStore, grpStore };
}

function resolveAddr(name, objStore, grpStore, visited = new Set()) {
  const trimmed = name.trim();
  if (!trimmed) return [];

  // 1. Raw IP or subnet — return immediately, no lookup needed
  if (looksLikeIP(trimmed)) return [trimmed];

  const key = trimmed.toLowerCase();

  // Cycle guard
  if (visited.has(key)) return [];
  visited.add(key);

  // 2. Named object — resolve each of its values (values can themselves be IPs, subnets, or other names)
  if (objStore[key]) {
    const results = [];
    for (const v of objStore[key]) {
      results.push(...resolveAddr(v, objStore, grpStore, new Set(visited)));
    }
    return [...new Set(results)];
  }

  // 3. Named group — members can be: object names, other group names, or raw IPs/subnets
  if (grpStore[key]) {
    const results = [];
    for (const m of grpStore[key]) {
      results.push(...resolveAddr(m, objStore, grpStore, new Set(visited)));
    }
    return [...new Set(results)];
  }

  // 4. Unknown name — return as-is so the caller can still show it
  return [trimmed];
}

function resolveField(field, objStore, grpStore) {
  if (!field || field === "any" || field === "*") return { addrs: [], isAny: true };
  const tokens = field.split(/[;,]/).map(t => t.trim()).filter(Boolean);
  const addrs = [];
  for (const t of tokens) addrs.push(...resolveAddr(t, objStore, grpStore));
  return { addrs: [...new Set(addrs)], isAny: false };
}

// ═══════════════════════════════════════════
// PARSERS
// ═══════════════════════════════════════════

function parseCSVGeneric(text) {
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map(h => h.trim().toLowerCase().replace(/[\s-]+/g, "_"));
  return lines.slice(1).map((line, idx) => {
    const vals = line.split(",").map(v => v.trim());
    const obj = { _rowIndex: idx + 2 };
    headers.forEach((h, i) => { obj[h] = vals[i] || ""; });
    return obj;
  });
}

function parseRulesCSV(text) {
  return parseCSVGeneric(text);
}

function parseObjectsCSV(text) {
  const rows = parseCSVGeneric(text);
  return rows.map(r => ({
    name: r.name || r.object_name || "",
    value: r.value || r.ip || r.address || r.ip_netmask || "",
  })).filter(r => r.name && r.value);
}

function parseGroupsCSV(text) {
  const rows = parseCSVGeneric(text);
  const map = {};
  for (const r of rows) {
    const name = (r.group_name || r.name || r.group || "").trim();
    if (!name) continue;
    if (!map[name]) map[name] = [];
    const mc = r.member || r.members || r.value || "";
    mc.split(/[;,]/).map(m => m.trim()).filter(Boolean).forEach(m => map[name].push(m));
  }
  return Object.entries(map).map(([name, members]) => ({ name, members }));
}

function parseObjectText(text) {
  const objects = [];
  const groups = [];
  const lines = text.split(/\r?\n/).filter(l => l.trim() && !l.trim().startsWith("#"));
  for (const line of lines) {
    const parts = line.trim().split(/[\s=:]+/);
    if (parts.length < 2) continue;
    const name = parts[0].trim();
    const rest = parts.slice(1).join(" ").trim();
    const members = rest.split(/[;,\s]+/).map(m => m.trim()).filter(Boolean);
    if (members.length === 1 && looksLikeIP(members[0])) {
      objects.push({ name, value: members[0] });
    } else if (members.length > 1) {
      groups.push({ name, members });
    } else if (members.length === 1) {
      objects.push({ name, value: members[0] });
    }
  }
  return { objects, groups };
}

function parseDecommIPs(text) {
  return [...new Set(text.split(/[\n,;\s]+/).map(ip => ip.trim()).filter(ip => ip.length > 3))];
}

// ═══════════════════════════════════════════
// SAMPLE TEMPLATES
// ═══════════════════════════════════════════

const TEMPLATE_RULES = `Name,Source,Destination,Source Port,Destination Port,Action
allow-web-traffic,OBJ-WEB-SERVER,10.0.0.0/8,any,443,allow
block-telnet,192.168.1.0/24,any,any,23,deny
permit-db-access,GRP-APP-SERVERS,OBJ-DB-SERVER,any,5432,allow
deny-legacy-host,OBJ-OLD-HOST,0.0.0.0/0,any,any,deny
allow-monitoring,10.30.0.0/24,GRP-MONITORED,any,161,allow`;

const TEMPLATE_OBJECTS = `name,value
OBJ-WEB-SERVER,10.10.1.5
OBJ-DB-SERVER,10.10.2.10
OBJ-OLD-HOST,192.168.50.100
OBJ-BACKUP-SRV,10.20.0.50
OBJ-MGMT-HOST,172.16.1.1`;

const TEMPLATE_GROUPS = `group_name,member
GRP-APP-SERVERS,OBJ-WEB-SERVER
GRP-APP-SERVERS,OBJ-DB-SERVER
GRP-APP-SERVERS,10.10.5.50
GRP-MONITORED,OBJ-WEB-SERVER
GRP-MONITORED,192.168.10.0/24
GRP-ALL-SERVERS,GRP-APP-SERVERS
GRP-ALL-SERVERS,OBJ-MGMT-HOST
GRP-ALL-SERVERS,172.16.0.1`;

const TEMPLATE_DECOMM = `10.10.10.5
10.10.10.6
192.168.50.0/24
172.16.1.100`;

// ═══════════════════════════════════════════
// COPY MODAL — shown instead of download
// ═══════════════════════════════════════════

function CopyModal({ title, content, onClose }) {
  const [copied, setCopied] = useState(false);
  if (!content) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(content).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", zIndex: 300, display: "flex", alignItems: "center", justifyContent: "center", padding: 24, backdropFilter: "blur(4px)" }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{ background: "#1c2128", border: "1px solid rgba(255,255,255,0.14)", borderRadius: 12, padding: 28, maxWidth: 680, width: "100%", maxHeight: "80vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 64px rgba(0,0,0,0.6)" }}
      >
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div>
            <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, letterSpacing: 3, color: "#f59e0b", textTransform: "uppercase", marginBottom: 4 }}>
              Sample Format
            </div>
            <div style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 700, fontSize: 16, color: "#e6edf3" }}>
              {title}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ background: "#262c36", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, color: "#8b949e", cursor: "pointer", padding: "6px 10px", fontSize: 14 }}
          >
            ✕
          </button>
        </div>

        {/* Instruction */}
        <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, color: "#6e7681", marginBottom: 12 }}>
          Copy the content below and paste into a new file, or use it as a reference for your own data.
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflowY: "auto", background: "#0d1117", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8, padding: 16, marginBottom: 16 }}>
          <pre style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, color: "#e6edf3", lineHeight: 1.7, margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {content}
          </pre>
        </div>

        {/* Actions */}
        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <button
            onClick={onClose}
            style={{ background: "#262c36", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, color: "#8b949e", cursor: "pointer", padding: "9px 18px", fontFamily: "'IBM Plex Mono', monospace", fontSize: 11 }}
          >
            Close
          </button>
          <button
            onClick={handleCopy}
            style={{
              background: copied ? "rgba(52,211,153,0.15)" : "rgba(245,158,11,0.12)",
              border: `1px solid ${copied ? "rgba(52,211,153,0.4)" : "rgba(245,158,11,0.35)"}`,
              borderRadius: 6, color: copied ? "#34d399" : "#f59e0b",
              cursor: "pointer", padding: "9px 20px",
              fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, fontWeight: 600,
              transition: "all 0.2s", letterSpacing: 0.5
            }}
          >
            {copied ? "✓ Copied!" : "Copy to Clipboard"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════
// ANALYSIS ENGINE
// ═══════════════════════════════════════════

function analyzeRules(rules, decommIPs, objStore, grpStore) {
  const flagged = [];
  for (const rule of rules) {
    const rawSrc = rule.source || rule.src || rule.source_address || "";
    const rawDst = rule.destination || rule.dst || rule.dest || rule.destination_address || "";
    const srcRes = resolveField(rawSrc, objStore, grpStore);
    const dstRes = resolveField(rawDst, objStore, grpStore);
    const srcHits = [];
    const dstHits = [];
    if (!srcRes.isAny) {
      for (const addr of srcRes.addrs) {
        for (const d of decommIPs) {
          if (addrMatchesDecomm(addr, d) && !srcHits.includes(addr)) srcHits.push(addr);
        }
      }
    }
    if (!dstRes.isAny) {
      for (const addr of dstRes.addrs) {
        for (const d of decommIPs) {
          if (addrMatchesDecomm(addr, d) && !dstHits.includes(addr)) dstHits.push(addr);
        }
      }
    }
    if (srcHits.length > 0 || dstHits.length > 0) {
      const matchType = srcHits.length > 0 && dstHits.length > 0 ? "both"
        : srcHits.length > 0 ? "source" : "destination";
      flagged.push({
        ...rule,
        _rawSrc: rawSrc,
        _rawDst: rawDst,
        _resolvedSrc: srcRes.addrs,
        _resolvedDst: dstRes.addrs,
        _srcHits: srcHits,
        _dstHits: dstHits,
        _srcMatch: srcHits.length > 0,
        _dstMatch: dstHits.length > 0,
        _matchType: matchType,
        _isObject: !looksLikeIP(rawSrc.split(/[;,]/)[0]) || !looksLikeIP(rawDst.split(/[;,]/)[0]),
      });
    }
  }
  return flagged;
}

// ═══════════════════════════════════════════
// SAMPLE DATA
// ═══════════════════════════════════════════

const SAMPLE_RULES = `Name,Source,Destination,Source Port,Destination Port,Action
allow-web-prod,OBJ-OLD-WEB,NET-PROD,any,443,allow
block-legacy,192.168.1.100,GRP-DECOMM-SERVERS,any,22,deny
allow-db-conn,GRP-APP-SERVERS,OBJ-OLD-DB,any,5432,allow
permit-mgmt,192.168.50.10,10.0.0.1,any,8080,allow
deny-old-srv,OBJ-DECOMM-HOST,0.0.0.0/0,any,any,deny
allow-backup,172.16.5.5,GRP-BACKUP-TARGETS,any,9000,allow
clean-rule-1,10.50.0.1,10.60.0.1,any,22,deny
clean-rule-2,172.31.0.5,10.70.0.0/24,any,3306,allow
allow-nested-grp,GRP-ALL-LEGACY,10.80.0.0/24,any,443,allow
permit-direct-ip,10.10.10.5,10.20.0.0/16,any,80,allow`;

const SAMPLE_OBJECTS = `name,value
OBJ-OLD-WEB,10.10.10.5
OBJ-OLD-DB,10.10.10.9
OBJ-DECOMM-HOST,10.10.10.7
OBJ-BACKUP-SRV1,192.168.50.13
OBJ-BACKUP-SRV2,192.168.50.14
OBJ-APP-SRV1,10.20.1.5
OBJ-APP-SRV2,10.20.1.6
OBJ-LEGACY-A,10.10.10.6
OBJ-LEGACY-B,192.168.50.10`;

const SAMPLE_GROUPS = `group_name,member
GRP-DECOMM-SERVERS,OBJ-OLD-WEB
GRP-DECOMM-SERVERS,OBJ-OLD-DB
GRP-DECOMM-SERVERS,OBJ-DECOMM-HOST
GRP-DECOMM-SERVERS,10.10.10.8
GRP-BACKUP-TARGETS,OBJ-BACKUP-SRV1
GRP-BACKUP-TARGETS,OBJ-BACKUP-SRV2
GRP-BACKUP-TARGETS,192.168.50.15/32
GRP-APP-SERVERS,OBJ-APP-SRV1
GRP-APP-SERVERS,OBJ-APP-SRV2
GRP-LEGACY-HOSTS,OBJ-LEGACY-A
GRP-LEGACY-HOSTS,OBJ-LEGACY-B
GRP-LEGACY-HOSTS,192.168.50.12
GRP-ALL-LEGACY,GRP-LEGACY-HOSTS
GRP-ALL-LEGACY,GRP-DECOMM-SERVERS`;

const SAMPLE_DECOMM = `10.10.10.5
10.10.10.6
10.10.10.7
10.10.10.8
10.10.10.9
192.168.50.10
192.168.50.11
192.168.50.12
192.168.50.13
192.168.50.14`;

// ═══════════════════════════════════════════
// VIRTUAL TABLE
// ═══════════════════════════════════════════

const ROW_H = 60;
const BUFFER = 6;

function VirtualTable({ rows, onRowClick }) {
  const ref = useRef(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerH, setContainerH] = useState(500);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setContainerH(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const totalH = rows.length * ROW_H;
  const startIdx = Math.max(0, Math.floor(scrollTop / ROW_H) - BUFFER);
  const visibleCount = Math.ceil(containerH / ROW_H) + BUFFER * 2;
  const endIdx = Math.min(rows.length, startIdx + visibleCount);
  const slice = rows.slice(startIdx, endIdx);
  const offsetY = startIdx * ROW_H;

  return (
    <div
      ref={ref}
      style={{ height: Math.min(540, rows.length * ROW_H + 1), overflowY: "auto", position: "relative" }}
      onScroll={e => setScrollTop(e.currentTarget.scrollTop)}
    >
      <div style={{ height: totalH, position: "relative" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", position: "absolute", top: offsetY, tableLayout: "fixed" }}>
          <colgroup>
            <col style={{ width: "17%" }} />
            <col style={{ width: "19%" }} />
            <col style={{ width: "19%" }} />
            <col style={{ width: "8%" }} />
            <col style={{ width: "8%" }} />
            <col style={{ width: "9%" }} />
            <col style={{ width: "9%" }} />
            <col style={{ width: "11%" }} />
          </colgroup>
          <tbody>
            {slice.map((rule, i) => {
              const act = (rule.action || "").toLowerCase();
              const isAllow = act === "allow" || act === "permit";
              return (
                <tr
                  key={startIdx + i}
                  onClick={() => onRowClick(rule)}
                  style={{ borderBottom: "1px solid rgba(255,255,255,0.06)", height: ROW_H, cursor: "pointer", transition: "background 0.12s" }}
                  onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.03)"}
                  onMouseLeave={e => e.currentTarget.style.background = ""}
                >
                  <td style={tdBase}>
                    <span style={{ color: "#e6edf3", fontWeight: 600, display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12 }}>
                      {rule.name || rule.rule_name || `Row ${rule._rowIndex}`}
                    </span>
                  </td>
                  <td style={tdBase}>
                    <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                      <span style={rule._srcMatch ? hitStyle : normStyle}>{rule._rawSrc || "—"}</span>
                      {rule._srcMatch && rule._rawSrc !== rule._srcHits[0] && (
                        <span style={resolvedStyle}>↳ {rule._srcHits.join(", ")}</span>
                      )}
                    </div>
                  </td>
                  <td style={tdBase}>
                    <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                      <span style={rule._dstMatch ? hitStyle : normStyle}>{rule._rawDst || "—"}</span>
                      {rule._dstMatch && rule._rawDst !== rule._dstHits[0] && (
                        <span style={resolvedStyle}>↳ {rule._dstHits.join(", ")}</span>
                      )}
                    </div>
                  </td>
                  <td style={{ ...tdBase, textAlign: "center" }}>
                    <span style={{ color: "#8b949e", fontSize: 11 }}>{rule.source_port || rule.src_port || "any"}</span>
                  </td>
                  <td style={{ ...tdBase, textAlign: "center" }}>
                    <span style={{ color: "#8b949e", fontSize: 11 }}>{rule.destination_port || rule.dst_port || "any"}</span>
                  </td>
                  <td style={{ ...tdBase, textAlign: "center" }}>
                    <Chip variant={isAllow ? "allow" : "deny"}>{rule.action || "—"}</Chip>
                  </td>
                  <td style={{ ...tdBase, textAlign: "center" }}>
                    <Chip variant={rule._matchType}>{rule._matchType}</Chip>
                  </td>
                  <td style={{ ...tdBase, textAlign: "center" }}>
                    {rule._isObject && <Chip variant="obj">obj/grp</Chip>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const tdBase = { padding: "0 14px", fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: "#8b949e", verticalAlign: "middle", overflow: "hidden" };
const hitStyle = { background: "rgba(251,146,60,0.12)", color: "#fb923c", borderRadius: 3, padding: "2px 6px", fontSize: 11, display: "inline-block", border: "1px solid rgba(251,146,60,0.2)" };
const normStyle = { color: "#8b949e" };
const resolvedStyle = { color: "#f59e0b", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", opacity: 0.85 };

const chipMap = {
  allow:       { bg: "rgba(52,211,153,0.1)",  color: "#34d399", border: "rgba(52,211,153,0.25)" },
  deny:        { bg: "rgba(248,113,113,0.1)", color: "#f87171", border: "rgba(248,113,113,0.25)" },
  source:      { bg: "rgba(251,146,60,0.1)",  color: "#fb923c", border: "rgba(251,146,60,0.25)" },
  destination: { bg: "rgba(96,165,250,0.1)",  color: "#60a5fa", border: "rgba(96,165,250,0.25)" },
  both:        { bg: "rgba(192,132,252,0.1)", color: "#c084fc", border: "rgba(192,132,252,0.25)" },
  obj:         { bg: "rgba(250,204,21,0.1)",  color: "#facc15", border: "rgba(250,204,21,0.25)" },
};

function Chip({ variant, children }) {
  const s = chipMap[variant] || chipMap.deny;
  return (
    <span style={{
      display: "inline-block", fontSize: 9, fontFamily: "'IBM Plex Mono', monospace",
      fontWeight: 600, letterSpacing: 0.8, textTransform: "uppercase",
      padding: "3px 7px", borderRadius: 3,
      background: s.bg, color: s.color, border: `1px solid ${s.border}`, whiteSpace: "nowrap"
    }}>
      {children}
    </span>
  );
}

// ═══════════════════════════════════════════
// MODAL
// ═══════════════════════════════════════════

function Modal({ rule, onClose }) {
  if (!rule) return null;
  return (
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 200, display: "flex", alignItems: "center", justifyContent: "center", padding: 24, backdropFilter: "blur(4px)" }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{ background: "#1c2128", border: "1px solid rgba(255,255,255,0.14)", borderRadius: 12, padding: 32, maxWidth: 600, width: "100%", maxHeight: "82vh", overflowY: "auto", boxShadow: "0 24px 64px rgba(0,0,0,0.5)" }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24 }}>
          <div>
            <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 3, color: "#f59e0b", textTransform: "uppercase", marginBottom: 6 }}>
              Rule Detail
            </div>
            <h3 style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 700, fontSize: 20, color: "#e6edf3" }}>
              {rule.name || rule.rule_name || `Row ${rule._rowIndex}`}
            </h3>
          </div>
          <button
            onClick={onClose}
            style={{ background: "#262c36", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, color: "#8b949e", cursor: "pointer", padding: "6px 10px", fontSize: 14 }}
          >
            ✕
          </button>
        </div>
        <div style={{ display: "grid", gap: 12 }}>
          <ModalField label="Source (raw)" value={rule._rawSrc} variant={rule._srcMatch ? "warn" : "normal"} />
          {rule._resolvedSrc.length > 0 && rule._rawSrc !== rule._resolvedSrc[0] && (
            <ModalField label="Source resolved to" value={rule._resolvedSrc.join(", ")} variant="muted" />
          )}
          {rule._srcHits.length > 0 && (
            <ModalField label="⚠ Decommissioned matches in source" value={rule._srcHits.join(", ")} variant="danger" />
          )}
          <div style={{ borderTop: "1px solid rgba(255,255,255,0.07)", margin: "4px 0" }} />
          <ModalField label="Destination (raw)" value={rule._rawDst} variant={rule._dstMatch ? "warn" : "normal"} />
          {rule._resolvedDst.length > 0 && rule._rawDst !== rule._resolvedDst[0] && (
            <ModalField label="Destination resolved to" value={rule._resolvedDst.join(", ")} variant="muted" />
          )}
          {rule._dstHits.length > 0 && (
            <ModalField label="⚠ Decommissioned matches in destination" value={rule._dstHits.join(", ")} variant="danger" />
          )}
          <div style={{ borderTop: "1px solid rgba(255,255,255,0.07)", margin: "4px 0" }} />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
            <ModalField label="Action" value={rule.action || "—"} variant="normal" />
            <ModalField label="Src Port" value={rule.source_port || rule.src_port || "any"} variant="normal" />
            <ModalField label="Dst Port" value={rule.destination_port || rule.dst_port || "any"} variant="normal" />
          </div>
          <ModalField label="Match type" value={rule._matchType + (rule._isObject ? " (via object/group)" : "")} variant="normal" />
        </div>
      </div>
    </div>
  );
}

function ModalField({ label, value, variant }) {
  const colors = { normal: "#e6edf3", warn: "#fb923c", danger: "#f87171", muted: "#8b949e" };
  return (
    <div>
      <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, color: "#484f58", textTransform: "uppercase", letterSpacing: 2, marginBottom: 5 }}>
        {label}
      </div>
      <div style={{
        fontFamily: "'IBM Plex Mono', monospace", fontSize: 12,
        color: colors[variant] || colors.normal,
        background: "#161b22", borderRadius: 6, padding: "9px 13px",
        wordBreak: "break-all", border: "1px solid rgba(255,255,255,0.08)"
      }}>
        {value || "—"}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════
// UI COMPONENTS
// ═══════════════════════════════════════════

function DropZone({ id, label, hint, icon, file, onFile, accentColor = "#f59e0b" }) {
  const [over, setOver] = useState(false);
  return (
    <div>
      <label htmlFor={id} style={{ cursor: "pointer" }}>
        <div
          onDragOver={e => { e.preventDefault(); setOver(true); }}
          onDragLeave={() => setOver(false)}
          onDrop={e => { e.preventDefault(); setOver(false); const f = e.dataTransfer.files[0]; if (f) onFile(f); }}
          style={{
            border: `1.5px dashed ${over ? accentColor : "rgba(255,255,255,0.1)"}`,
            borderRadius: 8, padding: "20px 16px", textAlign: "center", cursor: "pointer",
            transition: "all 0.2s", background: over ? "rgba(245,158,11,0.04)" : "#161b22"
          }}
        >
          <div style={{ fontSize: 22, marginBottom: 8 }}>{icon}</div>
          <div style={{ fontFamily: "'Outfit', sans-serif", fontSize: 13, color: "#8b949e", marginBottom: 3 }}>{label}</div>
          <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, color: "#484f58" }}>{hint}</div>
        </div>
      </label>
      <input id={id} type="file" accept=".csv,.txt" style={{ display: "none" }} onChange={e => { const f = e.target.files[0]; if (f) onFile(f); }} />
      {file && (
        <div style={{ display: "flex", alignItems: "center", gap: 7, marginTop: 8, background: "rgba(52,211,153,0.07)", border: "1px solid rgba(52,211,153,0.2)", borderRadius: 5, padding: "7px 11px", fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: "#34d399" }}>
          ✓ {file.name}
        </div>
      )}
    </div>
  );
}

function Card({ children, accentColor = "#f59e0b" }) {
  return (
    <div style={{ background: "#1c2128", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 10, padding: "22px", position: "relative", overflow: "hidden" }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${accentColor} 0%, transparent 60%)` }} />
      {children}
    </div>
  );
}

function CardLabel({ children, color = "#f59e0b" }) {
  return (
    <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, letterSpacing: 3, color, textTransform: "uppercase", marginBottom: 14 }}>
      {children}
    </div>
  );
}

function HintBox({ children }) {
  return (
    <div style={{ background: "rgba(96,165,250,0.07)", border: "1px solid rgba(96,165,250,0.18)", borderRadius: 6, padding: "11px 14px", fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, color: "#93c5fd", lineHeight: 1.7 }}>
      {children}
    </div>
  );
}

function StyledTextarea({ value, onChange, placeholder, rows = 6 }) {
  const [focused, setFocused] = useState(false);
  return (
    <textarea
      value={value}
      onChange={onChange}
      placeholder={placeholder}
      rows={rows}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      style={{
        width: "100%", background: "#161b22",
        border: `1.5px solid ${focused ? "#f59e0b" : "rgba(255,255,255,0.08)"}`,
        borderRadius: 7, padding: "11px 13px", color: "#e6edf3",
        fontFamily: "'IBM Plex Mono', monospace", fontSize: 11,
        resize: "vertical", outline: "none", lineHeight: 1.6, transition: "border-color 0.2s"
      }}
    />
  );
}

function StatCard({ label, value, accent, icon }) {
  return (
    <div style={{ background: "#1c2128", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 10, padding: "18px 20px", position: "relative", overflow: "hidden" }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${accent}, transparent)` }} />
      <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, color: "#484f58", textTransform: "uppercase", letterSpacing: 2, marginBottom: 10 }}>
        {icon} {label}
      </div>
      <div style={{ fontFamily: "'Outfit', sans-serif", fontSize: 32, fontWeight: 800, color: accent, lineHeight: 1 }}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════
// GLOBAL STYLES
// ═══════════════════════════════════════════

const GLOBAL_CSS = `
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Outfit:wght@400;500;600;700;800&display=swap');

* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0d1117; color: #e6edf3; font-family: 'Outfit', sans-serif; -webkit-font-smoothing: antialiased; }

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #161b22; }
::-webkit-scrollbar-thumb { background: #262c36; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #3d444d; }

textarea::placeholder { color: #3b4a5a; }

@keyframes fadeUp {
  from { opacity: 0; transform: translateY(10px); }
  to   { opacity: 1; transform: translateY(0); }
}
@keyframes shimmer {
  0%   { background-position: -200% 0; }
  100% { background-position:  200% 0; }
}
@keyframes pulseGlow {
  0%, 100% { box-shadow: 0 0 0 0 rgba(245,158,11,0); }
  50%       { box-shadow: 0 0 0 4px rgba(245,158,11,0.15); }
}

.fade-up { animation: fadeUp 0.3s ease both; }
.delay-1 { animation-delay: 0.05s; }
.delay-2 { animation-delay: 0.10s; }
.delay-3 { animation-delay: 0.15s; }
.delay-4 { animation-delay: 0.20s; }
.delay-5 { animation-delay: 0.25s; }

.nav-tab {
  padding: 10px 18px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px; letter-spacing: 1px;
  color: #6e7681; cursor: pointer;
  transition: all 0.2s;
  border-bottom: 2px solid transparent;
  white-space: nowrap; user-select: none;
  display: flex; align-items: center; gap: 6px;
}
.nav-tab:hover { color: #8b949e; }
.nav-tab.active { color: #f59e0b; border-bottom-color: #f59e0b; }

.analyze-btn {
  display: block; width: 100%;
  padding: 15px 24px;
  background: #f59e0b; border: none; border-radius: 8px;
  color: #000;
  font-family: 'Outfit', sans-serif; font-size: 14px; font-weight: 700; letter-spacing: 0.5px;
  cursor: pointer; transition: all 0.2s; text-transform: uppercase;
}
.analyze-btn:hover:not(:disabled) {
  background: #fbbf24;
  box-shadow: 0 4px 20px rgba(245,158,11,0.3);
  transform: translateY(-1px);
}
.analyze-btn:active:not(:disabled) { transform: translateY(0); }
.analyze-btn:disabled { opacity: 0.35; cursor: not-allowed; }

.filter-pill {
  padding: 5px 13px; border-radius: 20px;
  font-family: 'IBM Plex Mono', monospace; font-size: 10px;
  cursor: pointer; border: 1px solid rgba(255,255,255,0.08);
  color: #6e7681; background: transparent;
  transition: all 0.18s; letter-spacing: 0.5px; white-space: nowrap;
}
.filter-pill:hover { border-color: rgba(255,255,255,0.14); color: #8b949e; }
.filter-pill.active { border-color: #f59e0b; color: #f59e0b; background: rgba(245,158,11,0.1); }

.search-box {
  background: #161b22; border: 1.5px solid rgba(255,255,255,0.08);
  border-radius: 7px; padding: 8px 13px;
  color: #e6edf3; font-family: 'IBM Plex Mono', monospace; font-size: 12px;
  outline: none; transition: border-color 0.2s; width: 220px;
}
.search-box:focus { border-color: #f59e0b; }
.search-box::placeholder { color: #3b4a5a; }

.export-btn {
  background: #262c36; border: 1px solid rgba(255,255,255,0.14);
  border-radius: 6px; padding: 8px 14px;
  color: #8b949e; font-family: 'IBM Plex Mono', monospace; font-size: 10px;
  cursor: pointer; transition: all 0.18s; letter-spacing: 0.5px; white-space: nowrap;
}
.export-btn:hover { color: #e6edf3; border-color: #f59e0b; background: rgba(245,158,11,0.1); }

.sample-btn {
  width: 100%; margin-top: 10px; padding: 9px;
  background: rgba(96,165,250,0.07); border: 1px dashed rgba(96,165,250,0.25);
  border-radius: 6px; color: #60a5fa;
  font-family: 'IBM Plex Mono', monospace; font-size: 10px;
  cursor: pointer; transition: all 0.2s; letter-spacing: 0.5px;
}
.sample-btn:hover { background: rgba(96,165,250,0.13); border-color: rgba(96,165,250,0.4); }

.download-btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 7px 13px;
  background: rgba(245,158,11,0.07); border: 1px solid rgba(245,158,11,0.22);
  border-radius: 6px; color: #f59e0b;
  font-family: 'IBM Plex Mono', monospace; font-size: 10px;
  cursor: pointer; transition: all 0.2s; letter-spacing: 0.5px;
  white-space: nowrap;
}
.download-btn:hover { background: rgba(245,158,11,0.14); border-color: rgba(245,158,11,0.4); }

.progress-track { height: 3px; background: #262c36; border-radius: 2px; overflow: hidden; margin-bottom: 20px; }
.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #f59e0b, #fbbf24, #f59e0b);
  background-size: 200% 100%;
  border-radius: 2px; transition: width 0.3s ease;
  animation: shimmer 1.5s linear infinite;
}

.thead-cell {
  padding: 10px 14px; text-align: left;
  font-family: 'IBM Plex Mono', monospace; font-size: 9px;
  letter-spacing: 2px; color: #484f58; text-transform: uppercase;
  background: #161b22; border-bottom: 1px solid rgba(255,255,255,0.06);
}
`;

// ═══════════════════════════════════════════
// MAIN APP
// ═══════════════════════════════════════════

export default function App() {
  const [activeTab, setActiveTab] = useState(0);

  const [rulesCsv, setRulesCsv] = useState("");
  const [rulesFile, setRulesFile] = useState(null);

  const [objCsv, setObjCsv] = useState("");
  const [objFile, setObjFile] = useState(null);
  const [objPaste, setObjPaste] = useState("");

  const [grpCsv, setGrpCsv] = useState("");
  const [grpFile, setGrpFile] = useState(null);
  const [grpPaste, setGrpPaste] = useState("");

  const [decommText, setDecommText] = useState("");
  const [decommFile, setDecommFile] = useState(null);

  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [elapsed, setElapsed] = useState(null);
  const [searchQ, setSearchQ] = useState("");
  const [filterTab, setFilterTab] = useState("all");
  const [selectedRule, setSelectedRule] = useState(null);
  const [resultsKey, setResultsKey] = useState(0);
  const [sampleModal, setSampleModal] = useState(null); // { title, content }

  const readFile = (file, setter) => {
    const reader = new FileReader();
    reader.onload = e => setter(e.target.result);
    reader.readAsText(file);
  };

  const handleFile = (textSetter, fileSetter) => file => {
    fileSetter(file);
    readFile(file, textSetter);
  };

  const loadSample = () => {
    setRulesCsv(SAMPLE_RULES);
    setRulesFile({ name: "sample_paloalto_rules.csv" });
    setObjCsv(SAMPLE_OBJECTS);
    setObjFile({ name: "sample_objects.csv" });
    setGrpCsv(SAMPLE_GROUPS);
    setGrpFile({ name: "sample_groups.csv" });
    setDecommText(SAMPLE_DECOMM);
  };

  const analyze = () => {
    setLoading(true);
    setProgress(15);
    setResults(null);
    setSearchQ("");
    setFilterTab("all");

    const t0 = performance.now();

    setTimeout(() => {
      setProgress(35);
      const rules = parseRulesCSV(rulesCsv);

      setProgress(55);
      const rawObjs = [
        ...(objCsv.trim() ? parseObjectsCSV(objCsv) : []),
        ...(objPaste.trim() ? parseObjectText(objPaste).objects : []),
      ];
      const rawGrps = [
        ...(grpCsv.trim() ? parseGroupsCSV(grpCsv) : []),
        ...(grpPaste.trim() ? parseObjectText(grpPaste).groups : []),
        ...(objPaste.trim() ? parseObjectText(objPaste).groups : []),
      ];

      setProgress(72);
      const { objStore, grpStore } = buildStores(rawObjs, rawGrps);
      const decommIPs = parseDecommIPs(decommText);

      setProgress(90);
      const flagged = analyzeRules(rules, decommIPs, objStore, grpStore);
      setProgress(100);

      setTimeout(() => {
        setElapsed(Math.round(performance.now() - t0));
        setResults({
          flagged,
          decommIPs,
          totalRules: rules.length,
          objCount: Object.keys(objStore).length,
          grpCount: Object.keys(grpStore).length,
          objFlagged: flagged.filter(r => r._isObject).length,
        });
        setResultsKey(k => k + 1);
        setLoading(false);
      }, 200);
    }, 50);
  };

  const filteredRows = useMemo(() => {
    if (!results) return [];
    let rows = results.flagged;
    if (filterTab === "object") rows = rows.filter(r => r._isObject);
    else if (filterTab !== "all") rows = rows.filter(r => r._matchType === filterTab);
    if (searchQ.trim()) {
      const q = searchQ.toLowerCase();
      rows = rows.filter(r =>
        (r.name || r.rule_name || "").toLowerCase().includes(q) ||
        r._rawSrc.toLowerCase().includes(q) ||
        r._rawDst.toLowerCase().includes(q) ||
        r._srcHits.some(h => h.includes(q)) ||
        r._dstHits.some(h => h.includes(q))
      );
    }
    return rows;
  }, [results, searchQ, filterTab]);

  const exportCSV = () => {
    const headers = ["Rule Name", "Raw Source", "Raw Dest", "Resolved Src Hits", "Resolved Dst Hits", "Src Port", "Dst Port", "Action", "Match Type", "Via Obj/Group"];
    const rows = filteredRows.map(r => [
      r.name || r.rule_name || "",
      r._rawSrc, r._rawDst,
      r._srcHits.join(";"), r._dstHits.join(";"),
      r.source_port || r.src_port || "any",
      r.destination_port || r.dst_port || "any",
      r.action || "", r._matchType,
      r._isObject ? "YES" : "NO",
    ]);
    const csv = [headers, ...rows].map(r => r.join(",")).join("\n");
    setSampleModal({ title: "Flagged Rules Export", content: csv });
  };

  const canAnalyze = rulesCsv.trim() && decommText.trim() && !loading;

  const TABS = [
    { label: "Rules", icon: "📋", done: !!rulesCsv },
    { label: "Objects", icon: "🗂", done: !!(objCsv || objPaste) },
    { label: "Groups", icon: "👥", done: !!(grpCsv || grpPaste) },
    { label: "Decommissioned", icon: "🚫", done: !!decommText },
  ];

  return (
    <>
      <style>{GLOBAL_CSS}</style>
      <div style={{ minHeight: "100vh", background: "#0d1117" }}>

        {/* HEADER */}
        <div style={{ borderBottom: "1px solid rgba(255,255,255,0.07)", background: "#161b22" }}>
          <div style={{ maxWidth: 1260, margin: "0 auto", padding: "0 24px" }}>
            <div style={{ padding: "20px 0 0", display: "flex", alignItems: "flex-end", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                  <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#f59e0b", animation: "pulseGlow 2s ease infinite" }} />
                  <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 3, color: "#6e7681", textTransform: "uppercase" }}>
                    Firewall Intelligence Platform
                  </span>
                </div>
                <h1 style={{ fontFamily: "'Outfit', sans-serif", fontSize: "clamp(20px, 3.5vw, 32px)", fontWeight: 800, color: "#e6edf3", letterSpacing: "-0.5px" }}>
                  Decommissioned IP&nbsp;
                  <span style={{ color: "#f59e0b" }}>Rule Analyzer</span>
                </h1>
              </div>
              <div style={{ display: "flex", gap: 8, paddingBottom: 4, flexWrap: "wrap" }}>
                {[
                  { v: "10k+ rules", i: "⚡" },
                  { v: "Object resolution", i: "🗂" },
                  { v: "Nested groups", i: "👥" },
                  { v: "Subnet matching", i: "🔍" },
                ].map((b, i) => (
                  <div key={i} style={{ background: "#1c2128", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 6, padding: "5px 10px", fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, color: "#6e7681", display: "flex", gap: 5, alignItems: "center" }}>
                    <span>{b.i}</span><span>{b.v}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Nav Tabs */}
            <div style={{ display: "flex", gap: 0, marginTop: 16, overflowX: "auto" }}>
              {TABS.map((t, i) => (
                <div
                  key={i}
                  className={`nav-tab${activeTab === i ? " active" : ""}`}
                  onClick={() => setActiveTab(i)}
                >
                  {t.icon} {t.label}
                  {t.done && activeTab !== i && (
                    <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#34d399", display: "inline-block" }} />
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* BODY */}
        <div style={{ maxWidth: 1260, margin: "0 auto", padding: "32px 24px" }}>

          {/* TAB 0: RULES */}
          {activeTab === 0 && (
            <div className="fade-up" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              <Card>
                <CardLabel>Upload Firewall Rules</CardLabel>
                <DropZone
                  id="rules-file"
                  label="Drop Palo Alto CSV export here"
                  hint="or click to browse — .csv / .txt"
                  icon="📂"
                  file={rulesFile}
                  onFile={handleFile(setRulesCsv, setRulesFile)}
                />
                <button className="sample-btn" onClick={loadSample}>
                  ⚡ Load full sample dataset (rules + objects + groups)
                </button>
              </Card>
              <Card>
                <CardLabel>Expected Format</CardLabel>
                <HintBox>
                  <strong>Required columns:</strong> Name, Source, Destination, Source Port, Destination Port, Action<br /><br />
                  <strong>Source / Destination can be:</strong><br />
                  &nbsp;• Raw IP &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ <code>10.10.10.5</code><br />
                  &nbsp;• Subnet &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ <code>10.10.0.0/24</code><br />
                  &nbsp;• Object name &nbsp;→ <code>OBJ-WEB-SERVER</code><br />
                  &nbsp;• Group name &nbsp;&nbsp;→ <code>GRP-PROD-SERVERS</code><br />
                  &nbsp;• Mixed list &nbsp;&nbsp;&nbsp;→ <code>OBJ-A;OBJ-B;10.0.0.1</code>
                </HintBox>
                <div style={{ marginTop: 12, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
                  {rulesCsv && (
                    <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, color: "#6e7681" }}>
                      {parseRulesCSV(rulesCsv).length.toLocaleString()} rules loaded
                    </span>
                  )}
                  <button className="download-btn" onClick={() => setSampleModal({ title: "Firewall Rules — Sample CSV", content: TEMPLATE_RULES })}>
                    ↓ View Sample CSV Format
                  </button>
                </div>
              </Card>
            </div>
          )}

          {/* TAB 1: OBJECTS */}
          {activeTab === 1 && (
            <div className="fade-up" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              <Card accentColor="#60a5fa">
                <CardLabel color="#60a5fa">Upload Objects CSV</CardLabel>
                <HintBox>
                  <strong>Columns:</strong> <code>name, value</code> — one IP/subnet per row<br />
                  Also supports Palo Alto format: <code>name, type, ip_netmask</code>
                </HintBox>
                <div style={{ marginTop: 12 }}>
                  <DropZone
                    id="obj-file"
                    label="Drop objects CSV here"
                    hint="name, value"
                    icon="📄"
                    file={objFile}
                    onFile={handleFile(setObjCsv, setObjFile)}
                    accentColor="#60a5fa"
                  />
                </div>
                <div style={{ marginTop: 10, display: "flex", justifyContent: "flex-end" }}>
                  <button className="download-btn" onClick={() => setSampleModal({ title: "Objects — Sample CSV", content: TEMPLATE_OBJECTS })}>
                    ↓ View Sample CSV Format
                  </button>
                </div>
              </Card>
              <Card accentColor="#60a5fa">
                <CardLabel color="#60a5fa">Paste Object Definitions</CardLabel>
                <StyledTextarea
                  value={objPaste}
                  onChange={e => setObjPaste(e.target.value)}
                  placeholder={"OBJ-WEB-SERVER = 10.10.10.5\nOBJ-DB-HOST = 192.168.1.100\nOBJ-BACKUP = 10.20.0.5/24"}
                  rows={7}
                />
                <div style={{ marginTop: 10 }}>
                  <HintBox>
                    Supports: <code>NAME = IP</code> &nbsp;|&nbsp; <code>NAME IP</code> &nbsp;|&nbsp; <code>NAME: IP</code><br />
                    For groups: <code>GROUP-NAME member1;member2;member3</code>
                  </HintBox>
                </div>
              </Card>
            </div>
          )}

          {/* TAB 2: GROUPS */}
          {activeTab === 2 && (
            <div className="fade-up" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              <Card accentColor="#34d399">
                <CardLabel color="#34d399">Upload Groups CSV</CardLabel>
                <HintBox>
                  <strong>Option A</strong> — one member per row:<br />
                  &nbsp;&nbsp;<code>group_name, member</code><br /><br />
                  <strong>Option B</strong> — semicolon-separated members:<br />
                  &nbsp;&nbsp;<code>GRP-PROD, OBJ-A;OBJ-B;GRP-SUB</code><br /><br />
                  <strong>Members can be any mix of:</strong><br />
                  &nbsp;&nbsp;• Object names &nbsp;&nbsp;→ <code>OBJ-WEB-SERVER</code><br />
                  &nbsp;&nbsp;• Group names &nbsp;&nbsp;&nbsp;→ <code>GRP-PROD-SERVERS</code><br />
                  &nbsp;&nbsp;• Raw IPs &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ <code>10.10.5.50</code><br />
                  &nbsp;&nbsp;• Subnets &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ <code>192.168.10.0/24</code>
                </HintBox>
                <div style={{ marginTop: 12 }}>
                  <DropZone
                    id="grp-file"
                    label="Drop groups CSV here"
                    hint="group_name, member(s)"
                    icon="👥"
                    file={grpFile}
                    onFile={handleFile(setGrpCsv, setGrpFile)}
                    accentColor="#34d399"
                  />
                </div>
                <div style={{ marginTop: 10, display: "flex", justifyContent: "flex-end" }}>
                  <button className="download-btn" onClick={() => setSampleModal({ title: "Groups — Sample CSV", content: TEMPLATE_GROUPS })}>
                    ↓ View Sample CSV Format
                  </button>
                </div>
              </Card>
              <Card accentColor="#34d399">
                <CardLabel color="#34d399">Paste Group Definitions</CardLabel>
                <StyledTextarea
                  value={grpPaste}
                  onChange={e => setGrpPaste(e.target.value)}
                  placeholder={"GRP-PROD OBJ-WEB;OBJ-DB;OBJ-APP\nGRP-LEGACY OBJ-OLD-A;OBJ-OLD-B\nGRP-ALL GRP-PROD;GRP-LEGACY"}
                  rows={7}
                />
                <div style={{ marginTop: 10 }}>
                  <HintBox>
                    Nested groups fully supported — cycles are auto-detected and skipped.<br />
                    Groups can reference other groups to any depth.
                  </HintBox>
                </div>
              </Card>
            </div>
          )}

          {/* TAB 3: DECOMMISSIONED */}
          {activeTab === 3 && (
            <div className="fade-up" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              <Card accentColor="#f87171">
                <CardLabel color="#f87171">Decommissioned IPs / Subnets</CardLabel>
                <StyledTextarea
                  value={decommText}
                  onChange={e => setDecommText(e.target.value)}
                  placeholder={"10.10.10.5\n192.168.50.0/24\n172.16.1.100\n10.20.0.0/16"}
                  rows={8}
                />
                <div style={{ margin: "10px 0", display: "flex", alignItems: "center", gap: 8 }}>
                  <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.07)" }} />
                  <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, color: "#484f58" }}>OR UPLOAD FILE</span>
                  <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.07)" }} />
                </div>
                <DropZone
                  id="decomm-file"
                  label="Drop IP list here"
                  hint=".txt or .csv"
                  icon="📁"
                  file={decommFile}
                  onFile={handleFile(setDecommText, setDecommFile)}
                />
                <div style={{ marginTop: 10, display: "flex", justifyContent: "flex-end" }}>
                  <button className="download-btn" onClick={() => setSampleModal({ title: "Decommissioned IPs — Sample Format", content: TEMPLATE_DECOMM })}>
                    ↓ View Sample Format
                  </button>
                </div>
              </Card>
              <Card>
                <CardLabel>Matching Logic</CardLabel>
                <div style={{ display: "grid", gap: 10 }}>
                  {[
                    ["IP vs IP", "Exact match", "10.10.10.5 ↔ 10.10.10.5"],
                    ["IP vs Subnet", "IP inside subnet?", "10.10.10.5 ↔ 10.10.10.0/24 ✓"],
                    ["Subnet vs IP", "IP inside subnet?", "10.10.0.0/16 ↔ 10.10.10.5 ✓"],
                    ["Subnet vs Subnet", "Any overlap?", "10.0.0.0/8 ↔ 10.10.0.0/16 ✓"],
                  ].map(([title, desc, ex], i) => (
                    <div key={i} style={{ background: "#161b22", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "10px 13px" }}>
                      <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, color: "#f59e0b", marginBottom: 3 }}>{title}</div>
                      <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, color: "#8b949e", marginBottom: 2 }}>{desc}</div>
                      <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, color: "#484f58" }}>{ex}</div>
                    </div>
                  ))}
                </div>
                {decommText && (
                  <div style={{ marginTop: 12, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, color: "#6e7681" }}>
                      {parseDecommIPs(decommText).length} entries loaded
                    </span>
                  </div>
                )}
              </Card>
            </div>
          )}

          {/* ANALYZE BUTTON */}
          <div style={{ marginTop: 28 }}>
            <button className="analyze-btn" onClick={analyze} disabled={!canAnalyze}>
              {loading ? "Analyzing…" : "Analyze Rules"}
            </button>
          </div>

          {/* PROGRESS BAR */}
          {loading && (
            <div style={{ marginTop: 16 }}>
              <div className="progress-track">
                <div className="progress-fill" style={{ width: `${progress}%` }} />
              </div>
            </div>
          )}

          {/* RESULTS */}
          {results && (
            <div key={resultsKey} style={{ marginTop: 32 }}>

              {/* Stat Cards */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 14, marginBottom: 24 }}>
                {[
                  { label: "Total Rules", value: results.totalRules, accent: "#60a5fa", icon: "📋" },
                  { label: "Flagged Rules", value: results.flagged.length, accent: "#f87171", icon: "⚠" },
                  { label: "Via Obj / Group", value: results.objFlagged, accent: "#facc15", icon: "🗂" },
                  { label: "Objects Loaded", value: results.objCount, accent: "#a78bfa", icon: "📦" },
                  { label: "Groups Loaded", value: results.grpCount, accent: "#34d399", icon: "👥" },
                ].map((s, i) => (
                  <div key={i} className={`fade-up delay-${i + 1}`}>
                    <StatCard label={s.label} value={s.value} accent={s.accent} icon={s.icon} />
                  </div>
                ))}
              </div>

              {/* Results Table */}
              <div className="fade-up delay-2" style={{ background: "#1c2128", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 10, overflow: "hidden" }}>

                {/* Toolbar */}
                <div style={{ padding: "14px 18px", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, color: "#f59e0b", textTransform: "uppercase" }}>
                      Flagged Rules
                    </span>
                    <span style={{ background: "rgba(248,113,113,0.12)", color: "#f87171", border: "1px solid rgba(248,113,113,0.2)", borderRadius: 12, padding: "2px 9px", fontFamily: "'IBM Plex Mono', monospace", fontSize: 9 }}>
                      {filteredRows.length}
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <input
                      className="search-box"
                      placeholder="Search rule, IP, object…"
                      value={searchQ}
                      onChange={e => setSearchQ(e.target.value)}
                    />
                    {results.flagged.length > 0 && (
                      <button className="export-btn" onClick={exportCSV}>⎘ Copy CSV</button>
                    )}
                  </div>
                </div>

                {/* Filter Pills */}
                <div style={{ padding: "10px 18px", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {[
                    ["all", `All  ${results.flagged.length}`],
                    ["source", "Source"],
                    ["destination", "Destination"],
                    ["both", "Both"],
                    ["object", "Via Obj/Group"],
                  ].map(([v, l]) => (
                    <button
                      key={v}
                      className={`filter-pill${filterTab === v ? " active" : ""}`}
                      onClick={() => setFilterTab(v)}
                    >
                      {l}
                    </button>
                  ))}
                </div>

                {/* Table Header */}
                {filteredRows.length > 0 && (
                  <table style={{ width: "100%", borderCollapse: "collapse", tableLayout: "fixed" }}>
                    <colgroup>
                      <col style={{ width: "17%" }} />
                      <col style={{ width: "19%" }} />
                      <col style={{ width: "19%" }} />
                      <col style={{ width: "8%" }} />
                      <col style={{ width: "8%" }} />
                      <col style={{ width: "9%" }} />
                      <col style={{ width: "9%" }} />
                      <col style={{ width: "11%" }} />
                    </colgroup>
                    <thead>
                      <tr>
                        {["Rule Name", "Source", "Destination", "Src Port", "Dst Port", "Action", "Match", "Type"].map((h, i) => (
                          <th key={h} className="thead-cell" style={i >= 3 ? { textAlign: "center" } : {}}>
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                  </table>
                )}

                {/* Rows */}
                {filteredRows.length === 0 ? (
                  results.flagged.length === 0 ? (
                    <div style={{ textAlign: "center", padding: "60px 20px", fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, color: "#34d399" }}>
                      ✓ No rules contain decommissioned IPs — ruleset is clean
                    </div>
                  ) : (
                    <div style={{ textAlign: "center", padding: "48px 20px", fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, color: "#6e7681" }}>
                      No results for current filter
                    </div>
                  )
                ) : (
                  <VirtualTable rows={filteredRows} onRowClick={setSelectedRule} />
                )}

                {/* Footer */}
                <div style={{ padding: "8px 16px", borderTop: "1px solid rgba(255,255,255,0.06)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, color: "#484f58" }}>
                    Click any row for full detail
                  </span>
                  {elapsed && (
                    <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, color: "#484f58" }}>
                      ⚡ {results.totalRules.toLocaleString()} rules analyzed in {elapsed}ms
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* EMPTY STATE */}
          {!results && !loading && (
            <div style={{ marginTop: 32, background: "#1c2128", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 10, padding: "56px 24px", textAlign: "center" }}>
              <div style={{ fontSize: 32, marginBottom: 16 }}>🔍</div>
              <div style={{ fontFamily: "'Outfit', sans-serif", fontSize: 15, color: "#8b949e", marginBottom: 8 }}>
                Ready to analyze
              </div>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: "#484f58" }}>
                Upload your firewall CSV and decommissioned IP list, then click Analyze
              </div>
            </div>
          )}

        </div>
      </div>

      <Modal rule={selectedRule} onClose={() => setSelectedRule(null)} />
      <CopyModal title={sampleModal?.title} content={sampleModal?.content} onClose={() => setSampleModal(null)} />
    </>
  );
}
