#!/usr/bin/env python3
"""Generate a standalone HTML CLI reference from device_commands/*.yaml files.

Usage:
    python export_cli_reference.py [output_path]

Output defaults to device_commands/cli_reference.html
"""

import json
import sys
from pathlib import Path

COMMANDS_DIR = Path(__file__).parent / "device_commands"
DEFAULT_OUTPUT = COMMANDS_DIR / "cli_reference.html"


def _collect_tags(tree: dict) -> set:
    tags: set = set()
    for key, val in tree.items():
        if key.startswith("_") or not isinstance(val, dict):
            continue
        for t in val.get("_tags", []):
            tags.add(t)
        tags |= _collect_tags(val)
    return tags


def _count_commands(tree: dict) -> int:
    count = 0
    for key, val in tree.items():
        if key.startswith("_"):
            continue
        count += 1
        if isinstance(val, dict):
            count += _count_commands(val)
    return count


def load_databases() -> list:
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML not installed — run: pip install pyyaml")

    dbs = []
    for fpath in sorted(COMMANDS_DIR.glob("*.yaml")):
        if fpath.stem.endswith(".partial"):
            continue
        try:
            with open(fpath, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                continue
            commands = data.get("commands", {})
            dbs.append({
                "slug":          fpath.stem,
                "model":         data.get("model", fpath.stem),
                "firmware":      data.get("firmware", ""),
                "system":        data.get("system", ""),
                "source_ip":     data.get("source_ip", ""),
                "notes":         data.get("notes", ""),
                "command_count": _count_commands(commands),
                "tags":          sorted(_collect_tags(commands)),
                "commands":      commands,
            })
        except Exception as e:
            print(f"Warning: skip {fpath.name}: {e}", file=sys.stderr)
    return dbs


TAG_COLORS = {
    "dangerous":    "#dc3545",
    "factory-reset":"#dc3545",
    "stats":        "#0dcaf0",
    "wireless-rf":  "#0dcaf0",
    "version-info": "#0dcaf0",
    "ap-management":"#0dcaf0",
    "snmp-config":  "#ffc107",
    "auth":         "#ffc107",
    "acl":          "#ffc107",
    "backup":       "#0d6efd",
    "syslog":       "#0d6efd",
    "save-config":  "#198754",
    "debug":        "#6c757d",
    "vlan":         "#6c757d",
    "interfaces":   "#6c757d",
    "ntp":          "#6c757d",
    "topology":     "#6c757d",
    "dhcp":         "#6c757d",
    "crypto":       "#6c757d",
    "qos":          "#6c757d",
}

SYSTEM_LABELS = {
    "wlc-controller": ("WLC Controller",   "#0dcaf0"),
    "ap-shell":       ("AP IOS Shell",     "#198754"),
}


def generate_html(dbs: list, output: Path) -> None:
    data_json = json.dumps(dbs, ensure_ascii=False, separators=(",", ":"))

    tag_colors_json = json.dumps(TAG_COLORS)
    system_labels_json = json.dumps(SYSTEM_LABELS)

    generated = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CLI Command Reference</title>
<link rel="stylesheet"
  href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet"
  href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>
  :root {{
    --accent: #4fc3f7;
    --bg: #1a1d23;
    --bg2: #22262e;
    --bg3: #2a2f3a;
    --border: #333844;
    --text: #e0e4ef;
    --muted: #7a8499;
  }}
  body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',sans-serif; }}
  #sidebar {{
    width:280px; min-width:220px; max-width:340px;
    height:100vh; overflow-y:auto; background:var(--bg2);
    border-right:1px solid var(--border); padding:12px 8px;
    position:sticky; top:0;
  }}
  #main {{ flex:1; overflow-y:auto; padding:20px; }}
  .db-item {{
    padding:8px 10px; border-radius:6px; cursor:pointer;
    margin-bottom:4px; border:1px solid transparent;
    transition:.15s;
  }}
  .db-item:hover {{ background:var(--bg3); }}
  .db-item.active {{ background:var(--bg3); border-color:var(--accent); }}
  .db-name {{ font-size:.85rem; font-weight:600; color:var(--text); }}
  .db-meta {{ font-size:.72rem; color:var(--muted); }}
  .cmd-node {{ border-left:2px solid var(--border); margin-left:4px; }}
  .cmd-node.depth-0 {{ border-left:none; margin-left:0; }}
  .cmd-row {{ display:flex; align-items:flex-start; gap:.4rem;
              padding:3px 6px; border-radius:4px; cursor:default; }}
  .cmd-row:hover {{ background:var(--bg3); }}
  .cmd-key {{ color:var(--accent); font-family:monospace; font-size:.85rem;
              white-space:nowrap; min-width:120px; }}
  .cmd-desc {{ color:var(--muted); font-size:.78rem; flex:1; }}
  .tag {{ display:inline-block; font-size:.62rem; padding:1px 5px;
          border-radius:3px; margin-left:2px; color:#fff; white-space:nowrap; }}
  .toggle-btn {{ background:none; border:none; color:var(--muted);
                 font-size:.7rem; padding:0; min-width:14px; cursor:pointer; }}
  .tree-children {{ display:block; }}
  .tree-children.collapsed {{ display:none; }}
  #searchBox {{ background:var(--bg3); border:1px solid var(--border);
                color:var(--text); border-radius:6px; padding:6px 10px;
                font-size:.82rem; width:100%; }}
  #searchBox:focus {{ outline:none; border-color:var(--accent); }}
  .tag-filter {{ cursor:pointer; font-size:.72rem; margin:2px;
                 padding:2px 7px; border-radius:3px; color:#fff;
                 border:1px solid transparent; opacity:.7; }}
  .tag-filter.active {{ opacity:1; border-color:#fff4; }}
  .highlight {{ background:#ff0; color:#000; border-radius:2px; }}
  #noResults {{ display:none; }}
  .system-badge {{
    font-size:.72rem; padding:2px 8px; border-radius:4px;
    color:#000; font-weight:600; margin-bottom:8px; display:inline-block;
  }}
  .generated {{ font-size:.7rem; color:var(--muted); margin-top:4px; }}
</style>
</head>
<body>
<div class="d-flex" style="height:100vh;overflow:hidden">

<!-- Sidebar -->
<div id="sidebar">
  <div class="d-flex align-items-center gap-2 mb-3">
    <i class="bi bi-terminal-split" style="color:var(--accent);font-size:1.2rem"></i>
    <span style="font-weight:700;font-size:.95rem">CLI Reference</span>
  </div>
  <input id="searchBox" type="search" placeholder="Search commands…" autocomplete="off">
  <div class="generated">Generated {generated}</div>
  <hr style="border-color:var(--border);margin:10px 0">
  <div id="dbList"></div>
</div>

<!-- Main -->
<div id="main">
  <div id="welcome" class="text-center py-5" style="color:var(--muted)">
    <i class="bi bi-terminal" style="font-size:3rem;opacity:.3"></i>
    <p class="mt-3">Select a command database from the sidebar.</p>
  </div>
  <div id="dbView" style="display:none">
    <div class="d-flex align-items-center gap-3 mb-3 flex-wrap">
      <div>
        <span id="viewSystem"></span>
        <h5 id="viewModel" class="mb-0 d-inline"></h5>
        <span id="viewFirmware" class="badge bg-secondary ms-2" style="font-size:.72rem"></span>
      </div>
      <span id="viewCount" style="font-size:.8rem;color:var(--muted)"></span>
      <span id="viewIp" style="font-size:.8rem;color:var(--muted)"></span>
    </div>
    <div id="tagFilters" class="mb-3"></div>
    <div id="searchResults" style="display:none">
      <div id="searchCount" style="font-size:.75rem;color:var(--muted);margin-bottom:6px"></div>
      <div id="searchList"></div>
    </div>
    <div id="treeContainer"></div>
    <div id="noResults" class="text-center py-4" style="color:var(--muted)">
      <i class="bi bi-search" style="opacity:.3;font-size:2rem"></i>
      <p class="mt-2">No commands found.</p>
    </div>
  </div>
</div>
</div>

<script>
const DATABASES = {data_json};
const TAG_COLORS = {tag_colors_json};
const SYSTEM_LABELS = {system_labels_json};

let currentDb = null;
let activeTag = null;

function tagColor(tag) {{
  return TAG_COLORS[tag] || '#6c757d';
}}

function tagBadge(tag) {{
  return `<span class="tag" style="background:${{tagColor(tag)}}">${{tag}}</span>`;
}}

// ── Build sidebar ──────────────────────────────────────────────────────────
function buildSidebar() {{
  const list = document.getElementById('dbList');
  // Group by system
  const groups = {{}};
  DATABASES.forEach(db => {{
    const sys = db.system || 'other';
    if (!groups[sys]) groups[sys] = [];
    groups[sys].push(db);
  }});

  Object.entries(groups).forEach(([sys, dbs]) => {{
    const [label, color] = SYSTEM_LABELS[sys] || [sys, '#6c757d'];
    const badge = document.createElement('div');
    badge.className = 'system-badge';
    badge.style.background = color;
    badge.textContent = label;
    list.appendChild(badge);

    dbs.forEach(db => {{
      const el = document.createElement('div');
      el.className = 'db-item';
      el.dataset.slug = db.slug;
      el.innerHTML = `
        <div class="db-name">${{db.model}}</div>
        <div class="db-meta">
          <i class="bi bi-cpu me-1"></i>${{db.firmware}}
          &nbsp;·&nbsp;<i class="bi bi-terminal me-1"></i>${{db.command_count}} cmds
        </div>`;
      el.addEventListener('click', () => openDb(db.slug));
      list.appendChild(el);
    }});
  }});
}}

// ── Open database ──────────────────────────────────────────────────────────
function openDb(slug) {{
  currentDb = DATABASES.find(d => d.slug === slug);
  if (!currentDb) return;
  activeTag = null;
  document.getElementById('searchBox').value = '';

  // Sidebar active state
  document.querySelectorAll('.db-item').forEach(el => {{
    el.classList.toggle('active', el.dataset.slug === slug);
  }});

  // Header
  const [sysLabel, sysColor] = SYSTEM_LABELS[currentDb.system] || [currentDb.system, '#6c757d'];
  document.getElementById('viewSystem').innerHTML =
    `<span class="system-badge me-2" style="background:${{sysColor}}">${{sysLabel}}</span>`;
  document.getElementById('viewModel').textContent = currentDb.model;
  document.getElementById('viewFirmware').textContent = currentDb.firmware;
  document.getElementById('viewCount').innerHTML =
    `<i class="bi bi-terminal me-1"></i>${{currentDb.command_count}} commands`;
  document.getElementById('viewIp').innerHTML = currentDb.source_ip
    ? `<i class="bi bi-hdd-network me-1"></i>${{currentDb.source_ip}}` : '';

  // Tag filters
  const tf = document.getElementById('tagFilters');
  tf.innerHTML = '';
  if (currentDb.tags.length) {{
    const all = document.createElement('span');
    all.className = 'tag-filter active';
    all.style.background = '#6c757d';
    all.textContent = 'All';
    all.addEventListener('click', () => filterTag(null, all));
    tf.appendChild(all);
    currentDb.tags.forEach(tag => {{
      const t = document.createElement('span');
      t.className = 'tag-filter';
      t.style.background = tagColor(tag);
      t.textContent = tag;
      t.addEventListener('click', () => filterTag(tag, t));
      tf.appendChild(t);
    }});
  }}

  renderTree(currentDb.commands);
  document.getElementById('welcome').style.display = 'none';
  document.getElementById('dbView').style.display = 'block';
  document.getElementById('searchResults').style.display = 'none';
  document.getElementById('treeContainer').style.display = 'block';
  document.getElementById('noResults').style.display = 'none';
}}

// ── Render tree ────────────────────────────────────────────────────────────
function renderNode(key, val, depth) {{
  if (key.startsWith('_') || typeof val !== 'object' || val === null) return '';
  const desc = val._desc || '';
  const tags = val._tags || [];
  const hasChildren = Object.keys(val).some(k => !k.startsWith('_'));

  const tagHtml = tags.map(tagBadge).join('');
  const toggleBtn = hasChildren
    ? `<button class="toggle-btn" onclick="toggleNode(this)"><i class="bi bi-chevron-down"></i></button>`
    : `<span style="min-width:14px;display:inline-block"></span>`;

  let childHtml = '';
  if (hasChildren) {{
    Object.entries(val).forEach(([k, v]) => {{
      childHtml += renderNode(k, v, depth + 1);
    }});
  }}

  const tagAttr = tags.join(' ');
  return `
<div class="cmd-node depth-${{depth}}" data-tags="${{tagAttr}}"
     style="padding-left:${{depth * 18}}px">
  <div class="cmd-row">
    ${{toggleBtn}}
    <code class="cmd-key">${{key}}</code>
    ${{desc ? `<span class="cmd-desc">${{desc}}</span>` : ''}}
    ${{tagHtml}}
  </div>
  ${{hasChildren ? `<div class="tree-children">${{childHtml}}</div>` : ''}}
</div>`;
}}

function renderTree(commands) {{
  const container = document.getElementById('treeContainer');
  let html = '';
  Object.entries(commands).forEach(([k, v]) => {{
    html += renderNode(k, v, 0);
  }});
  container.innerHTML = html || '<p style="color:var(--muted)">No commands.</p>';
}}

function toggleNode(btn) {{
  const children = btn.closest('.cmd-node').querySelector('.tree-children');
  if (!children) return;
  const collapsed = children.classList.toggle('collapsed');
  btn.querySelector('i').className = collapsed ? 'bi bi-chevron-right' : 'bi bi-chevron-down';
}}

// ── Tag filter ─────────────────────────────────────────────────────────────
function filterTag(tag, el) {{
  activeTag = tag;
  document.querySelectorAll('.tag-filter').forEach(t => t.classList.remove('active'));
  el.classList.add('active');

  const q = document.getElementById('searchBox').value.trim();
  if (q) {{ doSearch(q); return; }}

  document.querySelectorAll('#treeContainer .cmd-node').forEach(node => {{
    if (!tag) {{ node.style.display = ''; return; }}
    const tags = (node.dataset.tags || '').split(' ');
    node.style.display = tags.includes(tag) ? '' : 'none';
  }});

  const visible = [...document.querySelectorAll('#treeContainer .cmd-node')]
    .filter(n => n.style.display !== 'none').length;
  document.getElementById('noResults').style.display = visible ? 'none' : 'block';
}}

// ── Search ─────────────────────────────────────────────────────────────────
function flattenTree(tree, prefix) {{
  const results = [];
  Object.entries(tree).forEach(([key, val]) => {{
    if (key.startsWith('_') || typeof val !== 'object') return;
    const path = prefix ? prefix + ' ' + key : key;
    const desc = val._desc || '';
    const tags = val._tags || [];
    results.push({{ path, desc, tags }});
    results.push(...flattenTree(val, path));
  }});
  return results;
}}

function doSearch(q) {{
  if (!currentDb || !q) {{
    document.getElementById('searchResults').style.display = 'none';
    document.getElementById('treeContainer').style.display = 'block';
    return;
  }}
  const ql = q.toLowerCase();
  let flat = flattenTree(currentDb.commands, '');
  if (activeTag) flat = flat.filter(c => c.tags.includes(activeTag));
  const hits = flat.filter(c =>
    c.path.toLowerCase().includes(ql) ||
    c.desc.toLowerCase().includes(ql) ||
    c.tags.some(t => t.includes(ql))
  );

  const hl = s => s.replace(new RegExp(q.replace(/[.*+?^${{}}()|[\]\\]/g,'\\$&'),'gi'),
    m => `<span class="highlight">${{m}}</span>`);

  document.getElementById('searchCount').textContent =
    `${{hits.length}} result${{hits.length !== 1 ? 's' : ''}} for "${{q}}"`;

  const list = document.getElementById('searchList');
  list.innerHTML = hits.slice(0, 200).map(c => `
    <div style="padding:4px 8px;border-bottom:1px solid var(--border)">
      <code style="color:var(--accent);font-size:.82rem">${{hl(c.path)}}</code>
      ${{c.desc ? `<span style="color:var(--muted);font-size:.76rem;margin-left:8px">${{hl(c.desc)}}</span>` : ''}}
      ${{c.tags.map(tagBadge).join('')}}
    </div>`).join('');

  document.getElementById('searchResults').style.display = 'block';
  document.getElementById('treeContainer').style.display = 'none';
  document.getElementById('noResults').style.display = hits.length ? 'none' : 'block';
}}

document.getElementById('searchBox').addEventListener('input', e => {{
  const q = e.target.value.trim();
  if (!q) {{
    document.getElementById('searchResults').style.display = 'none';
    document.getElementById('treeContainer').style.display = currentDb ? 'block' : 'none';
    document.getElementById('noResults').style.display = 'none';
    if (activeTag) filterTag(activeTag,
      document.querySelector('.tag-filter.active'));
  }} else {{
    doSearch(q);
  }}
}});

// ── Init ───────────────────────────────────────────────────────────────────
buildSidebar();
if (DATABASES.length === 1) openDb(DATABASES[0].slug);
</script>
</body>
</html>"""

    output.parent.mkdir(exist_ok=True)
    output.write_text(html, encoding="utf-8")
    print(f"Generated: {output}  ({output.stat().st_size // 1024} KB, {len(dbs)} database(s))")


def main():
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT
    dbs = load_databases()
    if not dbs:
        sys.exit(f"No YAML files found in {COMMANDS_DIR}")
    generate_html(dbs, output)


if __name__ == "__main__":
    main()
