/**
 * app.js — THESEUS Dashboard
 *
 * Responsibilities:
 *   1. Campaign selector: fetch /api/campaigns, populate <select>
 *   2. Graph rendering: D3 force-directed layout from nodes[] + edges[]
 *   3. WebSocket: receive init / patch events from /ws/graph
 *   4. Node detail panel: click a node to inspect properties + provenance
 *   5. Event log: render event_log entries with source badges
 *   6. Chat: POST /api/chat, stream SSE response tokens
 *
 * Security notes:
 *   - All user-derived content is inserted via textContent / createElement,
 *     never innerHTML, to prevent XSS.
 *   - Campaign name is URL-validated on the backend; we still sanitise here.
 */

'use strict';

// ── Constants ─────────────────────────────────────────────────────────────────

const NODE_COLORS = {
  Subnet: 'var(--c-subnet)',
  Host: 'var(--c-host)',
  Service: 'var(--c-service)',
  ServiceGroup: '#0284c7',
  ExploitStep: 'var(--c-exploit)',
  Credential: 'var(--c-cred)',
  CredentialGroup: '#ea580c',
  Interface: 'var(--c-iface)',
};

const NODE_RADII = {
  Subnet: 14,
  Host: 18,
  Service: 12,
  ServiceGroup: 15,
  ExploitStep: 16,
  Credential: 10,
  CredentialGroup: 14,
  Interface: 9,
};

// Layout "layers" — gives the graph a stable top-to-bottom shape instead of
// re-tangling itself into a different rotation on every render.
// Lower number = higher up on screen.
const TYPE_LAYER = {
  Subnet: 0,
  Interface: 1,
  Host: 2,
  Service: 3,
  ServiceGroup: 3,
  ExploitStep: 3,
  Credential: 4,
  CredentialGroup: 4,
};

// Extra radius padding used for collision detection, to account for the
// text label under each node (labels are wider than the circle itself).
const LABEL_PADDING = 22;

// Rough average character width in px for the label font (monospace-ish
// UI font at the size used in CSS for .node text). Used only to estimate
// how far a label extends horizontally, so nodes with long labels get a
// bigger collision radius than nodes with short ones.
const CHAR_WIDTH_PX = 6.4;

/**
 * Estimate the collision radius a node needs so its label doesn't overlap
 * neighboring nodes/labels. Labels are centered under the node, so they
 * extend roughly half their width to each side — that's what matters for
 * horizontal spacing between nodes in the same row.
 */
function collideRadius(d) {
  const circleR = NODE_RADII[d.type] ?? 12;
  const label = String(d.label ?? d.id ?? '');
  const halfLabelWidth = (label.length * CHAR_WIDTH_PX) / 2;
  return Math.max(circleR + LABEL_PADDING, halfLabelWidth + 10);
}

// ── State ─────────────────────────────────────────────────────────────────────

const state = {
  campaign: (new URLSearchParams(window.location.search)).get('campaign') || localStorage.getItem('theseus_campaign') || localStorage.getItem('pentagno_campaign') || 'drupal-lab',
  nodes: [],          // graph node objects (augmented with x/y by D3)
  edges: [],          // graph edge objects
  eventLog: [],       // timeline events
  timelineSteps: [],  // parsed step objects for timeline slider
  currentStep: 0,     // active step index (1-based)
  isPlaying: false,   // replay playback state
  playTimer: null,    // playback interval handle
  ws: null,           // active WebSocket
  simulation: null,   // D3 force simulation
  selectedNodeId: null,
};

// ── DOM refs ──────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

const dom = {
  campaignSelect: $('campaign-select'),
  wsDot: $('ws-dot'),
  statusLabel: $('status-label'),
  graphSvg: $('graph-svg'),
  emptyState: $('empty-state'),
  nodeDetail: $('node-detail'),
  nodeDetailTitle: $('node-detail-title'),
  nodeDetailBody: $('node-detail-body'),
  nodeDetailClose: $('node-detail-close'),
  tooltip: $('tooltip'),
  btnReplayPlay: $('btn-replay-play'),
  btnReplayStepBack: $('btn-replay-step-back'),
  btnReplayStepFwd: $('btn-replay-step-fwd'),
  timeSlider: $('time-slider'),
  timeStepLabel: $('time-step-label'),
  logPanel: $('log-panel'),
  logPanelToggle: $('log-panel-toggle'),
  logList: $('log-list'),
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Safely create a text node. Never use innerHTML. */
function txt(str) {
  return document.createTextNode(String(str ?? ''));
}

/** Create element, optionally with className and text. */
function el(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = String(text);
  return e;
}

/** Sanitise campaign name: only alphanumerics, dash, underscore, dot. */
function sanitiseCampaignName(raw) {
  return String(raw).replace(/[^a-zA-Z0-9_.-]/g, '');
}

/**
 * Given a source point and a target node, return the point where a line
 * from source to target should stop so it lands exactly on the edge of
 * the target's circle (plus a small margin for the arrowhead), instead
 * of overlapping the circle or floating away from it.
 */
function pointOnNodeEdge(source, target, targetRadius) {
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const dist = Math.sqrt(dx * dx + dy * dy) || 1;
  const margin = targetRadius + 4; // +4 leaves room for the arrow tip
  const ratio = Math.max(0, (dist - margin) / dist);
  return { x: source.x + dx * ratio, y: source.y + dy * ratio };
}

/**
 * Target vertical layer ratios (0..1) for node types inside each hop column.
 */
const TYPE_TARGET_Y = {
  Subnet: 0.18,          // Top row for subnets
  Host: 0.40,            // Upper-middle for hosts
  Interface: 0.46,       // Tightly attached to host
  ExploitStep: 0.60,     // Middle-lower row for exploit sessions
  Service: 0.68,         // Service level
  ServiceGroup: 0.68,
  Credential: 0.84,      // Bottom row for credentials
  CredentialGroup: 0.84,
};

/**
 * Distance tuning per edge type to reflect topological proximity.
 */
function getLinkDistance(l) {
  switch (l.type) {
    case 'HAS_INTERFACE': return 35;
    case 'RUNS': return 45;
    case 'YIELDS': return 50;
    case 'CONNECTS_TO': return 75;
    case 'EXPLOITED_VIA':
    case 'COMPROMISES': return 85;
    case 'PIVOTS_INTO': return 100;
    default: return 60;
  }
}

function getLinkStrength(l) {
  switch (l.type) {
    case 'HAS_INTERFACE': return 0.7;
    case 'RUNS': return 0.6;
    case 'YIELDS': return 0.5;
    case 'CONNECTS_TO': return 0.4;
    case 'PIVOTS_INTO': return 0.3;
    default: return 0.4;
  }
}

/**
 * Computes topological hop depth (0, 1, 2, 3...) for every node in the graph.
 * Traverses from entry subnets/hosts (Hop 0: DMZ / Attacker-facing) outwards across pivot chains.
 */
function computeTopologicalHopDepths(nodes, links) {
  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  const inDegree = new Map(nodes.map(n => [n.id, 0]));
  const adj = new Map(nodes.map(n => [n.id, []]));

  for (const link of links) {
    const srcId = typeof link.source === 'object' ? link.source.id : link.source;
    const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
    if (nodeMap.has(srcId) && nodeMap.has(tgtId)) {
      adj.get(srcId).push({ target: tgtId, type: link.type });
      inDegree.set(tgtId, (inDegree.get(tgtId) || 0) + 1);
    }
  }

  const depths = new Map();
  const queue = [];

  // Find root nodes (Attacker-facing DMZ subnets or nodes with 0 in-degree)
  for (const n of nodes) {
    const isAttackerSubnet = n.type === 'Subnet' && (
      n.properties?.is_attacker_network ||
      n.id.includes('28') ||
      n.label?.includes('28') ||
      inDegree.get(n.id) === 0
    );
    if (isAttackerSubnet) {
      depths.set(n.id, 0);
      queue.push(n.id);
    }
  }

  // Fallback if no explicit roots found
  if (queue.length === 0) {
    for (const n of nodes) {
      if (inDegree.get(n.id) === 0) {
        depths.set(n.id, 0);
        queue.push(n.id);
      }
    }
  }
  if (queue.length === 0 && nodes.length > 0) {
    depths.set(nodes[0].id, 0);
    queue.push(nodes[0].id);
  }

  // BFS with edge-type specific depth increments
  while (queue.length > 0) {
    const currentId = queue.shift();
    const currentDepth = depths.get(currentId) ?? 0;

    for (const edge of adj.get(currentId) || []) {
      let depthInc = 1.0;
      if (edge.type === 'HAS_INTERFACE') depthInc = 0.1;
      else if (edge.type === 'RUNS') depthInc = 0.25;
      else if (edge.type === 'YIELDS') depthInc = 0.4;
      else if (edge.type === 'CONNECTS_TO') depthInc = 0.8;
      else if (edge.type === 'EXPLOITED_VIA' || edge.type === 'COMPROMISES') depthInc = 1.0;
      else if (edge.type === 'PIVOTS_INTO') depthInc = 1.25;

      const newDepth = currentDepth + depthInc;
      if (!depths.has(edge.target) || depths.get(edge.target) > newDepth) {
        depths.set(edge.target, newDepth);
        queue.push(edge.target);
      }
    }
  }

  // Default depth for unvisited isolated nodes based on type
  for (const n of nodes) {
    if (!depths.has(n.id) || isNaN(depths.get(n.id))) {
      const typeDefault = {
        Subnet: 0, Host: 1, Interface: 1.1, Service: 1.3,
        ServiceGroup: 1.3, ExploitStep: 2, Credential: 2.5, CredentialGroup: 2.5,
      };
      depths.set(n.id, typeDefault[n.type] ?? 1);
    }
  }

  return depths;
}

// ── Campaign selector ─────────────────────────────────────────────────────────

async function loadCampaigns() {
  try {
    const res = await fetch('/api/campaigns');
    if (!res.ok) return;
    const { campaigns } = await res.json();
    dom.campaignSelect.replaceChildren();

    const saved = (new URLSearchParams(window.location.search)).get('campaign') || localStorage.getItem('theseus_campaign') || localStorage.getItem('pentagno_campaign');
    if (saved && campaigns.includes(saved)) {
      state.campaign = sanitiseCampaignName(saved);
    } else if (campaigns.length > 0 && !campaigns.includes(state.campaign)) {
      state.campaign = sanitiseCampaignName(campaigns[0]);
    }

    for (const name of campaigns) {
      const opt = document.createElement('option');
      opt.value = sanitiseCampaignName(name);
      opt.textContent = name;
      if (name === state.campaign) opt.selected = true;
      dom.campaignSelect.appendChild(opt);
    }
  } catch (_) { /* server may be starting */ }
}

dom.campaignSelect.addEventListener('change', () => {
  state.campaign = sanitiseCampaignName(dom.campaignSelect.value);
  try {
    localStorage.setItem('theseus_campaign', state.campaign);
    const url = new URL(window.location);
    url.searchParams.set('campaign', state.campaign);
    window.history.replaceState({}, '', url);
  } catch (_) {}
  connectWebSocket();
});

// ── WebSocket ─────────────────────────────────────────────────────────────────

function setStatus(status) {
  dom.wsDot.className = `status-dot ${status}`;
  const labels = {
    connected: 'live',
    error: 'disconnected',
    '': 'connecting…',
  };
  dom.statusLabel.textContent = labels[status] ?? status;
}

function connectWebSocket() {
  if (state.ws) {
    state.ws.onclose = null;
    state.ws.onerror = null;
    state.ws.close();
    state.ws = null;
  }
  const campaign = sanitiseCampaignName(state.campaign);
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${protocol}//${location.host}/ws/graph?campaign=${encodeURIComponent(campaign)}`;
  const ws = new WebSocket(url);
  state.ws = ws;
  setStatus('');

  ws.addEventListener('open', () => {
    if (state.ws === ws) setStatus('connected');
  });

  ws.addEventListener('close', () => {
    if (state.ws === ws) {
      setStatus('error');
      setTimeout(() => {
        if (state.ws === ws) {
          connectWebSocket();
        }
      }, 3000);
    }
  });

  ws.addEventListener('error', () => {
    if (state.ws === ws) setStatus('error');
  });

  ws.addEventListener('message', evt => {
    if (state.ws !== ws) return;
    let msg;
    try { msg = JSON.parse(evt.data); } catch (_) { return; }

    if (msg.type === 'init') {
      initGraph(msg.data.nodes ?? [], msg.data.edges ?? [], msg.data.event_log ?? []);
    } else if (msg.type === 'patch') {
      applyPatch(msg.data.nodes ?? [], msg.data.edges ?? [], msg.data.event_log ?? []);
    }
  });
}

async function refreshGraph() {
  try {
    const res = await fetch(`/api/graph?campaign=${encodeURIComponent(state.campaign)}`);
    if (res.ok) {
      const data = await res.json();
      initGraph(data.nodes ?? [], data.edges ?? [], data.event_log ?? []);
    }
  } catch (_) {}
}

// ── D3 Graph ──────────────────────────────────────────────────────────────────

let svgEl, gMain, linkGroup, nodeGroup, linkLabelGroup;

function setupSvg() {
  svgEl = d3.select(dom.graphSvg);
  svgEl.selectAll('*').remove();

  // Zoom & pan
  const zoom = d3.zoom()
    .scaleExtent([0.2, 4])
    .on('zoom', e => gMain.attr('transform', e.transform));

  svgEl.call(zoom);

  gMain = svgEl.append('g');

  // Arrow marker
  svgEl.append('defs').append('marker')
    .attr('id', 'arrow')
    .attr('viewBox', '0 -4 8 8')
    .attr('refX', 5)
    .attr('refY', 0)
    .attr('markerWidth', 6)
    .attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M0,-4L8,0L0,4')
    .attr('fill', 'var(--border-h)');

  linkGroup = gMain.append('g').attr('class', 'links');
  linkLabelGroup = gMain.append('g').attr('class', 'link-labels');
  nodeGroup = gMain.append('g').attr('class', 'nodes');
}

function initGraph(nodes, edges, eventLog = []) {
  // Preserve D3 force simulation layout state (x, y, fx, fy, vx, vy) for existing nodes
  const existingMap = new Map(state.nodes.map(n => [n.id, n]));
  state.nodes = nodes.map(n => {
    const prev = existingMap.get(n.id);
    return prev ? { ...prev, ...n } : { ...n };
  });
  state.edges = edges.map(e => ({ ...e }));
  state.eventLog = eventLog;

  if (!gMain) {
    setupSvg();
  }
  renderGraph();
  setupTimeline();

  dom.emptyState.style.display = state.nodes.length ? 'none' : 'flex';
}

function applyPatch(newNodes, newEdges, newEvents = []) {
  const existingMap = new Map(state.nodes.map(n => [n.id, n]));
  newNodes.forEach(n => {
    const prev = existingMap.get(n.id);
    if (prev) {
      Object.assign(prev, n);
    } else {
      state.nodes.push({ ...n });
    }
  });

  const existingEdgeIds = new Set(state.edges.map(e => e.id));
  newEdges.forEach(e => { if (!existingEdgeIds.has(e.id)) state.edges.push({ ...e }); });

  const existingSeqs = new Set(state.eventLog.map(ev => ev.seq));
  newEvents.forEach(ev => { if (!existingSeqs.has(ev.seq)) state.eventLog.push(ev); });
  state.eventLog.sort((a, b) => a.seq - b.seq);

  renderGraph();
  setupTimeline();
  dom.emptyState.style.display = state.nodes.length ? 'none' : 'flex';
}

// ── Timeline & Attack Replay ──────────────────────────────────────────────────

function setupTimeline() {
  const tsSet = new Set();

  // 1. Include timestamps from node discoveries
  state.nodes.forEach(n => { if (n.discovered_at) tsSet.add(n.discovered_at); });

  // 2. Include timestamps from Orchestrator decision logs as independent timeline steps
  (state.eventLog || []).forEach(ev => {
    if (ev.reasoning && String(ev.reasoning).trim() && ev.timestamp) {
      tsSet.add(ev.timestamp);
    }
  });

  const sortedTimestamps = Array.from(tsSet).sort();

  if (sortedTimestamps.length > 0) {
    state.timelineSteps = sortedTimestamps.map((ts, idx) => ({
      step: idx + 1,
      timestamp: ts,
    }));
  } else {
    state.timelineSteps = [{ step: 1, timestamp: null }];
  }

  const totalSteps = state.timelineSteps.length || 1;
  dom.timeSlider.min = 1;
  dom.timeSlider.max = totalSteps;

  if (!state.isPlaying) {
    dom.timeSlider.value = totalSteps;
    state.currentStep = totalSteps;
  }

  updateTimelineUI();
  renderLogPanel();
}

function renderLogPanel() {
  dom.logList.replaceChildren();

  // Strictly filter event_log for entries containing non-empty Orchestrator AI reasoning
  const decisionEvents = (state.eventLog || []).filter(ev => Boolean(ev.reasoning && String(ev.reasoning).trim()));

  if (decisionEvents.length === 0) {
    const emptyMsg = el('div', 'log-result', 'Nessuna decisione motivata registrata.');
    dom.logList.appendChild(emptyMsg);
    return;
  }

  decisionEvents.forEach(ev => {
    const item = el('div', 'log-item');
    item.dataset.seq = ev.seq;
    item.dataset.timestamp = ev.timestamp || '';

    const header = el('div', 'log-item-header');
    const badgeType = ev.type && ev.type !== 'decision' ? ev.type : 'reasoning';
    const typeLabel = (ev.type && ev.type !== 'decision' ? ev.type : 'reasoning').toUpperCase().replace('_', ' ');
    const badge = el('span', `log-badge ${badgeType}`, typeLabel);
    
    const rightHeader = el('div', 'log-header-right');
    const time = el('span', 'log-time', ev.timestamp ? ev.timestamp.split('T')[1]?.replace('Z', '') : '');
    rightHeader.appendChild(time);

    const delLogBtn = el('button', 'log-delete-btn', '🗑️');
    delLogBtn.title = `Elimina decisione #${ev.seq}`;
    delLogBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const snippet = (ev.reasoning || '').slice(0, 100);
      const confirmed = window.confirm(`Vuoi eliminare questa decisione dell'Orchestratore (Seq #${ev.seq})?\n"${snippet}..."`);
      if (!confirmed) return;
      try {
        const res = await fetch('/api/graph/event/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ campaign: state.campaign, seq: ev.seq })
        });
        if (res.ok) {
          refreshGraph();
        } else {
          const data = await res.json();
          alert(`Errore: ${data.message || 'Impossibile eliminare l\'evento'}`);
        }
      } catch (err) {
        alert(`Errore di rete: ${err.message}`);
      }
    });
    rightHeader.appendChild(delLogBtn);

    header.appendChild(badge);
    header.appendChild(rightHeader);

    const reasoning = el('div', 'log-reasoning', ev.reasoning);

    item.appendChild(header);
    item.appendChild(reasoning);

    dom.logList.appendChild(item);
  });
}

function updateTimelineUI() {
  const totalSteps = state.timelineSteps.length;
  if (!totalSteps) {
    dom.timeStepLabel.textContent = 'Step 0 / 0';
    return;
  }

  const stepIdx = Math.min(Math.max(1, state.currentStep), totalSteps) - 1;
  const currentEv = state.timelineSteps[stepIdx];

  dom.timeStepLabel.textContent = `Step ${state.currentStep} / ${totalSteps}`;

  if (!currentEv) return;
  const currentCutoffTs = currentEv.timestamp;

  // Dim or reveal nodes based on cutoff timestamp
  if (nodeGroup) {
    nodeGroup.selectAll('g.node').each(function (d) {
      const nodeTs = d.discovered_at;
      const isVisible = !currentCutoffTs || !nodeTs || nodeTs <= currentCutoffTs;
      d3.select(this).classed('dimmed', !isVisible);
    });
  }

  // Dim or reveal links based on source and target node visibility
  if (linkGroup) {
    linkGroup.selectAll('line.link').each(function (d) {
      const srcTs = typeof d.source === 'object' ? d.source.discovered_at : null;
      const tgtTs = typeof d.target === 'object' ? d.target.discovered_at : null;
      const isVisible = (!currentCutoffTs) || ((!srcTs || srcTs <= currentCutoffTs) && (!tgtTs || tgtTs <= currentCutoffTs));
      d3.select(this).classed('dimmed', !isVisible);
    });
  }

  if (linkLabelGroup) {
    linkLabelGroup.selectAll('text.link-label').each(function (d) {
      const srcTs = typeof d.source === 'object' ? d.source.discovered_at : null;
      const tgtTs = typeof d.target === 'object' ? d.target.discovered_at : null;
      const isVisible = (!currentCutoffTs) || ((!srcTs || srcTs <= currentCutoffTs) && (!tgtTs || tgtTs <= currentCutoffTs));
      d3.select(this).classed('dimmed', !isVisible);
    });
  }

  // Update Orchestrator Log Panel
  updateLogPanelUI(currentCutoffTs);
}

function updateLogPanelUI(currentCutoffTs) {
  const logItems = dom.logList.querySelectorAll('.log-item');
  let activeItem = null;

  logItems.forEach(item => {
    const ts = item.dataset.timestamp;
    const isPastOrActive = !currentCutoffTs || !ts || ts <= currentCutoffTs;

    item.classList.remove('active-step');
    if (isPastOrActive) {
      item.classList.add('past-step');
      item.style.display = 'block';
      activeItem = item;
    } else {
      item.classList.remove('past-step');
      item.style.display = 'none';
    }
  });

  if (activeItem) {
    activeItem.classList.add('active-step');
    activeItem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

if (dom.logPanelToggle) {
  dom.logPanelToggle.addEventListener('click', () => {
    const isCollapsed = dom.logPanel.classList.toggle('collapsed');
    dom.logPanelToggle.textContent = isCollapsed ? '📋 Espandi' : '📋 Minimizza';
  });
}

function togglePlay() {
  if (state.isPlaying) {
    stopPlay();
  } else {
    startPlay();
  }
}

function startPlay() {
  const totalSteps = state.timelineSteps.length || 1;
  if (state.currentStep >= totalSteps) {
    state.currentStep = 1;
    dom.timeSlider.value = 1;
    updateTimelineUI();
  }
  state.isPlaying = true;
  dom.btnReplayPlay.textContent = '⏸';
  if (state.playTimer) clearInterval(state.playTimer);
  state.playTimer = setInterval(() => {
    const maxSteps = state.timelineSteps.length || 1;
    if (state.currentStep < maxSteps) {
      state.currentStep++;
      dom.timeSlider.value = state.currentStep;
      updateTimelineUI();
    } else {
      stopPlay();
    }
  }, 1000);
}

function stopPlay() {
  state.isPlaying = false;
  dom.btnReplayPlay.textContent = '▶';
  if (state.playTimer) {
    clearInterval(state.playTimer);
    state.playTimer = null;
  }
}

dom.timeSlider.addEventListener('input', () => {
  state.currentStep = parseInt(dom.timeSlider.value, 10);
  updateTimelineUI();
});

dom.btnReplayPlay.addEventListener('click', togglePlay);

dom.btnReplayStepBack.addEventListener('click', () => {
  if (state.isPlaying) stopPlay();
  if (state.currentStep > 1) {
    state.currentStep--;
    dom.timeSlider.value = state.currentStep;
    updateTimelineUI();
  }
});

dom.btnReplayStepFwd.addEventListener('click', () => {
  if (state.isPlaying) stopPlay();
  const maxSteps = state.timelineSteps.length || 1;
  if (state.currentStep < maxSteps) {
    state.currentStep++;
    dom.timeSlider.value = state.currentStep;
    updateTimelineUI();
  }
});

// Keyboard controls: ArrowLeft (step back), ArrowRight (step fwd), Space (play/pause), Delete/Canc (delete selected node)
document.addEventListener('keydown', (e) => {
  const tag = e.target ? e.target.tagName : '';
  if (tag === 'INPUT' && e.target !== dom.timeSlider) return;
  if (tag === 'TEXTAREA' || tag === 'SELECT') return;

  if (e.key === 'Delete' || e.key === 'Del' || e.code === 'Delete') {
    if (state.selectedNodeId) {
      e.preventDefault();
      const node = state.nodes.find(n => n.id === state.selectedNodeId);
      if (node) {
        deleteNode(node);
      }
    }
    return;
  }

  const maxSteps = state.timelineSteps.length || 1;

  if (e.key === 'ArrowLeft') {
    e.preventDefault();
    if (state.isPlaying) stopPlay();
    if (state.currentStep > 1) {
      state.currentStep--;
      dom.timeSlider.value = state.currentStep;
      updateTimelineUI();
    }
  } else if (e.key === 'ArrowRight') {
    e.preventDefault();
    if (state.isPlaying) stopPlay();
    if (state.currentStep < maxSteps) {
      state.currentStep++;
      dom.timeSlider.value = state.currentStep;
      updateTimelineUI();
    }
  } else if (e.key === ' ') {
    e.preventDefault();
    togglePlay();
  }
});

// Cache for synthetic group nodes so D3 preserves their x, y, vx, vy position state across renders
const syntheticGroupNodeCache = new Map();

/**
 * Processes state.nodes and state.edges to group:
 * 1. Un-exploited open services per host (e.g. "17 Open Services").
 * 2. Credential nodes yielded by the same exploit or host (e.g. "7 Credentials").
 * PRESERVES original node object identity so D3 force simulation maintains x, y coordinates!
 */
function getProcessedGraphData() {
  const nodes = [];
  const edges = [];
  const nodeMap = new Map();

  const getEdgeFromId = e => (typeof e.from === 'object' ? e.from.id : e.from);
  const getEdgeToId = e => (typeof e.to === 'object' ? e.to.id : e.to);

  // ── 1. SERVICE GROUPING ──
  // Find all exploited service IDs
  const exploitedServiceIds = new Set();
  for (const n of state.nodes) {
    if (n.type === 'Service' && n.properties && n.properties.status === 'exploited') {
      exploitedServiceIds.add(n.id);
    }
  }
  for (const e of state.edges) {
    if (e.type === 'EXPLOITED_VIA') {
      exploitedServiceIds.add(getEdgeFromId(e));
      exploitedServiceIds.add(getEdgeToId(e));
    }
  }

  // Map service -> host
  const hostOpenServices = new Map(); // hostId -> [serviceNode]
  const serviceToHost = new Map();    // serviceId -> hostNode

  for (const n of state.nodes) {
    if (n.type === 'Host') {
      hostOpenServices.set(n.id, []);
    }
  }

  for (const e of state.edges) {
    if (e.type === 'RUNS') {
      const fromId = getEdgeFromId(e);
      const toId = getEdgeToId(e);
      const fromNode = state.nodes.find(n => n.id === fromId);
      const toNode = state.nodes.find(n => n.id === toId);
      if (fromNode && fromNode.type === 'Host' && toNode && toNode.type === 'Service') {
        serviceToHost.set(toNode.id, fromNode);
      }
    }
  }

  // Separate exploited services vs un-exploited open services per host
  const unexploitedServiceIds = new Set();
  for (const n of state.nodes) {
    if (n.type === 'Service') {
      if (exploitedServiceIds.has(n.id)) {
        continue; // Keep as individual node
      }
      const hostNode = serviceToHost.get(n.id);
      if (hostNode) {
        unexploitedServiceIds.add(n.id);
        const list = hostOpenServices.get(hostNode.id) || [];
        list.push(n);
        hostOpenServices.set(hostNode.id, list);
      }
    }
  }

  // ── 2. CREDENTIAL GROUPING ──
  const parentToCreds = new Map(); // parentNodeId -> [credNode]
  const credToParentId = new Map(); // credId -> parentNodeId

  for (const e of state.edges) {
    if (e.type === 'YIELDS') {
      const fromId = getEdgeFromId(e);
      const toId = getEdgeToId(e);
      const toNode = state.nodes.find(n => n.id === toId);
      if (toNode && toNode.type === 'Credential') {
        credToParentId.set(toId, fromId);
        const list = parentToCreds.get(fromId) || [];
        list.push(toNode);
        parentToCreds.set(fromId, list);
      }
    }
  }

  const groupedCredIds = new Set();
  for (const [parentId, creds] of parentToCreds.entries()) {
    if (creds.length > 1) {
      for (const c of creds) {
        groupedCredIds.add(c.id);
      }
    }
  }

  // Add all non-grouped nodes (KEEP ORIGINAL OBJECTS!)
  for (const n of state.nodes) {
    if (!unexploitedServiceIds.has(n.id) && !groupedCredIds.has(n.id)) {
      nodes.push(n);
      nodeMap.set(n.id, n);
    }
  }

  // Create or reuse synthetic ServiceGroup summary nodes for hosts with unexploited open services
  for (const [hostId, svcs] of hostOpenServices.entries()) {
    if (svcs.length === 0) continue;

    const hostNode = state.nodes.find(n => n.id === hostId);
    const hostIp = hostNode ? (hostNode.properties?.ip || hostNode.label || hostId) : hostId;

    if (svcs.length === 1) {
      // Single un-exploited service — keep as single node
      const s = svcs[0];
      if (!nodeMap.has(s.id)) {
        nodes.push(s);
        nodeMap.set(s.id, s);
      }
      unexploitedServiceIds.delete(s.id);
    } else {
      // Group multiple open services into one stable node
      const groupId = `svc-group-${hostId}`;
      let groupNode = syntheticGroupNodeCache.get(groupId);

      if (!groupNode) {
        groupNode = {
          id: groupId,
          type: 'ServiceGroup',
          label: `${svcs.length} Open Services`,
          source: 'tool',
          discovered_at: svcs[0].discovered_at || new Date().toISOString(),
        };
        syntheticGroupNodeCache.set(groupId, groupNode);
      }

      // Update properties on the persistent groupNode object
      groupNode.label = `${svcs.length} Open Services`;
      groupNode.properties = {
        host: hostIp,
        total_open_ports: svcs.length,
        ports: svcs.map(s => s.properties?.port || s.label).join(', '),
        services_list: svcs.map(s => `Port ${s.properties?.port || '?'}: ${s.properties?.banner || 'unknown'}`),
      };
      groupNode.grouped_services = svcs;

      nodes.push(groupNode);
      nodeMap.set(groupId, groupNode);

      // Add synthetic RUNS edge from host to group node
      edges.push({
        id: `e-${hostId}-runs-group`,
        type: 'RUNS',
        from: hostId,
        to: groupId,
        source: 'tool',
        properties: { count: svcs.length },
      });
    }
  }

  // Create or reuse synthetic CredentialGroup summary nodes for exploits/hosts with multiple credentials
  for (const [parentId, creds] of parentToCreds.entries()) {
    if (creds.length <= 1) continue;

    const parentNode = state.nodes.find(n => n.id === parentId);
    const parentName = parentNode ? (parentNode.label || parentId) : parentId;

    const groupId = `cred-group-${parentId}`;
    let groupNode = syntheticGroupNodeCache.get(groupId);

    if (!groupNode) {
      groupNode = {
        id: groupId,
        type: 'CredentialGroup',
        label: `${creds.length} Credentials`,
        source: 'tool',
        discovered_at: creds[0].discovered_at || new Date().toISOString(),
      };
      syntheticGroupNodeCache.set(groupId, groupNode);
    }

    groupNode.label = `${creds.length} Credentials`;
    groupNode.properties = {
      source_entity: parentName,
      total_credentials: creds.length,
      users: creds.map(c => c.properties?.username || 'user').join(', '),
    };
    groupNode.grouped_credentials = creds;

    nodes.push(groupNode);
    nodeMap.set(groupId, groupNode);

    // Add synthetic YIELDS edge from parent to credential group node
    edges.push({
      id: `e-${parentId}-yields-group`,
      type: 'YIELDS',
      from: parentId,
      to: groupId,
      source: 'tool',
      properties: { count: creds.length },
    });
  }

  // Helper to resolve a node ID, falling back to a valid node if the exact ID was deleted/renamed
  const resolveNodeId = id => {
    if (nodeMap.has(id)) return id;
    if (id.startsWith('exploit-')) {
      const credGroupId = `cred-group-${id}`;
      if (nodeMap.has(credGroupId)) return credGroupId;
      const anyExploitNode = nodes.find(n => n.type === 'ExploitStep');
      if (anyExploitNode) return anyExploitNode.id;
    }
    return id;
  };

  // Add edges (filtering out edges to individual unexploited services or grouped credentials)
  for (const e of state.edges) {
    let fromId = getEdgeFromId(e);
    let toId = getEdgeToId(e);
    if (unexploitedServiceIds.has(fromId) || unexploitedServiceIds.has(toId)) {
      continue;
    }
    if (groupedCredIds.has(fromId) || groupedCredIds.has(toId)) {
      continue;
    }

    fromId = resolveNodeId(fromId);
    toId = resolveNodeId(toId);

    edges.push({
      id: e.id,
      type: e.type,
      from: fromId,
      to: toId,
      source: e.source,
      properties: e.properties || {}
    });
  }

  return { nodes, edges };
}

function renderGraph() {
  const width = dom.graphSvg.clientWidth || 800;
  const height = dom.graphSvg.clientHeight || 600;

  // Pre-process graph nodes & edges to group un-exploited open services per host
  const { nodes, edges } = getProcessedGraphData();

  // Build id → node map for edge resolution
  const nodeById = new Map(nodes.map(n => [n.id, n]));

  // Resolve edge sources/targets to node objects (D3 requirement)
  const links = edges.map(e => ({
    ...e,
    source: nodeById.get(e.from) ?? e.from,
    target: nodeById.get(e.to) ?? e.to,
  })).filter(l => typeof l.source === 'object' && typeof l.target === 'object');

  // Compute Hop Depths for column flow
  const depths = computeTopologicalHopDepths(nodes, links);
  const maxDepth = Math.max(...depths.values(), 1);

  const marginX = Math.min(140, width * 0.14);
  const availableWidth = width - 2 * marginX;

  // Map Interface nodes to their parent Host node
  const ifaceHostMap = new Map();
  links.forEach(l => {
    if (l.type === 'HAS_INTERFACE') {
      const hNode = l.source.type === 'Host' ? l.source : (l.target.type === 'Host' ? l.target : null);
      const iNode = l.source.type === 'Interface' ? l.source : (l.target.type === 'Interface' ? l.target : null);
      if (hNode && iNode) ifaceHostMap.set(iNode.id, hNode);
    }
  });

  // Group non-interface nodes by depth & type
  const typeGroups = new Map();
  nodes.forEach(n => {
    if (n.type === 'Interface') return; // Handled relative to host
    const depth = depths.get(n.id) ?? 0;
    const key = `${depth}_${n.type}`;
    if (!typeGroups.has(key)) typeGroups.set(key, []);
    typeGroups.get(key).push(n);
  });

  // Position main nodes (Subnets, Hosts, Services, Exploits, Credentials)
  typeGroups.forEach((groupNodes, key) => {
    const [depthStr, type] = key.split('_');
    const depth = parseFloat(depthStr);
    const baseX = marginX + (depth / maxDepth) * availableWidth;
    const baseRatioY = TYPE_TARGET_Y[type] ?? 0.5;
    const count = groupNodes.length;
    const spacingY = Math.min(170, Math.max(110, (height * 0.6) / Math.max(1, count)));

    groupNodes.forEach((n, i) => {
      const offsetY = (i - (count - 1) / 2) * spacingY;
      n.targetX = baseX;
      n.targetY = (baseRatioY * height) + offsetY;

      if (n.x === undefined || isNaN(n.x)) {
        n.x = n.targetX;
        n.y = n.targetY;
      }
    });
  });

  // Position Interface nodes offset relative to their Host node
  const hostIfaceCounts = new Map();
  nodes.filter(n => n.type === 'Interface').forEach(n => {
    const parentHost = ifaceHostMap.get(n.id);
    if (parentHost) {
      const idx = hostIfaceCounts.get(parentHost.id) ?? 0;
      hostIfaceCounts.set(parentHost.id, idx + 1);

      n.targetX = (parentHost.x ?? parentHost.targetX ?? marginX) + 100;
      n.targetY = (parentHost.y ?? parentHost.targetY ?? height * 0.4) + (idx * 45 - 20);

      if (n.x === undefined || isNaN(n.x)) {
        n.x = n.targetX;
        n.y = n.targetY;
      }
    } else {
      n.targetX = marginX + 130;
      n.targetY = height * 0.4;
      if (n.x === undefined || isNaN(n.x)) {
        n.x = n.targetX;
        n.y = n.targetY;
      }
    }
  });

  // ── Simulation Setup — Spacious & Well-Separated Graph ──
  const forceLink = d3.forceLink(links)
    .id(d => d.id)
    .distance(l => {
      switch (l.type) {
        case 'HAS_INTERFACE': return 95;
        case 'RUNS': return 110;
        case 'YIELDS': return 120;
        case 'EXPLOITED_VIA': return 145;
        case 'COMPROMISES': return 155;
        case 'CONNECTS_TO': return 185;
        case 'PIVOTS_INTO': return 220;
        default: return 120;
      }
    })
    .strength(0.5);

  const forceCharge = d3.forceManyBody()
    .strength(-260)
    .distanceMax(450)
    .distanceMin(20);

  const forceCollide = d3.forceCollide(d => (NODE_RADII[d.type] ?? 12) + 32).strength(0.85);

  if (!state.simulation) {
    state.simulation = d3.forceSimulation(nodes)
      .force('link', forceLink)
      .force('charge', forceCharge)
      .force('collide', forceCollide)
      .alphaDecay(0.035);
  } else {
    state.simulation.nodes(nodes);
    state.simulation.force('link', forceLink);
    state.simulation.force('charge', forceCharge);
    state.simulation.force('collide', forceCollide);
    state.simulation.alpha(0.2).restart();
  }

  // ── Links SVG ──
  const linkSel = linkGroup.selectAll('line').data(links, d => d.id);
  linkSel.exit().remove();
  const linkEnter = linkSel.enter().append('line')
    .attr('class', 'link')
    .attr('marker-end', 'url(#arrow)');
  const linkMerged = linkEnter.merge(linkSel);

  // ── Link labels SVG ──
  const llSel = linkLabelGroup.selectAll('text').data(links, d => d.id);
  llSel.exit().remove();
  const llEnter = llSel.enter().append('text')
    .attr('class', 'link-label')
    .attr('text-anchor', 'middle')
    .attr('dy', '-3');
  llEnter.each(function (d) {
    // Hide noisy structural link labels like HAS_INTERFACE and RUNS to avoid text overlap
    const showLabel = d.type !== 'HAS_INTERFACE' && d.type !== 'RUNS';
    this.appendChild(txt(showLabel ? (d.type ?? '') : ''));
  });
  const llMerged = llEnter.merge(llSel);

  // ── Nodes SVG ──
  const nodeSel = nodeGroup.selectAll('g.node').data(nodes, d => d.id);
  nodeSel.exit().remove();

  const nodeEnter = nodeSel.enter().append('g')
    .attr('class', 'node')
    .call(d3.drag()
      .on('start', (e, d) => {
        if (!e.active) state.simulation.alphaTarget(0.05).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on('drag', (e, d) => {
        d.fx = e.x; d.fy = e.y;
      })
      .on('end', (e, d) => {
        if (!e.active) state.simulation.alphaTarget(0);
        d.fx = e.x; d.fy = e.y; // Keep node permanently pinned where user dragged it
      })
    );

  nodeEnter.append('circle')
    .attr('r', d => NODE_RADII[d.type] ?? 12)
    .attr('fill', d => NODE_COLORS[d.type] ?? 'var(--c-iface)')
    .attr('stroke', d => NODE_COLORS[d.type] ?? 'var(--c-iface)')
    .attr('fill-opacity', 0.25)
    .on('click', (e, d) => { e.stopPropagation(); showNodeDetail(d); })
    .on('mouseenter', (e, d) => showTooltip(e, d.label ?? d.id))
    .on('mousemove', (e) => moveTooltip(e))
    .on('mouseleave', () => hideTooltip());

  nodeEnter.append('text')
    .attr('dy', d => (NODE_RADII[d.type] ?? 12) + 12)
    .attr('text-anchor', 'middle')
    .each(function (d) { this.appendChild(txt(d.label ?? d.id)); });

  const nodeMerged = nodeEnter.merge(nodeSel);
  nodeMerged.select('circle')
    .attr('r', d => NODE_RADII[d.type] ?? 12)
    .attr('fill', d => NODE_COLORS[d.type] ?? 'var(--c-iface)')
    .attr('stroke', d => NODE_COLORS[d.type] ?? 'var(--c-iface)');

  nodeMerged.select('text')
    .attr('dy', d => (NODE_RADII[d.type] ?? 12) + 12)
    .text(d => d.label ?? d.id);

  // ── Simulation Tick Handler ──
  state.simulation.on('tick', () => {
    const padding = 45;
    nodes.forEach(d => {
      d.x = Math.max(padding, Math.min(width - padding, d.x));
      d.y = Math.max(padding, Math.min(height - padding, d.y));
    });

    linkMerged
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => {
        const r = NODE_RADII[d.target.type] ?? 12;
        return pointOnNodeEdge(d.source, d.target, r).x;
      })
      .attr('y2', d => {
        const r = NODE_RADII[d.target.type] ?? 12;
        return pointOnNodeEdge(d.source, d.target, r).y;
      });

    llMerged
      .attr('x', d => ((d.source.x + d.target.x) / 2))
      .attr('y', d => ((d.source.y + d.target.y) / 2));

    nodeMerged.attr('transform', d => `translate(${d.x},${d.y})`);
  });
}

// Click on SVG background → close detail
dom.graphSvg.addEventListener('click', () => closeNodeDetail());

// ── Node detail panel ─────────────────────────────────────────────────────────

function showNodeDetail(node) {
  state.selectedNodeId = node.id;
  dom.nodeDetailTitle.textContent = '';
  dom.nodeDetailTitle.appendChild(txt(node.label ?? node.id));
  dom.nodeDetailBody.replaceChildren();

  // Type badge
  const badge = el('span', 'detail-badge');
  badge.textContent = node.type ?? '';
  badge.style.background = (NODE_COLORS[node.type] ?? 'var(--c-iface)') + '33';
  badge.style.color = NODE_COLORS[node.type] ?? 'var(--c-iface)';
  dom.nodeDetailBody.appendChild(badge);

  // Source badge
  const srcBadge = el('span', `source-badge source-${node.source ?? 'tool'}`);
  srcBadge.textContent = ' ' + (node.source ?? 'tool');
  dom.nodeDetailBody.appendChild(srcBadge);

  // Phase Statuses editor for Host nodes (testing)
  if (node.type === 'Host') {
    const statusSec = detailSection('Phase Status (Testing)');

    const phases = [
      { key: 'scout_status', label: 'scout_status', options: ['pending', 'done'] },
      { key: 'exploit_status', label: 'exploit_status', options: ['pending', 'done', 'unsuccessful'] },
      { key: 'postexploit_status', label: 'postexploit_status', options: ['pending', 'done'] },
    ];

    phases.forEach(({ key, label, options }) => {
      const row = el('div', 'phase-status-row');
      const lbl = el('span', 'phase-status-label', label);
      const select = el('select', 'phase-status-select');
      const currentVal = (node.properties && node.properties[key]) ? String(node.properties[key]).toLowerCase() : 'pending';
      select.dataset.val = currentVal;

      options.forEach(optVal => {
        const opt = document.createElement('option');
        opt.value = optVal;
        opt.textContent = optVal;
        if (optVal === currentVal) opt.selected = true;
        select.appendChild(opt);
      });

      select.addEventListener('change', async () => {
        const newVal = select.value;
        select.dataset.val = newVal;
        try {
          const res = await fetch('/api/graph/host/status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              campaign: state.campaign,
              node_id: node.id,
              [key]: newVal,
            }),
          });
          if (res.ok) {
            if (!node.properties) node.properties = {};
            node.properties[key] = newVal;
            if (key === 'exploit_status') {
              if (newVal === 'done') node.properties.status = 'pwned';
              else if (node.properties.status === 'pwned') node.properties.status = 'alive';
            }
            refreshGraph();
          } else {
            const data = await res.json();
            alert(`Errore: ${data.message || 'Impossibile aggiornare lo status'}`);
            select.value = currentVal;
            select.dataset.val = currentVal;
          }
        } catch (err) {
          alert(`Errore di rete: ${err.message}`);
          select.value = currentVal;
          select.dataset.val = currentVal;
        }
      });

      row.appendChild(lbl);
      row.appendChild(select);
      statusSec.appendChild(row);
    });

    dom.nodeDetailBody.appendChild(statusSec);
  }

  // Properties section
  if (node.grouped_services && node.grouped_services.length) {
    const sec = detailSection(`Grouped Open Services (${node.grouped_services.length})`);
    for (const s of node.grouped_services) {
      const p = s.properties || {};
      const label = `Port ${p.port || '?'}/${p.proto || 'tcp'}`;
      const desc = p.banner || 'open service';
      sec.appendChild(detailRow(label, desc));
    }
    dom.nodeDetailBody.appendChild(sec);
  } else if (node.grouped_credentials && node.grouped_credentials.length) {
    const sec = detailSection(`Grouped Harvested Credentials (${node.grouped_credentials.length})`);
    for (const c of node.grouped_credentials) {
      const p = c.properties || {};
      const label = `${p.username || 'user'} (${p.cred_type || 'secret'})`;
      const desc = `${p.secret || '***'} [${p.location || 'env/file'}]`;
      sec.appendChild(detailRow(label, desc));
    }
    dom.nodeDetailBody.appendChild(sec);
  } else if (node.properties && Object.keys(node.properties).length) {
    const sec = detailSection('Properties');
    for (const [k, v] of Object.entries(node.properties)) {
      if (k === 'services_list') continue; // Handled separately
      if (node.type === 'Host' && ['scout_status', 'exploit_status', 'postexploit_status'].includes(k)) continue;
      const val = Array.isArray(v) ? v.join(', ') : String(v ?? '');
      sec.appendChild(detailRow(k, val));
    }
    dom.nodeDetailBody.appendChild(sec);
  }

  // Provenance section
  if (node.provenance) {
    const sec = detailSection('Provenance');
    sec.appendChild(detailRow('tool', node.provenance.tool ?? ''));
    sec.appendChild(detailRow('timestamp', node.provenance.timestamp ?? ''));
    if (node.provenance.args && Object.keys(node.provenance.args).length) {
      sec.appendChild(detailRow('args', JSON.stringify(node.provenance.args)));
    }
    if (node.provenance.raw_output) {
      const rowEl = el('div', 'detail-row');
      const keyEl = el('span', 'detail-key', 'output');
      const valEl = el('pre', 'detail-val');
      // Truncate long raw output for readability
      const truncated = String(node.provenance.raw_output).slice(0, 300);
      valEl.textContent = truncated + (node.provenance.raw_output.length > 300 ? '…' : '');
      rowEl.appendChild(keyEl);
      rowEl.appendChild(valEl);
      sec.appendChild(rowEl);
    }
    dom.nodeDetailBody.appendChild(sec);
  }

  // Delete Node button
  const delBtn = el('button', 'btn-delete-node', '🗑️ Elimina Nodo (Canc)');
  delBtn.title = `Elimina il nodo ${node.id} e gli archi correlati (o premi Canc sulla tastiera)`;
  delBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    deleteNode(node);
  });
  dom.nodeDetailBody.appendChild(delBtn);

  dom.nodeDetail.classList.add('visible');
}

function detailSection(title) {
  const sec = el('div', 'detail-section');
  sec.appendChild(el('div', 'detail-section-title', title));
  return sec;
}

function detailRow(key, val) {
  const row = el('div', 'detail-row');
  row.appendChild(el('span', 'detail-key', key));
  const valEl = el('span', 'detail-val');
  valEl.textContent = String(val);
  row.appendChild(valEl);
  return row;
}

function closeNodeDetail() {
  state.selectedNodeId = null;
  dom.nodeDetail.classList.remove('visible');
}

async function deleteNode(node) {
  if (!node) return;
  const confirmed = window.confirm(
    `Sei sicuro di voler eliminare il nodo "${node.label || node.id}" (${node.type})?\n` +
    `Questa azione rimuoverà anche gli archi collegati e resetterà lo stato di exploit sul target per consentire la ripetizione dell'attacco.`
  );
  if (!confirmed) return;

  const delBtn = document.querySelector('.btn-delete-node');
  if (delBtn) {
    delBtn.disabled = true;
    delBtn.textContent = 'Eliminazione in corso…';
  }

  try {
    const res = await fetch('/api/graph/node/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ campaign: state.campaign, node_id: node.id })
    });
    const data = await res.json();
    if (res.ok) {
      closeNodeDetail();
      refreshGraph();
    } else {
      alert(`Errore: ${data.message || 'Impossibile eliminare il nodo'}`);
      if (delBtn) {
        delBtn.disabled = false;
        delBtn.textContent = '🗑️ Elimina Nodo (Canc)';
      }
    }
  } catch (err) {
    alert(`Errore di rete: ${err.message}`);
    if (delBtn) {
      delBtn.disabled = false;
      delBtn.textContent = '🗑️ Elimina Nodo (Canc)';
    }
  }
}

dom.nodeDetailClose.addEventListener('click', closeNodeDetail);

// ── Tooltip ───────────────────────────────────────────────────────────────────

function showTooltip(e, text) {
  dom.tooltip.style.display = 'block';
  dom.tooltip.textContent = String(text);
  moveTooltip(e);
}

function moveTooltip(e) {
  dom.tooltip.style.left = (e.clientX + 12) + 'px';
  dom.tooltip.style.top = (e.clientY - 28) + 'px';
}

function hideTooltip() {
  dom.tooltip.style.display = 'none';
}

  // ── Resize ────────────────────────────────────────────────────────────────────

window.addEventListener('resize', () => {
  if (state.simulation) state.simulation.alpha(0.3).restart();
});

// ── Boot ──────────────────────────────────────────────────────────────────────

(async function boot() {
  setupSvg();
  await loadCampaigns();
  connectWebSocket();
})();