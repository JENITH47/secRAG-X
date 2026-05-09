/* ═══════════════════════════════════════════════════════════
   SecRAG-X — Graph-Centric Application Logic
   D3.js force-directed knowledge graph + Q&A + dashboard
   ═══════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  /* ── Utility ──────────────────────────────────────────── */
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  async function api(url, opts) {
    try {
      const r = await fetch(url, opts);
      if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || r.status); }
      return await r.json();
    } catch (e) { showToast(e.message || "Network error"); throw e; }
  }
  function showToast(m) {
    const old = $(".toast"); if (old) old.remove();
    const el = document.createElement("div"); el.className = "toast"; el.textContent = m;
    document.body.appendChild(el); setTimeout(() => el.remove(), 5000);
  }
  function esc(s) { return s == null ? "" : String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
  function fmtNum(n) { if (n == null || isNaN(n)) return "—"; return n >= 1000 ? (n/1000).toFixed(1).replace(/\.0$/,"")+"K" : String(n); }
  function arrJoin(a) { return Array.isArray(a) && a.length ? a.join(", ") : "—"; }
  function critBadge(v) {
    if (!v) return "";
    const c = v==="CRITICAL"?"badge-critical":v==="HIGH"?"badge-high":v==="MEDIUM"?"badge-medium":"badge-low";
    return `<span class="badge ${c}">${v}</span>`;
  }

  /* ── Node colors ──────────────────────────────────────── */
  const NODE_COLORS = {
    Asset: "#22d3ee", CVE: "#f59e0b", CWE: "#a78bfa",
    ATTACK: "#ef4444", Software: "#3b82f6", Subnet: "#10b981"
  };
  const NODE_RADIUS = { Asset: 14, CVE: 8, CWE: 10, ATTACK: 12, Software: 9, Subnet: 10 };

  /* ── Metrics ──────────────────────────────────────────── */
  (async function loadMetrics() {
    try {
      const d = await api("/api/summary");
      $("#hm-assets").textContent = fmtNum(d.assets);
      $("#hm-cves").textContent = fmtNum(d.cves);
      $("#hm-weaknesses").textContent = fmtNum(d.weaknesses);
      $("#hm-attacks").textContent = fmtNum(d.attacks);
    } catch (_) {}
  })();

  /* ── Ask + Graph ──────────────────────────────────────── */
  const askForm = $("#ask-form"), askInput = $("#ask-input"), askBtn = $("#ask-btn");
  const answerBody = $("#answer-body"), nodeCount = $("#answer-node-count");

  async function submitQuestion(q) {
    q = q.trim(); if (!q) return;
    askBtn.disabled = true;
    $("#ask-btn-text").textContent = "...";
    answerBody.innerHTML = `<div class="spinner-inline"><div class="spinner"></div>Checking knowledge graph...</div>`;
    nodeCount.textContent = "";

    try {
      const data = await api("/api/ask", {
        method: "POST", headers: {"Content-Type":"application/json"},
        body: JSON.stringify({question: q})
      });

      // Render answer
      answerBody.innerHTML = `
        <div class="answer-question-label"><span class="q-icon">Q</span>${esc(data.question)}</div>
        <div class="answer-content">${esc(data.answer)}</div>`;

      // Render graph
      if (data.graph && data.graph.nodes && data.graph.nodes.length > 0) {
        renderGraph(data.graph);
        nodeCount.textContent = `${data.graph.nodes.length} nodes · ${data.graph.edges.length} edges`;
        $("#graph-title").textContent = `Graph for: ${q.length > 40 ? q.slice(0,40)+"…" : q}`;
      } else {
        showEmptyGraph();
        nodeCount.textContent = "No graph data";
      }
    } catch (_) {
      answerBody.innerHTML = `<div class="answer-content">Could not reach the backend. Make sure the server and Neo4j are running.</div>`;
      showEmptyGraph();
    } finally {
      askBtn.disabled = false;
      $("#ask-btn-text").textContent = "Ask ▶";
      askInput.value = "";
      askInput.focus();
    }
  }

  askForm.addEventListener("submit", (e) => { e.preventDefault(); submitQuestion(askInput.value); });
  $$("#example-chips .chip").forEach(c => c.addEventListener("click", () => {
    askInput.value = c.textContent; submitQuestion(c.textContent);
  }));

  function showEmptyGraph() {
    $("#graph-placeholder").style.display = "flex";
    $("#graph-svg").style.display = "none";
  }

  /* ═══════════════════════════════════════════════════════
     D3.js Force-Directed Knowledge Graph
     ═══════════════════════════════════════════════════════ */
  let simulation = null;

  function renderGraph(graphData) {
    const container = $("#graph-container");
    const svg = d3.select("#graph-svg");
    const tooltip = $("#graph-tooltip");

    // Show SVG, hide placeholder
    $("#graph-placeholder").style.display = "none";
    $("#graph-svg").style.display = "block";

    // Clear previous
    svg.selectAll("*").remove();
    if (simulation) simulation.stop();

    const width = container.clientWidth;
    const height = container.clientHeight || 500;
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const nodes = graphData.nodes.map(d => ({...d}));
    const edges = graphData.edges.map(d => ({...d}));

    // Create maps for lookup
    const nodeMap = new Map(nodes.map(n => [n.id, n]));

    // Filter edges to only include those where both source and target exist
    const validEdges = edges.filter(e => nodeMap.has(e.source) && nodeMap.has(e.target));

    // SVG groups
    const g = svg.append("g");

    // Zoom
    const zoom = d3.zoom()
      .scaleExtent([0.3, 4])
      .on("zoom", (event) => g.attr("transform", event.transform));
    svg.call(zoom);

    // Arrow markers
    const defs = svg.append("defs");
    Object.entries(NODE_COLORS).forEach(([type, color]) => {
      defs.append("marker")
        .attr("id", `arrow-${type}`)
        .attr("viewBox", "0 -4 8 8").attr("refX", 20).attr("refY", 0)
        .attr("markerWidth", 6).attr("markerHeight", 6).attr("orient", "auto")
        .append("path").attr("d", "M0,-3L8,0L0,3").attr("fill", color).attr("opacity", 0.4);
    });

    // Links
    const link = g.append("g").selectAll("line")
      .data(validEdges).enter().append("line")
      .attr("class", "link-line")
      .attr("marker-end", d => {
        const tgt = typeof d.target === "object" ? d.target : nodeMap.get(d.target);
        return tgt ? `url(#arrow-${tgt.type})` : "";
      });

    // Link labels
    const linkLabel = g.append("g").selectAll("text")
      .data(validEdges).enter().append("text")
      .attr("class", "link-label")
      .text(d => d.type);

    // Nodes
    const node = g.append("g").selectAll("g")
      .data(nodes).enter().append("g")
      .call(d3.drag()
        .on("start", dragStart)
        .on("drag", dragging)
        .on("end", dragEnd));

    // Glow filter
    const filter = defs.append("filter").attr("id", "glow");
    filter.append("feGaussianBlur").attr("stdDeviation", "2").attr("result", "blur");
    const merge = filter.append("feMerge");
    merge.append("feMergeNode").attr("in", "blur");
    merge.append("feMergeNode").attr("in", "SourceGraphic");

    // Node circles
    node.append("circle")
      .attr("class", "node-circle")
      .attr("r", d => NODE_RADIUS[d.type] || 8)
      .attr("fill", d => NODE_COLORS[d.type] || "#64748b")
      .attr("stroke", d => NODE_COLORS[d.type] || "#64748b")
      .attr("stroke-width", 2)
      .attr("stroke-opacity", 0.3)
      .attr("fill-opacity", 0.85)
      .attr("filter", d => d.type === "Asset" || d.type === "ATTACK" ? "url(#glow)" : null);

    // Node labels
    node.append("text")
      .attr("class", "node-label")
      .attr("dy", d => (NODE_RADIUS[d.type] || 8) + 12)
      .text(d => {
        const l = d.label || d.id;
        return l.length > 18 ? l.slice(0,16)+"…" : l;
      });

    // Hover
    node.on("mouseover", function(event, d) {
      d3.select(this).select("circle").transition().duration(150)
        .attr("r", (NODE_RADIUS[d.type] || 8) * 1.4).attr("fill-opacity", 1);
      // Highlight connected
      link.attr("stroke", e => (e.source.id===d.id||e.target.id===d.id) ? NODE_COLORS[d.type] : null)
          .attr("stroke-opacity", e => (e.source.id===d.id||e.target.id===d.id) ? 0.6 : 0.12)
          .attr("stroke-width", e => (e.source.id===d.id||e.target.id===d.id) ? 2 : 1);
      // Tooltip
      let html = `<b>${esc(d.label||d.id)}</b><br>Type: ${d.type}`;
      if (d.cvss) html += `<br>CVSS: ${d.cvss}`;
      if (d.severity) html += `<br>Severity: ${d.severity}`;
      if (d.department) html += `<br>Dept: ${d.department}`;
      if (d.criticality) html += `<br>Criticality: ${d.criticality}`;
      tooltip.innerHTML = html;
      tooltip.style.display = "block";
    })
    .on("mousemove", (event) => {
      tooltip.style.left = (event.clientX + 14) + "px";
      tooltip.style.top = (event.clientY - 10) + "px";
    })
    .on("mouseout", function(event, d) {
      d3.select(this).select("circle").transition().duration(150)
        .attr("r", NODE_RADIUS[d.type] || 8).attr("fill-opacity", 0.85);
      link.attr("stroke", null).attr("stroke-opacity", null).attr("stroke-width", 1);
      tooltip.style.display = "none";
    });

    // Force simulation
    simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(validEdges).id(d => d.id).distance(80))
      .force("charge", d3.forceManyBody().strength(-180))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(d => (NODE_RADIUS[d.type] || 8) + 8))
      .on("tick", () => {
        link
          .attr("x1", d => d.source.x).attr("y1", d => d.source.y)
          .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
        linkLabel
          .attr("x", d => (d.source.x + d.target.x) / 2)
          .attr("y", d => (d.source.y + d.target.y) / 2);
        node.attr("transform", d => `translate(${d.x},${d.y})`);
      });

    // Fit to view after settling
    setTimeout(() => {
      const bounds = g.node().getBBox();
      if (bounds.width > 0) {
        const pad = 40;
        const scale = Math.min(
          (width - pad*2) / bounds.width,
          (height - pad*2) / bounds.height,
          1.5
        );
        const tx = width/2 - (bounds.x + bounds.width/2) * scale;
        const ty = height/2 - (bounds.y + bounds.height/2) * scale;
        svg.transition().duration(600)
          .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
      }
    }, 1500);

    function dragStart(event, d) { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }
    function dragging(event, d) { d.fx = event.x; d.fy = event.y; }
    function dragEnd(event, d) { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }
  }

  /* ── Dashboard Toggle ─────────────────────────────────── */
  const dashToggle = $("#dashboard-toggle");
  const dashSection = $("#dashboard-section");
  const tabLoaded = {};

  dashToggle.addEventListener("click", () => {
    const open = dashSection.style.display !== "none";
    dashSection.style.display = open ? "none" : "block";
    dashToggle.classList.toggle("open", !open);
    dashToggle.textContent = open ? "📊 Show Dashboard Tables ▼" : "📊 Hide Dashboard Tables ▲";
    if (!open && !tabLoaded.risk) { tabLoaded.risk = true; loadRisks(); }
  });

  /* ── Dashboard Tabs ───────────────────────────────────── */
  $$("#tab-nav .tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.tab;
      $$("#tab-nav .tab-btn").forEach(b => b.classList.remove("active"));
      $$(".tab-panel").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      $(`#panel-${tab}`).classList.add("active");
      if (!tabLoaded[tab]) { tabLoaded[tab] = true;
        if (tab==="risk") loadRisks();
        else if (tab==="attack") loadAttacks();
        else if (tab==="health") loadHealth();
      }
    });
  });

  /* ── Risk Scoring ─────────────────────────────────────── */
  const riskSlider = $("#risk-slider"), riskVal = $("#risk-slider-val");
  riskSlider.addEventListener("input", () => riskVal.textContent = riskSlider.value);
  riskSlider.addEventListener("change", loadRisks);

  async function loadRisks() {
    const wrap = $("#risk-table-wrap"), mWrap = $("#risk-top-metrics");
    wrap.innerHTML = `<div class="table-empty"><div class="spinner" style="margin:1rem auto"></div></div>`;
    try {
      const rows = await api(`/api/risks?limit=${riskSlider.value}`);
      if (rows.length) {
        const t = rows[0];
        mWrap.innerHTML = `
          <div class="inline-metric"><div class="inline-metric-label">Top Asset</div><div class="inline-metric-value">${esc(t.asset_id)}</div></div>
          <div class="inline-metric"><div class="inline-metric-label">Risk Score</div><div class="inline-metric-value">${t.risk_rank_score??"—"}</div></div>
          <div class="inline-metric"><div class="inline-metric-label">Records</div><div class="inline-metric-value">${t.known_issues??"—"}</div></div>
          <div class="inline-metric"><div class="inline-metric-label">Severity</div><div class="inline-metric-value">${t.highest_score??"—"}</div></div>`;
      }
      wrap.innerHTML = buildTable(rows, ["asset_id","hostname","department","criticality","subnet","known_issues","highest_score","connected_systems","risk_rank_score","software"]);
    } catch(_) { wrap.innerHTML = `<div class="table-empty">Could not load.</div>`; }
  }

  /* ── Attack Exposure ──────────────────────────────────── */
  async function loadAttacks() {
    const cW = $("#attack-categories-wrap"), eW = $("#attack-exposure-wrap");
    cW.innerHTML = eW.innerHTML = `<div class="table-empty"><div class="spinner" style="margin:1rem auto"></div></div>`;
    try { cW.innerHTML = buildTable(await api("/api/attacks?limit=5"), ["attack_type","known_issues","asset_count","highest_score","example_assets"]); } catch(_) { cW.innerHTML=`<div class="table-empty">Error</div>`; }
    try { eW.innerHTML = buildTable(await api("/api/exposure?limit=5"), ["asset_id","hostname","department","subnet","known_issues","highest_score","connected_systems","possible_attack_methods"]); } catch(_) { eW.innerHTML=`<div class="table-empty">Error</div>`; }
  }

  /* ── Asset Lookup ─────────────────────────────────────── */
  $("#lookup-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const id = $("#lookup-input").value.trim().toUpperCase(), res = $("#asset-result");
    if (!/^SRV-\d+$/.test(id)) { res.innerHTML = `<p style="color:var(--warning);font-size:0.85rem">Enter SRV-032 format.</p>`; return; }
    res.innerHTML = `<div class="spinner-inline"><div class="spinner"></div>Looking up...</div>`;
    try {
      const d = await api(`/api/asset/${id}`);
      res.innerHTML = `
        <div class="inline-metrics" style="margin-bottom:0.75rem">
          <div class="inline-metric"><div class="inline-metric-label">Asset</div><div class="inline-metric-value">${esc(d.asset_id)}</div></div>
          <div class="inline-metric"><div class="inline-metric-label">Records</div><div class="inline-metric-value">${d.known_issues??"—"}</div></div>
          <div class="inline-metric"><div class="inline-metric-label">Severity</div><div class="inline-metric-value">${d.highest_score??"—"}</div></div>
          <div class="inline-metric"><div class="inline-metric-label">Connected</div><div class="inline-metric-value">${d.connected_systems??"—"}</div></div>
        </div>
        <div class="asset-detail">
          <div class="detail-card"><h4>Context</h4><ul>
            <li>Dept: ${esc(d.department||"Unknown")}</li><li>Criticality: ${critBadge(d.criticality)||"—"}</li>
            <li>Subnet: ${esc(d.subnet||"Unknown")}</li><li>Hostname: ${esc(d.hostname||"Unknown")}</li></ul></div>
          <div class="detail-card"><h4>Software & CVEs</h4><p>${arrJoin(d.software)}</p><p style="font-size:0.78rem;color:var(--text-muted);margin-top:4px">${arrJoin(d.example_cves)}</p></div>
        </div>
        <button class="explain-btn" id="explain-btn">Explain why ${esc(d.asset_id)} is risky ▶</button>`;
      $("#explain-btn").addEventListener("click", () => submitQuestion(`why is ${d.asset_id} risky`));
    } catch(err) { res.innerHTML = `<p style="color:var(--warning);font-size:0.85rem">${esc(err.message)}</p>`; }
  });

  /* ── Data Health ──────────────────────────────────────── */
  async function loadHealth() {
    const c = $("#health-sections");
    c.innerHTML = `<div class="spinner-inline"><div class="spinner"></div>Loading...</div>`;
    try {
      const d = await api("/api/health"); c.innerHTML = "";
      [["relationships","Relationship Counts"],["confidence","AFFECTED_BY Confidence"],["weak_links","Weak Links"]].forEach(([k,t],i) => {
        const rows = d[k]||[], cols = rows.length?Object.keys(rows[0]):[];
        const s = document.createElement("div"); s.className = "health-section";
        s.innerHTML = `<button class="health-toggle ${i===0?"open":""}">${t} <span style="color:var(--text-muted);font-weight:400;font-size:0.75rem">(${rows.length})</span><span class="health-toggle-icon">▼</span></button>
          <div class="health-content ${i===0?"open":""}"><div class="table-wrap">${rows.length?buildTable(rows,cols):'<div class="table-empty">No data</div>'}</div></div>`;
        c.appendChild(s);
      });
      $$(".health-toggle").forEach(b => b.addEventListener("click", () => { b.classList.toggle("open"); b.nextElementSibling.classList.toggle("open"); }));
    } catch(_) { c.innerHTML = `<div class="table-empty">Error</div>`; }
  }

  /* ── Table Builder ────────────────────────────────────── */
  function buildTable(rows, cols) {
    if (!rows||!rows.length) return '<div class="table-empty">No data found.</div>';
    cols = cols || Object.keys(rows[0]);
    const hdr = k => k.replace(/_/g," ").replace(/\b\w/g,c=>c.toUpperCase());
    let h = '<table class="data-table"><thead><tr>';
    cols.forEach(c => h += `<th>${hdr(c)}</th>`);
    h += "</tr></thead><tbody>";
    rows.forEach(r => {
      h += "<tr>";
      cols.forEach(c => {
        let v = r[c];
        if (Array.isArray(v)) v = v.join(", ")||"—";
        if (c==="criticality"&&v) { h+=`<td>${critBadge(v)}</td>`; return; }
        h += `<td>${esc(v==null?"—":String(v))}</td>`;
      });
      h += "</tr>";
    });
    return h + "</tbody></table>";
  }
})();
