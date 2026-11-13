const state = {
  incidents: [],
  selectedId: null,
};

function esc(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

async function fetchHealth() {
  try {
    const res = await fetch("/healthz");
    const data = await res.json();
    const meta = document.getElementById("health-meta");
    meta.innerHTML = `
      <span class="pill">logs: ${esc(data.log_provider)}</span>
      <span class="pill">git: ${esc(data.git_provider)}</span>
      <span class="pill">rollback: ${esc(data.rollback_provider)}</span>
    `;
  } catch {
    // ignore
  }
}

async function fetchMetrics() {
  try {
    const res = await fetch("/api/metrics");
    const m = await res.json();
    document.getElementById("m-total").textContent = m.total_incidents;
    document.getElementById("m-active").textContent = m.active_incidents;
    document.getElementById("m-inv").textContent = `${Math.round(m.avg_investigation_ms)} ms`;
    document.getElementById("m-mttr").textContent =
      m.avg_mttr_seconds != null ? `${m.avg_mttr_seconds} s` : "-";
    document.getElementById("m-corr").textContent = `${m.correlation_hit_rate}%`;
  } catch {
    // ignore
  }
}

async function fetchIncidents() {
  const params = new URLSearchParams({ limit: "50" });
  const svc = document.getElementById("filter-service").value.trim();
  const sev = document.getElementById("filter-severity").value;
  const status = document.getElementById("filter-status").value;
  if (svc) params.set("service", svc);
  if (sev) params.set("severity", sev);
  if (status) params.set("status", status);

  const res = await fetch(`/api/incidents?${params.toString()}`);
  state.incidents = await res.json();
  if (!state.selectedId && state.incidents.length > 0) {
    state.selectedId = state.incidents[0].id;
  }
  renderList();
  if (state.selectedId) {
    const current = state.incidents.find((i) => i.id === state.selectedId);
    if (current) renderDetail(current);
  }
  fetchMetrics();
}

function renderList() {
  const list = document.getElementById("incident-list");
  if (!state.incidents.length) {
    list.innerHTML = '<div class="empty-state">No incidents match the current filter.</div>';
    return;
  }
  list.innerHTML = state.incidents
    .map((inc) => {
      const active = inc.id === state.selectedId ? "active" : "";
      const sev = inc.event.severity;
      const status = inc.status;
      const conf = inc.brief ? `${Math.round(inc.brief.confidence)}%` : "...";
      return `
        <div class="incident-item ${active}" data-id="${esc(inc.id)}">
          <div class="item-top">
            <span class="badge sev-${esc(sev)}">${esc(sev)}</span>
            <span class="badge status-${esc(status)}">${esc(status)}</span>
          </div>
          <div class="item-title">${esc(inc.event.title)}</div>
          <div class="item-sub">
            <span>${esc(inc.event.service)}</span>
            <span>conf: ${esc(conf)} | alerts: ${esc(inc.alert_count)}</span>
          </div>
        </div>
      `;
    })
    .join("");

  list.querySelectorAll(".incident-item").forEach((el) => {
    el.addEventListener("click", () => {
      state.selectedId = el.getAttribute("data-id");
      renderList();
      const found = state.incidents.find((i) => i.id === state.selectedId);
      if (found) renderDetail(found);
    });
  });
}

function renderDetail(inc) {
  const pane = document.getElementById("detail-pane");
  const brief = inc.brief;
  const canAct =
    inc.status !== "rolled_back" && inc.status !== "dismissed" && inc.status !== "resolved";
  const target = brief && brief.rollback_target ? brief.rollback_target : "previous-stable";

  let stackHtml = '<p class="muted">No stack trace captured.</p>';
  if (brief && brief.top_stacktrace && brief.top_stacktrace.frames.length) {
    const lines = brief.top_stacktrace.frames
      .map((f) => `${f.function || "<frame>"} -> ${f.file}:${f.line || "?"}`)
      .join("\n");
    stackHtml = `<pre class="code-block">${esc(brief.top_stacktrace.error_type)}: ${esc(brief.top_stacktrace.error_message)}\n${esc(lines)}</pre>`;
  }

  let candidatesHtml = "<p>No matching recent commit identified.</p>";
  const candidates = brief && brief.candidates && brief.candidates.length
    ? brief.candidates
    : brief && brief.top_candidate
    ? [brief.top_candidate]
    : [];
  if (candidates.length) {
    candidatesHtml = candidates
      .map((cand, idx) => {
        const c = cand.commit;
        const diff =
          idx === 0
            ? c.files.map((f) => `--- ${f.path}\n${f.patch}`).join("\n\n")
            : "";
        return `
          <div class="candidate-item">
            <div class="candidate-head">
              <span><strong>#${idx + 1} ${esc(c.short_sha)}</strong> by ${esc(c.author)}: ${esc(c.message)}</span>
              <span class="pill">score: ${esc(cand.score)}%</span>
            </div>
            <ul class="clean-list">
              ${(cand.reasons || []).map((r) => `<li>${esc(r)}</li>`).join("")}
            </ul>
            ${diff ? `<pre class="code-block">${esc(diff)}</pre>` : ""}
          </div>
        `;
      })
      .join("");
  }

  let runbooksHtml = "";
  if (brief && brief.matched_runbooks && brief.matched_runbooks.length) {
    runbooksHtml = `
      <div class="card">
        <h3>Matched Operational Runbooks</h3>
        ${brief.matched_runbooks
          .map(
            (rb) => `
          <div class="candidate-item">
            <div class="candidate-head">
              <strong>${esc(rb.title)}</strong>
              <span class="pill">matched: ${esc(rb.matched_pattern)}</span>
            </div>
            <ul class="clean-list">
              ${(rb.steps || []).map((s) => `<li>${esc(s)}</li>`).join("")}
            </ul>
          </div>
        `
          )
          .join("")}
      </div>
    `;
  }

  const timelineHtml = (inc.timeline || [])
    .map(
      (step) => `
      <div class="timeline-row">
        <div>
          <span class="timeline-stage">${esc(step.stage)}</span>
          <div>${esc(step.detail)}</div>
        </div>
        <div class="pill">${esc(step.duration_ms)} ms</div>
      </div>
    `
    )
    .join("");

  const rollbackHtml = (inc.rollbacks || []).length
    ? inc.rollbacks
        .map(
          (rb) => `
        <div class="timeline-row">
          <div>
            <strong>${esc(rb.target_version)}</strong> (${esc(rb.provider)}) by ${esc(rb.requested_by)}
            <div>${esc(rb.status === "succeeded" ? rb.output : rb.error)}</div>
          </div>
          <span class="badge ${rb.status === "succeeded" ? "status-rolled_back" : "status-rollback_failed"}">${esc(rb.status)}</span>
        </div>
      `
        )
        .join("")
    : "<p>No rollback executed.</p>";

  const spikeLabel =
    brief && brief.error_spike_ratio != null ? `${brief.error_spike_ratio}x` : "-";

  pane.innerHTML = `
    <div class="detail-header">
      <div>
        <h1>${esc(inc.event.title)}</h1>
        <div>
          <span class="badge sev-${esc(inc.event.severity)}">${esc(inc.event.severity)}</span>
          <span class="badge status-${esc(inc.status)}">${esc(inc.status)}</span>
          <span class="pill">${esc(inc.id)}</span>
          <span class="pill">${esc(inc.event.service)} / ${esc(inc.event.environment)}</span>
        </div>
      </div>
      <div class="detail-actions">
        <button class="btn btn-danger" id="btn-rollback" ${canAct ? "" : "disabled"}>Confirm Rollback (${esc(target)})</button>
        <button class="btn" id="btn-dismiss" ${canAct ? "" : "disabled"}>Dismiss</button>
        <a class="btn btn-ghost" href="/api/incidents/${esc(inc.id)}/postmortem.md" target="_blank">Postmortem .md</a>
      </div>
    </div>

    <div class="card">
      <h3>Incident Brief</h3>
      <p><strong>Probable Cause:</strong> ${esc(brief ? brief.probable_cause : "Investigating...")}</p>
      <p><strong>Recommendation:</strong> ${esc(brief ? brief.recommendation : "Pending...")}</p>
      <div class="kpi-row">
        <div>
          <div class="kpi-label">Confidence</div>
          <div class="kpi-val">${brief ? Math.round(brief.confidence) : 0}%</div>
        </div>
        <div>
          <div class="kpi-label">Errors (15m / 45m base)</div>
          <div class="kpi-val">${brief ? brief.error_count_15m : 0} / ${brief ? brief.baseline_error_count_45m : 0} (${esc(spikeLabel)})</div>
        </div>
        <div>
          <div class="kpi-label">Investigation</div>
          <div class="kpi-val">${brief ? brief.investigation_duration_ms : 0} ms</div>
        </div>
        <div>
          <div class="kpi-label">MTTR</div>
          <div class="kpi-val">${inc.mttr_seconds != null ? `${inc.mttr_seconds} s` : "-"}</div>
        </div>
      </div>
    </div>

    ${runbooksHtml}

    <div class="grid-2">
      <div class="card">
        <h3>Evidence</h3>
        <ul class="clean-list">
          ${(brief && brief.evidence ? brief.evidence : []).map((e) => `<li>${esc(e)}</li>`).join("")}
        </ul>
      </div>
      <div class="card">
        <h3>Stack Trace</h3>
        ${stackHtml}
      </div>
    </div>

    <div class="card">
      <h3>Top Suspect Commits (${candidates.length})</h3>
      ${candidatesHtml}
    </div>

    <div class="grid-2">
      <div class="card">
        <h3>Investigation Timeline</h3>
        ${timelineHtml}
      </div>
      <div class="card">
        <h3>Rollback Audit</h3>
        ${rollbackHtml}
      </div>
    </div>
  `;

  const rbBtn = document.getElementById("btn-rollback");
  if (rbBtn && canAct) {
    rbBtn.addEventListener("click", async () => {
      rbBtn.disabled = true;
      rbBtn.textContent = "Rolling back...";
      await fetch(`/api/incidents/${encodeURIComponent(inc.id)}/rollback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_version: target, requested_by: "web-dashboard" }),
      });
      await fetchIncidents();
    });
  }

  const disBtn = document.getElementById("btn-dismiss");
  if (disBtn && canAct) {
    disBtn.addEventListener("click", async () => {
      disBtn.disabled = true;
      await fetch(`/api/incidents/${encodeURIComponent(inc.id)}/dismiss`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ actor: "web-dashboard" }),
      });
      await fetchIncidents();
    });
  }
}

async function runSimulation() {
  const btn = document.getElementById("simulate-btn");
  const scenario = document.getElementById("sim-scenario").value;
  btn.disabled = true;
  btn.textContent = "Simulating...";
  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario }),
    });
    const created = await res.json();
    state.selectedId = created.id;
    await fetchIncidents();
  } finally {
    btn.disabled = false;
    btn.textContent = "Simulate Incident";
  }
}

function connectSSE() {
  const dot = document.getElementById("sse-dot");
  const es = new EventSource("/api/events");
  es.addEventListener("connected", () => dot.classList.add("connected"));
  es.addEventListener("incident_created", () => fetchIncidents());
  es.addEventListener("incident_updated", () => fetchIncidents());
  es.onerror = () => dot.classList.remove("connected");
}

document.getElementById("refresh-btn").addEventListener("click", fetchIncidents);
document.getElementById("simulate-btn").addEventListener("click", runSimulation);
document.getElementById("filter-service").addEventListener("input", fetchIncidents);
document.getElementById("filter-severity").addEventListener("change", fetchIncidents);
document.getElementById("filter-status").addEventListener("change", fetchIncidents);

fetchHealth();
fetchIncidents();
connectSSE();
