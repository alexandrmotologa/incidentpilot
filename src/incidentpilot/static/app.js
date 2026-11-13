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

async function fetchIncidents() {
  const res = await fetch("/api/incidents?limit=50");
  state.incidents = await res.json();
  if (!state.selectedId && state.incidents.length > 0) {
    state.selectedId = state.incidents[0].id;
  }
  renderList();
  if (state.selectedId) {
    const current = state.incidents.find((i) => i.id === state.selectedId);
    if (current) renderDetail(current);
  }
}

function renderList() {
  const list = document.getElementById("incident-list");
  if (!state.incidents.length) {
    list.innerHTML = '<div class="empty-state">No incidents recorded yet.</div>';
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
  const canAct = inc.status !== "rolled_back" && inc.status !== "dismissed";
  const target = brief && brief.rollback_target ? brief.rollback_target : "previous-stable";

  let stackHtml = '<p class="muted">No stack trace captured.</p>';
  if (brief && brief.top_stacktrace && brief.top_stacktrace.frames.length) {
    const lines = brief.top_stacktrace.frames
      .map((f) => `${f.function || "<frame>"} -> ${f.file}:${f.line || "?"}`)
      .join("\n");
    stackHtml = `<pre class="code-block">${esc(brief.top_stacktrace.error_type)}: ${esc(brief.top_stacktrace.error_message)}\n${esc(lines)}</pre>`;
  }

  let commitHtml = "<p>No matching recent commit identified.</p>";
  if (brief && brief.top_candidate) {
    const c = brief.top_candidate.commit;
    const diff = c.files.map((f) => `--- ${f.path}\n${f.patch}`).join("\n\n");
    commitHtml = `
      <p><strong>${esc(c.short_sha)}</strong> by ${esc(c.author)}: ${esc(c.message)}</p>
      <pre class="code-block">${esc(diff || "No diff patch available.")}</pre>
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
          <div class="kpi-label">Errors (15m)</div>
          <div class="kpi-val">${brief ? brief.error_count_15m : 0}</div>
        </div>
        <div>
          <div class="kpi-label">Investigation</div>
          <div class="kpi-val">${brief ? brief.investigation_duration_ms : 0} ms</div>
        </div>
        <div>
          <div class="kpi-label">Synthesis</div>
          <div class="kpi-val">${brief ? esc(brief.synthesis_mode) : "-"}</div>
        </div>
      </div>
    </div>

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
      <h3>Suspect Commit & Diff</h3>
      ${commitHtml}
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

function connectSSE() {
  const dot = document.getElementById("sse-dot");
  const es = new EventSource("/api/events");
  es.addEventListener("connected", () => dot.classList.add("connected"));
  es.addEventListener("incident_created", () => fetchIncidents());
  es.addEventListener("incident_updated", () => fetchIncidents());
  es.onerror = () => dot.classList.remove("connected");
}

document.getElementById("refresh-btn").addEventListener("click", fetchIncidents);
fetchHealth();
fetchIncidents();
connectSSE();
