import React, { useEffect, useState } from "react";
import { IncidentRecord, SreMetrics } from "./types";

export const App: React.FC = () => {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [metrics, setMetrics] = useState<SreMetrics | null>(null);
  const [connected, setConnected] = useState<boolean>(false);
  const [filterService, setFilterService] = useState<string>("");
  const [filterSeverity, setFilterSeverity] = useState<string>("");
  const [filterStatus, setFilterStatus] = useState<string>("");
  const [simScenario, setSimScenario] = useState<string>("go_nil_pointer");
  const [isSimulating, setIsSimulating] = useState<boolean>(false);

  const fetchIncidents = async () => {
    try {
      const params = new URLSearchParams({ limit: "50" });
      if (filterService) params.set("service", filterService);
      if (filterSeverity) params.set("severity", filterSeverity);
      if (filterStatus) params.set("status", filterStatus);

      const res = await fetch(`/api/incidents?${params.toString()}`);
      if (res.ok) {
        const data: IncidentRecord[] = await res.json();
        setIncidents(data);
        if (!selectedId && data.length > 0) {
          setSelectedId(data[0].id);
        }
      }
    } catch {
      // offline or server restarting
    }
  };

  const fetchMetrics = async () => {
    try {
      const res = await fetch("/api/metrics");
      if (res.ok) {
        const data: SreMetrics = await res.json();
        setMetrics(data);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchIncidents();
    fetchMetrics();

    const es = new EventSource("/api/events");
    es.addEventListener("connected", () => setConnected(true));
    es.addEventListener("incident_created", () => {
      fetchIncidents();
      fetchMetrics();
    });
    es.addEventListener("incident_updated", () => {
      fetchIncidents();
      fetchMetrics();
    });
    es.onerror = () => setConnected(false);

    return () => {
      es.close();
    };
  }, [filterService, filterSeverity, filterStatus]);

  const handleSimulate = async () => {
    setIsSimulating(true);
    try {
      const res = await fetch("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario: simScenario }),
      });
      if (res.ok) {
        const created: IncidentRecord = await res.json();
        setSelectedId(created.id);
        await fetchIncidents();
        await fetchMetrics();
      }
    } finally {
      setIsSimulating(false);
    }
  };

  const handleRollback = async (inc: IncidentRecord) => {
    const target = inc.brief?.rollback_target || "previous-stable";
    await fetch(`/api/incidents/${encodeURIComponent(inc.id)}/rollback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_version: target, requested_by: "war-room-operator" }),
    });
    await fetchIncidents();
    await fetchMetrics();
  };

  const handleDismiss = async (inc: IncidentRecord) => {
    await fetch(`/api/incidents/${encodeURIComponent(inc.id)}/dismiss`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actor: "war-room-operator" }),
    });
    await fetchIncidents();
    await fetchMetrics();
  };

  const selectedIncident = incidents.find((i) => i.id === selectedId) || incidents[0];
  const brief = selectedIncident?.brief;
  const canAct =
    selectedIncident &&
    selectedIncident.status !== "rolled_back" &&
    selectedIncident.status !== "dismissed" &&
    selectedIncident.status !== "resolved";
  const rollbackTarget = brief?.rollback_target || "previous-stable";

  return (
    <>
      <header className="topbar">
        <div className="brand">
          <span
            className={`brand-dot ${connected ? "connected" : ""}`}
            title={connected ? "Connected to Live Event Stream" : "Reconnecting..."}
          />
          <span className="brand-name">IncidentPilot</span>
          <span className="brand-tag">Autonomous SRE War Room</span>
        </div>

        <div className="topbar-controls">
          <div className="sim-group">
            <select
              className="select-input"
              value={simScenario}
              onChange={(e) => setSimScenario(e.target.value)}
            >
              <option value="go_nil_pointer">Go nil pointer (PagerDuty)</option>
              <option value="python_checkout_error">Python ZeroDivision (Sentry)</option>
              <option value="oom_runbook">OOMKilled Runbook (Alertmanager)</option>
            </select>
            <button
              className="btn btn-primary btn-sm"
              onClick={handleSimulate}
              disabled={isSimulating}
            >
              {isSimulating ? "Simulating..." : "Simulate Incident"}
            </button>
          </div>
        </div>
      </header>

      {metrics && (
        <section className="metrics-bar">
          <div className="metric-card">
            <span className="metric-label">Total Incidents</span>
            <span className="metric-val">{metrics.total_incidents}</span>
          </div>
          <div className="metric-card">
            <span className="metric-label">Active</span>
            <span className="metric-val">{metrics.active_incidents}</span>
          </div>
          <div className="metric-card">
            <span className="metric-label">Avg Investigation</span>
            <span className="metric-val">{Math.round(metrics.avg_investigation_ms)} ms</span>
          </div>
          <div className="metric-card">
            <span className="metric-label">Avg MTTR</span>
            <span className="metric-val">
              {metrics.avg_mttr_seconds != null ? `${metrics.avg_mttr_seconds} s` : "-"}
            </span>
          </div>
          <div className="metric-card">
            <span className="metric-label">Correlation Hit Rate</span>
            <span className="metric-val">{metrics.correlation_hit_rate}%</span>
          </div>
        </section>
      )}

      <main className="layout">
        <aside className="sidebar">
          <div className="sidebar-header">
            <h2>Incidents</h2>
            <button className="btn btn-ghost btn-sm" onClick={fetchIncidents}>
              Refresh
            </button>
          </div>

          <div className="filter-box">
            <input
              type="text"
              className="text-input"
              placeholder="Filter service..."
              value={filterService}
              onChange={(e) => setFilterService(e.target.value)}
            />
            <div className="filter-row">
              <select
                className="select-input"
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
              >
                <option value="">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                className="select-input"
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
              >
                <option value="">All statuses</option>
                <option value="brief_sent">Brief Sent</option>
                <option value="rolled_back">Rolled Back</option>
                <option value="resolved">Resolved</option>
                <option value="dismissed">Dismissed</option>
              </select>
            </div>
          </div>

          <div className="incident-list">
            {incidents.length === 0 ? (
              <div className="empty-state">No incidents match current filter.</div>
            ) : (
              incidents.map((inc) => {
                const isActive = inc.id === (selectedIncident?.id || selectedId);
                const conf = inc.brief ? `${Math.round(inc.brief.confidence)}%` : "...";
                return (
                  <div
                    key={inc.id}
                    className={`incident-card ${isActive ? "active" : ""}`}
                    onClick={() => setSelectedId(inc.id)}
                  >
                    <div className="card-top">
                      <span className={`badge sev-${inc.event.severity}`}>
                        {inc.event.severity}
                      </span>
                      <span className={`badge status-${inc.status}`}>{inc.status}</span>
                    </div>
                    <div className="card-title">{inc.event.title}</div>
                    <div className="card-meta">
                      <span>{inc.event.service}</span>
                      <span>conf: {conf}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </aside>

        <section className="detail-pane">
          {selectedIncident ? (
            <>
              <div className="detail-header">
                <div>
                  <h1>{selectedIncident.event.title}</h1>
                  <div className="header-meta">
                    <span className={`badge sev-${selectedIncident.event.severity}`}>
                      {selectedIncident.event.severity}
                    </span>
                    <span className={`badge status-${selectedIncident.status}`}>
                      {selectedIncident.status}
                    </span>
                    <span className="pill">{selectedIncident.id}</span>
                    <span className="pill">
                      {selectedIncident.event.service} / {selectedIncident.event.environment}
                    </span>
                    <span className="pill">source: {selectedIncident.event.source}</span>
                  </div>
                </div>

                <div className="detail-actions">
                  <button
                    className="btn btn-danger"
                    disabled={!canAct}
                    onClick={() => handleRollback(selectedIncident)}
                  >
                    Confirm Rollback ({rollbackTarget})
                  </button>
                  <button
                    className="btn"
                    disabled={!canAct}
                    onClick={() => handleDismiss(selectedIncident)}
                  >
                    Acknowledge
                  </button>
                  <a
                    className="btn btn-ghost"
                    href={`/api/incidents/${encodeURIComponent(selectedIncident.id)}/postmortem.md`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Postmortem .md
                  </a>
                </div>
              </div>

              <div className="box">
                <h3>Incident Brief</h3>
                <p>
                  <strong>Probable Cause:</strong>{" "}
                  {brief ? brief.probable_cause : "Investigating..."}
                </p>
                <p>
                  <strong>Recommendation:</strong>{" "}
                  {brief ? brief.recommendation : "Analyzing telemetry..."}
                </p>
                <div className="kpi-row">
                  <div className="kpi-cell">
                    <span className="kpi-lbl">Confidence</span>
                    <span className="kpi-val">{brief ? Math.round(brief.confidence) : 0}%</span>
                  </div>
                  <div className="kpi-cell">
                    <span className="kpi-lbl">Errors (15m / 45m base)</span>
                    <span className="kpi-val">
                      {brief ? brief.error_count_15m : 0} /{" "}
                      {brief ? brief.baseline_error_count_45m : 0}{" "}
                      {brief?.error_spike_ratio != null && `(${brief.error_spike_ratio}x)`}
                    </span>
                  </div>
                  <div className="kpi-cell">
                    <span className="kpi-lbl">Investigation Duration</span>
                    <span className="kpi-val">
                      {brief ? brief.investigation_duration_ms : 0} ms
                    </span>
                  </div>
                  <div className="kpi-cell">
                    <span className="kpi-lbl">MTTR</span>
                    <span className="kpi-val">
                      {selectedIncident.mttr_seconds != null
                        ? `${selectedIncident.mttr_seconds} s`
                        : "-"}
                    </span>
                  </div>
                  <div className="kpi-cell">
                    <span className="kpi-lbl">Synthesis Mode</span>
                    <span className="kpi-val">{brief ? brief.synthesis_mode : "-"}</span>
                  </div>
                </div>
              </div>

              {brief?.matched_runbooks && brief.matched_runbooks.length > 0 && (
                <div className="box">
                  <h3>Matched Operational Runbooks</h3>
                  {brief.matched_runbooks.map((rb) => (
                    <div key={rb.id} className="candidate-box">
                      <div className="candidate-head">
                        <strong>{rb.title}</strong>
                        <span className="pill">pattern: {rb.matched_pattern}</span>
                      </div>
                      <ul className="clean-list">
                        {rb.steps.map((st, i) => (
                          <li key={i}>{st}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              )}

              <div className="grid-2">
                <div className="box">
                  <h3>Evidence Waterfall</h3>
                  <ul className="clean-list">
                    {(brief?.evidence || []).map((e, idx) => (
                      <li key={idx}>{e}</li>
                    ))}
                  </ul>
                </div>

                <div className="box">
                  <h3>Stack Trace</h3>
                  {brief?.top_stacktrace ? (
                    <pre className="code-block">
                      {brief.top_stacktrace.error_type}: {brief.top_stacktrace.error_message}
                      {"\n"}
                      {brief.top_stacktrace.frames.map((f, i) => (
                        <div key={i}>
                          &nbsp;&nbsp;at {f.function || "<frame>"} ({f.file}:{f.line || "?"})
                        </div>
                      ))}
                    </pre>
                  ) : (
                    <p className="empty-state">No stack trace captured for this incident.</p>
                  )}
                </div>
              </div>

              <div className="box">
                <h3>Top Suspect Commits ({brief?.candidates?.length || 0})</h3>
                {brief?.candidates && brief.candidates.length > 0 ? (
                  brief.candidates.map((cand, idx) => {
                    const c = cand.commit;
                    const diff =
                      idx === 0
                        ? c.files.map((f) => `--- ${f.path}\n${f.patch}`).join("\n\n")
                        : "";
                    return (
                      <div key={c.sha || idx} className="candidate-box">
                        <div className="candidate-head">
                          <span>
                            <strong>
                              #{idx + 1} {c.short_sha}
                            </strong>{" "}
                            by {c.author}: {c.message}
                          </span>
                          <span className="pill">score: {cand.score}%</span>
                        </div>
                        <ul className="clean-list">
                          {cand.reasons.map((r, i) => (
                            <li key={i}>{r}</li>
                          ))}
                        </ul>
                        {diff && <pre className="code-block">{diff}</pre>}
                      </div>
                    );
                  })
                ) : (
                  <p className="empty-state">No direct code commit match identified.</p>
                )}
              </div>

              <div className="grid-2">
                <div className="box">
                  <h3>Investigation Timeline</h3>
                  {selectedIncident.timeline.map((step, idx) => (
                    <div key={idx} className="timeline-row">
                      <div>
                        <span className="timeline-stage">{step.stage}</span>
                        <div>{step.detail}</div>
                      </div>
                      <span className="pill">{step.duration_ms} ms</span>
                    </div>
                  ))}
                </div>

                <div className="box">
                  <h3>Rollback & Mitigation Audit</h3>
                  {selectedIncident.rollbacks.length === 0 ? (
                    <p className="empty-state">No mitigation action executed yet.</p>
                  ) : (
                    selectedIncident.rollbacks.map((rb) => (
                      <div key={rb.id} className="timeline-row">
                        <div>
                          <strong>{rb.target_version}</strong> ({rb.provider}) by {rb.requested_by}
                          <div>{rb.status === "succeeded" ? rb.output : rb.error}</div>
                        </div>
                        <span
                          className={`badge ${
                            rb.status === "succeeded"
                              ? "status-rolled_back"
                              : "status-rollback_failed"
                          }`}
                        >
                          {rb.status}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state">
              <h3>No incident selected</h3>
              <p>Inbound alerts and simulations will appear here in real time.</p>
            </div>
          )}
        </section>
      </main>
    </>
  );
};
