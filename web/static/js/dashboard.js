// SOC Command Center Real-Time Dashboard Controller

let network = null;
let networkData = { nodes: new vis.DataSet([]), edges: new vis.DataSet([]) };
let isStreaming = true;
let streamInterval = null;

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    initNetworkGraph();
    loadExplanation();
    loadMitigationRules();
    startStream();

    // Event listeners
    const toggleBtn = document.getElementById("toggle-stream-btn");
    if (toggleBtn) {
        toggleBtn.addEventListener("click", toggleStreaming);
    }

    const whatIfForm = document.getElementById("whatif-form");
    if (whatIfForm) {
        whatIfForm.addEventListener("change", runWhatIf);
    }
});

// 1. Initialize Vis.js Interactive Network Topology
function initNetworkGraph() {
    const container = document.getElementById("network-graph");
    if (!container) return;

    const options = {
        nodes: {
            font: { color: "#f1f5f9", size: 12, face: "-apple-system, BlinkMacSystemFont, sans-serif" },
            borderWidth: 2,
            shadow: false,
        },
        edges: {
            font: { color: "#94a3b8", size: 10, align: "top" },
            smooth: { type: "continuous" },
            arrows: { to: { enabled: true, scaleFactor: 0.7 } },
        },
        physics: {
            stabilization: false,
            barnesHut: {
                gravitationalConstant: -2800,
                springLength: 90,
                springConstant: 0.04,
            },
        },
        interaction: { hover: true, tooltipDelay: 100 },
    };

    network = new vis.Network(container, networkData, options);

    // Initial graph fetch
    fetch("/api/graph/current")
        .then(res => res.json())
        .then(data => {
            networkData.nodes.clear();
            networkData.edges.clear();
            networkData.nodes.add(data.nodes);
            networkData.edges.add(data.edges);
        })
        .catch(err => console.error("Error fetching topology graph:", err));
}

// 2. Real-Time Telemetry Streaming
function startStream() {
    if (streamInterval) clearInterval(streamInterval);
    streamInterval = setInterval(fetchStreamBatch, 2500);
}

function toggleStreaming() {
    isStreaming = !isStreaming;
    const btn = document.getElementById("toggle-stream-btn");
    const indicator = document.getElementById("stream-status-indicator");

    if (isStreaming) {
        startStream();
        if (btn) btn.textContent = "Pause Stream";
        if (indicator) {
            indicator.textContent = "LIVE";
            indicator.className = "text-[11px] font-mono text-emerald-400 font-semibold tracking-wide";
        }
    } else {
        if (streamInterval) clearInterval(streamInterval);
        if (btn) btn.textContent = "Resume Stream";
        if (indicator) {
            indicator.textContent = "PAUSED";
            indicator.className = "text-[11px] font-mono text-amber-400 font-semibold tracking-wide";
        }
    }
}

function fetchStreamBatch() {
    fetch("/api/stream/next?batch_size=5")
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                updateFlowTable(data.processed_batch);
                updateRiskGauge(data.latest_risk);
                updateForecastCard(data.latest_forecast);
                updateMetrics(data.metrics);
                refreshGraphNodes();
            }
        })
        .catch(err => console.error("Stream fetch error:", err));
}

// 3. Update Live Telemetry Table
function updateFlowTable(batch) {
    const tbody = document.getElementById("flow-table-body");
    if (!tbody) return;

    batch.forEach(flow => {
        const tr = document.createElement("tr");
        tr.className = "border-b border-slate-800/60 hover:bg-slate-800/40 text-xs transition-colors duration-150";

        let badgeColor = "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
        if (flow.risk_level === "Critical") badgeColor = "bg-rose-500/10 text-rose-400 border border-rose-500/20";
        else if (flow.risk_level === "High") badgeColor = "bg-amber-500/10 text-amber-400 border border-amber-500/20";
        else if (flow.risk_level === "Medium") badgeColor = "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20";

        tr.innerHTML = `
            <td class="py-2.5 px-3 font-mono text-slate-400">${flow.timestamp.split(" ")[1] || flow.timestamp}</td>
            <td class="py-2.5 px-3 font-mono text-sky-400 font-medium">${flow.src_ip}</td>
            <td class="py-2.5 px-3 font-mono text-slate-300">${flow.dst_ip}:${flow.dst_port}</td>
            <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-medium ${badgeColor}">
                    ${flow.label}
                </span>
            </td>
            <td class="py-2.5 px-3 font-bold font-mono-num ${flow.risk_score >= 80 ? 'text-rose-400' : (flow.risk_score >= 60 ? 'text-amber-400' : 'text-emerald-400')}">
                ${flow.risk_score}
            </td>
            <td class="py-2.5 px-3 text-purple-300 font-medium">
                ${flow.predicted_next_stage}
            </td>
            <td class="py-2.5 px-3 font-mono text-amber-400">
                ${flow.tti_minutes}m
            </td>
        `;

        tbody.insertBefore(tr, tbody.firstChild);
        if (tbody.children.length > 25) {
            tbody.removeChild(tbody.lastChild);
        }
    });
}

// 4. Update Risk Score Gauge
function updateRiskGauge(risk) {
    const scoreElem = document.getElementById("risk-score-value");
    const badgeElem = document.getElementById("risk-level-badge");
    const threatBar = document.getElementById("risk-threat-bar");
    const stageBar = document.getElementById("risk-stage-bar");
    const assetBar = document.getElementById("risk-asset-bar");

    if (scoreElem) scoreElem.textContent = risk.risk_score;
    if (badgeElem) {
        badgeElem.textContent = risk.risk_level.toUpperCase();
        badgeElem.className = `px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide ${
            risk.risk_level === 'Critical' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' :
            (risk.risk_level === 'High' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30' :
            (risk.risk_level === 'Medium' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30' :
            'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'))
        }`;
    }

    if (risk.components) {
        if (threatBar) threatBar.style.width = `${Math.min(100, risk.components.threat_contribution * 2.5)}%`;
        if (stageBar) stageBar.style.width = `${Math.min(100, risk.components.kill_chain_contribution * 2.5)}%`;
        if (assetBar) assetBar.style.width = `${Math.min(100, risk.components.asset_contribution * 2.5)}%`;
    }
}

// 5. Update Forecast View Card
function updateForecastCard(forecast) {
    const stageElem = document.getElementById("forecast-next-stage");
    const probElem = document.getElementById("forecast-prob-val");
    const probBar = document.getElementById("forecast-prob-bar");
    const ttiElem = document.getElementById("forecast-tti-val");

    if (stageElem) stageElem.textContent = forecast.next_stage_name || "Normal Activity";
    if (probElem) probElem.textContent = `${Math.round((forecast.transition_probability || 0.1) * 100)}%`;
    if (probBar) probBar.style.width = `${Math.round((forecast.transition_probability || 0.1) * 100)}%`;
    if (ttiElem) ttiElem.textContent = `${forecast.estimated_time_to_impact_minutes || 45.0}m`;
}

// 6. Update Header Counters
function updateMetrics(metrics) {
    const totalFlows = document.getElementById("metric-total-flows");
    const threatActors = document.getElementById("metric-threat-actors");
    const compHosts = document.getElementById("metric-compromised-hosts");
    const totalAlerts = document.getElementById("metric-total-alerts");

    if (totalFlows) totalFlows.textContent = metrics.total_flows.toLocaleString();
    if (threatActors) threatActors.textContent = metrics.active_threat_actors;
    if (compHosts) compHosts.textContent = metrics.compromised_hosts;
    if (totalAlerts) totalAlerts.textContent = metrics.total_alerts;
}

// 7. Refresh Graph Node Statuses
function refreshGraphNodes() {
    fetch("/api/graph/current")
        .then(res => res.json())
        .then(data => {
            if (network && data.nodes) {
                networkData.nodes.update(data.nodes);
            }
        })
        .catch(err => console.error("Graph refresh error:", err));
}

// 8. What-If Counterfactual Sandbox
function runWhatIf() {
    const blockIp = document.getElementById("whatif-block-ip")?.checked || false;
    const quarantine = document.getElementById("whatif-quarantine")?.checked || false;
    const rateLimit = document.getElementById("whatif-rate-limit")?.checked || false;
    const zeroTrust = document.getElementById("whatif-zero-trust")?.checked || false;

    const payload = {
        block_source_ip: blockIp,
        quarantine_host: quarantine,
        rate_limit_ports: rateLimit ? [80, 443] : [],
        restrict_cross_subnet: zeroTrust,
    };

    fetch("/api/whatif", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    })
        .then(res => res.json())
        .then(data => {
            const resScore = document.getElementById("whatif-result-score");
            const resDelta = document.getElementById("whatif-result-delta");
            const resStatus = document.getElementById("whatif-result-status");

            if (resScore) resScore.textContent = data.simulated_risk_score;
            if (resDelta) {
                resDelta.textContent = `${data.delta_risk} (${data.risk_reduction_percentage}% reduction)`;
                resDelta.className = data.delta_risk < 0 ? "text-emerald-400 font-bold" : "text-gray-400";
            }
            if (resStatus) {
                resStatus.textContent = data.containment_status;
                resStatus.className = `text-xs px-2 py-1 rounded font-bold ${
                    data.containment_status === 'CONTAINED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                }`;
            }
        })
        .catch(err => console.error("What-if simulation error:", err));
}

// 9. Load SHAP Feature Attribution
function loadExplanation() {
    const container = document.getElementById("shap-bars-container");
    if (!container) return;

    fetch("/api/explain")
        .then(res => res.json())
        .then(data => {
            container.innerHTML = "";
            (data.top_features || []).forEach(f => {
                const item = document.createElement("div");
                item.className = "mb-3";
                item.innerHTML = `
                    <div class="flex justify-between text-xs mb-1">
                        <span class="text-gray-300 font-mono font-medium">${f.feature}</span>
                        <span class="text-cyan-400 font-bold">+${f.impact_percentage}%</span>
                    </div>
                    <div class="w-full bg-gray-800 rounded-full h-2">
                        <div class="bg-gradient-to-r from-blue-500 to-cyan-400 h-2 rounded-full" style="width: ${f.impact_percentage * 2.2}%"></div>
                    </div>
                    <p class="text-[11px] text-gray-500 mt-0.5">${f.explanation}</p>
                `;
                container.appendChild(item);
            });
        })
        .catch(err => console.error("Error loading explanation:", err));
}

// 10. Load Mitigation Rules
function loadMitigationRules() {
    const iptablesBlock = document.getElementById("mitigation-iptables");
    const suricataBlock = document.getElementById("mitigation-suricata");

    fetch("/api/mitigation")
        .then(res => res.json())
        .then(data => {
            if (iptablesBlock) {
                iptablesBlock.textContent = data.firewall_rules.iptables.join("\n");
            }
            if (suricataBlock) {
                suricataBlock.textContent = data.ids_signatures.suricata;
            }
        })
        .catch(err => console.error("Error loading mitigation:", err));
}
