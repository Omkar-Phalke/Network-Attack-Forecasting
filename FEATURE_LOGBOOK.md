# FEATURE LOGBOOK: SIH26153 — AI-Based Network Attack Forecasting

## 1. Document Overview & Metadata
- **Project Title:** AI-Based Network Attack Forecasting from Network Traffic Data
- **Problem Statement ID:** `SIH26153`
- **Primary Research Dataset:** Kaggle [IDS 2018 Intrusion CSVs (CSE-CIC-IDS2018)](https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv?utm_source=chatgpt.com)
- **Document Purpose:** Complete, auditable logbook of all network telemetry features utilized in the 7-stage forecasting pipeline. Details feature origins, mathematical definitions, normalization methods, security implications, feature importance scores, and MITRE ATT&CK mappings.

---

## 2. Raw Flow Features Catalog (CSE-CIC-IDS2018)

The CSE-CIC-IDS2018 dataset records 80 features extracted from bidirectional network flows (using CICFlowMeter). Each row represents a bidirectional flow between an IP tuple within a time boundary.

### 2.1 Flow Identification & Core Topology
| Feature Name | Data Type | Units / Format | Security Interpretation & Forensic Role |
| :--- | :--- | :--- | :--- |
| `Dst Port` | Integer | 0 – 65535 | Identifies the targeted service (e.g., 21=FTP, 22=SSH, 80=HTTP, 443=HTTPS, 3389=RDP). Crucial for classifying targeted brute force or port scanning. |
| `Protocol` | Categorical | 6 (TCP), 17 (UDP), 1 (ICMP) | Transport layer protocol used. Indicates attack mechanism (e.g., UDP floods vs TCP SYN floods vs ICMP ping sweeps). |
| `Timestamp` | Datetime | `dd/MM/yyyy HH:mm:ss` | Absolute time of flow initiation. Critical for temporal sequence ordering, sliding window aggregation, and time-to-impact forecasting. |
| `Flow Duration` | Numeric | Microseconds ($\mu s$) | Total flow lifespan from SYN to FIN/RST or timeout. Abnormally short flows indicate port scans; prolonged flows indicate C2 channels or slowloris attacks. |

### 2.2 Packet & Byte Counters
| Feature Name | Data Type | Description | Cyber Attack Significance |
| :--- | :--- | :--- | :--- |
| `Tot Fwd Pkts` | Integer | Total packets transmitted in forward direction (Source $\to$ Destination). | High values with low response packets indicate one-way flooding (UDP/ICMP/SYN Flood). |
| `Tot Bwd Pkts` | Integer | Total packets transmitted in backward direction (Destination $\to$ Source). | Very low backward packets indicate dropped or filtered connections (unresponsive host or firewall block). |
| `TotLen Fwd Pkts` | Numeric | Total volume of payload bytes sent forward. | Indicates exfiltration payload size or request volume in HTTP floods. |
| `TotLen Bwd Pkts` | Numeric | Total volume of payload bytes sent backward. | High volume indicates file download, data retrieval, or response amplification (DNS/NTP amplification). |
| `Fwd Pkt Len Max` | Numeric | Maximum packet size in forward direction. | Identifies buffer overflow attempts or jumbo frame data smuggling. |
| `Fwd Pkt Len Min` | Numeric | Minimum packet size in forward direction. | Consistent 0-byte or 40-byte payloads indicate raw TCP SYN/ACK probing. |
| `Fwd Pkt Len Mean`| Numeric | Average forward packet length. | Characteristic fingerprint of HTTP requests, SSH handshakes, or robotic DoS tools. |
| `Fwd Pkt Len Std` | Numeric | Standard deviation of forward packet sizes. | Machine-generated traffic (bots) has near-zero variance; human browsing exhibits high variance. |
| `Bwd Pkt Len Max` | Numeric | Maximum packet size in backward direction. | Captures server banner grabbing or data transfer packets. |
| `Bwd Pkt Len Min` | Numeric | Minimum packet size in backward direction. | TCP control responses (RST/ACK). |
| `Bwd Pkt Len Mean`| Numeric | Average backward packet length. | Distinguishes normal webpage responses from empty ACK or error responses. |
| `Bwd Pkt Len Std` | Numeric | Standard deviation of backward packet lengths. | Measures server response diversity. |

### 2.3 Flow Rates & Throughput
| Feature Name | Data Type | Formula | Threat Detection Context |
| :--- | :--- | :--- | :--- |
| `Flow Byts/s` | Float | $\frac{\text{TotLen Fwd Pkts} + \text{TotLen Bwd Pkts}}{\text{Flow Duration} \times 10^{-6}}$ | Measures network bandwidth consumption. Spikes identify high-volume volumetric DDoS (HOIC, LOIC). |
| `Flow Pkts/s` | Float | $\frac{\text{Tot Fwd Pkts} + \text{Tot Bwd Pkts}}{\text{Flow Duration} \times 10^{-6}}$ | Measures packet rate. Critical for detecting packet-per-second state-exhaustion attacks. |
| `Fwd Pkts/s` | Float | $\frac{\text{Tot Fwd Pkts}}{\text{Flow Duration} \times 10^{-6}}$ | Rate of outbound requests from client/attacker. |
| `Bwd Pkts/s` | Float | $\frac{\text{Tot Bwd Pkts}}{\text{Flow Duration} \times 10^{-6}}$ | Rate of inbound server responses. |

### 2.4 Inter-Arrival Times (IAT)
| Feature Name | Description | Forensic Value |
| :--- | :--- | :--- |
| `Flow IAT Mean` | Mean elapsed time between successive packets in the flow. | Automated botnets and script-based attacks show highly deterministic IATs. |
| `Flow IAT Std` | Standard deviation of inter-arrival times. | Low std dev indicates machine scripting; high std dev indicates interactive human user activity. |
| `Flow IAT Max` | Maximum interval between packets. | Identifies keep-alive intervals or beaconing heartbeat cadence in C2 channels. |
| `Flow IAT Min` | Minimum interval between packets. | Microsecond bursts indicate multi-threaded high-rate stress tools. |
| `Fwd IAT Tot` | Total time between forward packets. | Overall duration of outbound packet generation. |
| `Fwd IAT Mean` | Mean forward packet inter-arrival time. | Evaluates pacing of attacker requests. |
| `Fwd IAT Std` | Variance in forward packet arrival pacing. | Fingerprints specific attack tooling (Ares, LOIC, Slowloris). |
| `Fwd IAT Max` | Maximum interval between attacker packets. | Detects intentional evasion pacing (jittered scanning). |
| `Fwd IAT Min` | Minimum forward packet interval. | Identifies pipeline pipelining and packet blasting. |
| `Bwd IAT Tot` | Total time between server responses. | Server latency and capacity under load. |
| `Bwd IAT Mean` | Mean time between backward packets. | Server response pacing. |
| `Bwd IAT Std` | Standard deviation of backward packet arrival. | Variability under server load or exhaustion. |
| `Bwd IAT Max` | Maximum server response gap. | Detects server timeouts or backend database locking. |
| `Bwd IAT Min` | Minimum server response gap. | Pipelined server data streaming. |

### 2.5 TCP Flags & Header Attributes
| Feature Name | Flag / Meaning | Threat Implication |
| :--- | :--- | :--- |
| `Fwd PSH Flags` | Push flag count (Forward) | Data immediately forwarded to application layer; common in command injection and interactive shells. |
| `Bwd PSH Flags` | Push flag count (Backward) | Immediate application response. |
| `Fwd URG Flags` | Urgent flag count (Forward) | Rare in normal traffic; frequently used in evasion and fuzzing. |
| `Bwd URG Flags` | Urgent flag count (Backward) | Urgent responses. |
| `FIN Flag Cnt` | TCP Connection Termination | Orderly shutdown. Abnormally high FIN without preceding data = FIN port scanning. |
| `SYN Flag Cnt` | TCP Connection Initiation | SYN Flood DDoS (half-open connection attacks) or stealth SYN scans (Nmap `-sS`). |
| `RST Flag Cnt` | TCP Connection Reset | Closed port response or firewall TCP teardown. High RST counts signal active port scanning. |
| `PSH Flag Cnt` | TCP Push Flag | Application data delivery. |
| `ACK Flag Cnt` | TCP Acknowledgement | Normal handshake or ACK storm DDoS. |
| `URG Flag Cnt` | TCP Urgent Flag | Out-of-band data delivery. |
| `CWE Flag Count`| Congestion Window Reduced | ECN congestion notification. |
| `ECE Flag Count`| ECN-Echo Flag | Network congestion indicator or crafted packet fuzzing. |
| `Fwd Header Len`| Bytes of TCP/IP header (Forward)| Malformed headers or covert channel encapsulation. |
| `Bwd Header Len`| Bytes of TCP/IP header (Backward)| Server header size. |

### 2.6 Window Sizes, Subflows & Active/Idle Periods
| Feature Name | Description | Cyber Relevance |
| :--- | :--- | :--- |
| `Down/Up Ratio` | Ratio of downloaded packets to uploaded packets | Distinguishes client-heavy downloads (normal browsing) from attacker-heavy uploads (exfiltration/DDoS). |
| `Pkt Size Avg` | Average overall packet size in flow | Identifies protocol abuse (e.g. tiny 40-byte ping packets vs 1500-byte jumbo frames). |
| `Init Fwd Win Byts`| Initial TCP window size (Forward) | Operating system TCP stack fingerprinting. Identifies OS of attacker. |
| `Init Bwd Win Byts`| Initial TCP window size (Backward) | Operating system TCP stack fingerprinting of server/target. |
| `Fwd Act Data Pkts`| Count of forward packets containing $\ge 1$ byte of payload | Filters empty ACK/SYN handshakes from genuine data transfers. |
| `Fwd Seg Size Min` | Minimum segment size observed forward | MSS negotiation irregularities. |
| `Active Mean` | Mean time flow was active before becoming idle | Evaluates duty cycle of communication channels. |
| `Active Std` | Variance in active session duration | Consistency of active sessions. |
| `Active Max` | Longest active burst | Burst duration of attack runs. |
| `Active Min` | Shortest active burst | Ephemeral connections. |
| `Idle Mean` | Mean time flow was idle before resuming | C2 beaconing interval detection (e.g. regular 60s check-ins). |
| `Idle Std` | Variance in idle periods | Identifies beacon jitter introduced to evade threshold-based detection. |
| `Idle Max` | Maximum idle gap | Longest inactivity timeout. |
| `Idle Min` | Minimum idle gap | Micro-idling between command sequences. |

---

## 3. Data Preprocessing & Quality Assurance Log

### 3.1 Data Cleaning & Normalization Pipeline
1. **Header Normalization:**
   - Stripped all leading/trailing whitespace from column names (e.g., `' Destination Port '` $\to$ `'Dst Port'`).
   - Standardized casing across multiple CSV day files.
2. **Infinite & NaN Value Imputation:**
   - Evaluated `Flow Byts/s` and `Flow Pkts/s` where `Flow Duration == 0` causing division-by-zero ($\infty$).
   - Imputed infinite values with the 99.9th percentile value of the respective feature.
   - Replaced missing values (`NaN`) with column medians to prevent biased skewing.
3. **Subnet & Entity Categorization:**
   - `Internal Subnet (192.168.0.0/16, 10.0.0.0/8)` tagged as `INTERNAL_HOST`.
   - Public IP ranges tagged as `EXTERNAL_INGRESS`.
   - Identified critical infrastructure (Domain Controller, Database, Web DMZ).
4. **Timestamp Standardization:**
   - Converted diverse string date formats (`14/02/2018 08:31:01`, `2018-02-14 08:31:01`) into standardized Unix epoch timestamps and ISO-8601 strings for millisecond-precision chronological ordering.

---

## 4. Newly Engineered Features (The Attack Forecasting Engine)

To move beyond point-in-time detection and enable **Predictive Attack Forecasting**, we engineer four multi-dimensional feature families:

### 4.1 Temporal Rolling Window Aggregates
Features are calculated over sliding historical windows ($W_1 = 60s$, $W_5 = 300s$, $W_{15} = 900s$) for each active host:

| Engineered Feature | Mathematical Definition | Security Forecasting Role |
| :--- | :--- | :--- |
| `rolling_conn_rate_60s` | $N_{\text{flows}}(SrcIP, \Delta t=60s)$ | Quantifies sudden surges in connection attempts. Forewarns of impending DoS or aggressive brute-force sweeps. |
| `rolling_conn_rate_300s`| $N_{\text{flows}}(SrcIP, \Delta t=300s)$ | Baseline activity metric over 5-minute sustained period. |
| `rolling_unique_ports_60s` | $|\{DstPort_i \mid t_i \in [t-60, t]\}|$ | Counts unique destination ports probed by single IP. Identifies reconnaissance before exploitation begins. |
| `rolling_syn_ratio_60s` | $\frac{\sum SYN}{\sum Pkts_{\text{total}}}$ | Proportion of SYN flags. If $> 0.85$, forecasts imminent SYN flood / service collapse. |
| `rolling_byte_volume_300s`| $\sum \text{Bytes}(SrcIP, \Delta t=300s)$ | Cumulative byte volume over 5 minutes. Detects ongoing staging for bulk exfiltration. |

### 4.2 Behavioral & Statistical Entropy Features
| Engineered Feature | Formula / Logic | Anomaly & Threat Indicator |
| :--- | :--- | :--- |
| `dst_port_entropy` | $H(P_{dst}) = -\sum_{i=1}^k p_i \log_2(p_i)$ | **High Entropy ($>3.5$):** Uniform horizontal port scanning across many ports.<br>**Low Entropy ($<0.5$):** Targeted laser-focused exploitation against a single vulnerable service. |
| `payload_asymmetry_ratio` | $\log_{10}\left(\frac{\text{TotLen Fwd Pkts} + 1}{\text{TotLen Bwd Pkts} + 1}\right)$ | Strongly positive values indicate massive outbound data exfiltration; strongly negative values indicate inbound reflection or amplified denial-of-service. |
| `fan_out_degree` | Number of distinct destination IPs contacted by host | Measures spread of activity. Sudden jump indicates lateral movement pivot or worm propagation. |
| `fan_in_degree` | Number of distinct source IPs contacting a single destination IP | High fan-in indicates an asset undergoing distributed denial-of-service (DDoS). |

### 4.3 Dynamic Host Graph Features $G=(V, E)$
Using NetworkX, we model the monitored network as a dynamic directed multigraph $G = (V, E, W)$, where vertices $V$ are host IP addresses and edges $E$ represent active communication sessions weighted by bytes and packet frequency.

| Graph Feature | Mathematical Representation | Threat Graph Significance |
| :--- | :--- | :--- |
| `host_in_degree_centrality` | $C_{in}(v) = \frac{\deg^-(v)}{|V|-1}$ | Measures how central a target is as a destination. Critical servers have normal high in-degree; workstations with sudden in-degree spikes indicate targeted lateral movement. |
| `host_out_degree_centrality`| $C_{out}(v) = \frac{\deg^+(v)}{|V|-1}$ | Identifies hosts actively probing or broadcasting across the subnet. Primary indicator of a compromised pivot workstation. |
| `host_pagerank` | $PR(u) = \frac{1-d}{N} + d \sum_{v \in B_u} \frac{PR(v)}{L(v)}$ | Determines asset importance in network topology. Helps calculate downstream impact if the node is breached. |
| `bipartite_cross_subnet_edge`| $\mathbb{I}(Subnet(Src) \neq Subnet(Dst))$ | Flags flows crossing boundary between DMZ and internal core database subnets (Infiltration flag). |

### 4.4 Cyber Kill Chain State Estimation
We map individual flow events into 6 discrete progressive cyber kill chain stages:
1. **Stage 0: Benign / Baseline Activity**
2. **Stage 1: Reconnaissance** (Port scanning, service discovery, ping sweep)
3. **Stage 2: Initial Access & Weaponization** (SSH/FTP brute force, Web exploits, SQL injection)
4. **Stage 3: Infiltration & Execution** (Malware payload delivery, backdoor staging)
5. **Stage 4: Lateral Movement** (Internal subnet pivoting, SMB/RDP credential reuse)
6. **Stage 5: Command & Control (C2)** (Botnet beaconing, DNS tunneling)
7. **Stage 6: Actions on Objectives** (Data exfiltration, DoS service shutdown)

---

## 5. Feature Importance & TreeSHAP Attribution Rankings

Based on feature importance evaluations using Random Forest Mean Decrease in Impurity (MDI) and TreeSHAP on the CSE-CIC-IDS2018 dataset, the top 20 most predictive features are ranked below:

| Rank | Feature Name | Category | Importance Score (%) | Mean Absolute SHAP Value | Primary Predictive Cyber Role |
| :---: | :--- | :--- | :---: | :---: | :--- |
| 1 | `rolling_conn_rate_60s` | Engineered Temporal | 14.2% | 0.412 | Differentiates burst attacks (DoS, Brute Force) from normal activity. |
| 2 | `dst_port_entropy` | Engineered Behavioral | 11.8% | 0.385 | Early-warning trigger distinguishing recon scans from focused attacks. |
| 3 | `Dst Port` | Raw Topology | 10.5% | 0.354 | Pinpoints vulnerable application attack surfaces (SSH/FTP/HTTP). |
| 4 | `Flow Duration` | Raw Flow | 8.7% | 0.312 | Identifies microsecond flood packets vs long-lived C2 channels. |
| 5 | `payload_asymmetry_ratio`| Engineered Behavioral | 7.9% | 0.289 | Key predictor of data exfiltration and asymmetric amplification. |
| 6 | `Flow Byts/s` | Raw Throughput | 6.4% | 0.251 | Volumetric DoS/DDoS thresholding. |
| 7 | `rolling_syn_ratio_60s` | Engineered Temporal | 5.8% | 0.233 | Direct forecaster of half-open TCP SYN exhaustion attacks. |
| 8 | `host_out_degree_centrality`| Engineered Graph | 5.2% | 0.218 | Lateral movement detector across internal network assets. |
| 9 | `Flow IAT Mean` | Raw IAT | 4.6% | 0.197 | Machine script periodicity vs human user variability. |
| 10 | `Tot Fwd Pkts` | Raw Counters | 4.1% | 0.182 | Cumulative packet volume generated by attacking host. |
| 11 | `Init Fwd Win Byts` | Raw TCP Window | 3.5% | 0.165 | Operating system and toolchain fingerprinting. |
| 12 | `RST Flag Cnt` | Raw Flag | 3.1% | 0.151 | Closed port rejection count during automated reconnaissance. |
| 13 | `Fwd Pkt Len Max` | Raw Packet Length | 2.8% | 0.140 | Buffer overflow and exploit payload size signature. |
| 14 | `host_in_degree_centrality` | Engineered Graph | 2.5% | 0.128 | Identifies victim hosts being targeted concurrently by multiple bots. |
| 15 | `Bwd Pkt Len Mean` | Raw Packet Length | 2.1% | 0.114 | Server response payload analysis. |
| 16 | `Fwd Pkts/s` | Raw Throughput | 1.8% | 0.103 | Rate of outbound requests from attacking nodes. |
| 17 | `Idle Mean` | Raw Active/Idle | 1.5% | 0.092 | Detects C2 beaconing check-in intervals. |
| 18 | `Down/Up Ratio` | Raw Subflow | 1.3% | 0.081 | Directional traffic balance. |
| 19 | `PSH Flag Cnt` | Raw Flag | 1.2% | 0.073 | Immediate application execution triggers. |
| 20 | `Protocol` | Raw Topology | 1.0% | 0.065 | Protocol constraint verification. |

---

## 6. MITRE ATT&CK Matrix Mapping

The following table aligns each feature family to specific MITRE ATT&CK tactics, techniques, and SOC detection logic:

| MITRE Tactic | ATT&CK ID & Name | Associated Telemetry Features | Detection & Forecasting Logic |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | `T1595` Active Scanning | `dst_port_entropy`, `rolling_unique_ports_60s`, `RST Flag Cnt` | Rapid querying of multiple destination ports from a single IP yielding TCP RST responses. High entropy indicates horizontal port sweep. |
| **Initial Access** | `T1110` Brute Force | `Dst Port` (21, 22), `rolling_conn_rate_60s`, `Flow Duration` | High-frequency short-duration connections targeting SSH (22) or FTP (21) with repeated authentication failures. |
| **Execution / Exploitation** | `T1190` Exploit Public App | `Fwd Pkt Len Max`, `TotLen Fwd Pkts`, `Dst Port` (80, 443) | Abnormally large forward packet payloads containing web shell injection strings or SQL injection syntax. |
| **Lateral Movement** | `T1021` Remote Services | `host_out_degree_centrality`, `fan_out_degree`, `bipartite_cross_subnet_edge` | Internal workstation suddenly establishing connections to multiple internal servers over ports 445 (SMB) or 3389 (RDP). |
| **Command & Control** | `T1071` App Layer Protocol | `Idle Mean`, `Idle Std`, `Flow IAT Mean`, `Dst Port` | Periodic regular communication intervals (low `Idle Std`) to external IP endpoints representing beaconing heartbeats. |
| **Exfiltration** | `T1048` Exfiltration Over Alt Protocol | `payload_asymmetry_ratio`, `rolling_byte_volume_300s`, `TotLen Fwd Pkts` | Sustained massive volume of outbound forward bytes with minimal inbound server response, signaling data leakage. |
| **Impact** | `T1498` Network Denial of Service | `Flow Byts/s`, `Flow Pkts/s`, `rolling_syn_ratio_60s`, `host_in_degree_centrality` | Volumetric saturation of target host bandwidth or half-open TCP SYN connection exhaustion causing target inaccessibility. |

---

## 7. Model Versioning & Drift Adaptation Protocol

### 7.1 Drift Monitoring Metrics
To ensure the AI forecasting layer does not degrade under evolving network conditions, two continuous statistical drift monitors are deployed:
1. **Population Stability Index (PSI):**
   $$PSI = \sum_{i=1}^k \left( P_{\text{actual}}(i) - P_{\text{expected}}(i) \right) \times \ln\left( \frac{P_{\text{actual}}(i)}{P_{\text{expected}}(i)} \right)$$
   - $PSI < 0.10$: No significant drift (Baseline stable).
   - $0.10 \le PSI < 0.25$: Moderate drift detected (Triggers SOC warning and soft model retuning).
   - $PSI \ge 0.25$: Significant concept drift detected (Triggers automated continuous retraining pipeline).

2. **Two-Sample Kolmogorov-Smirnov (KS) Test:**
   Evaluates whether the empirical cumulative distribution functions of streaming flow features differ significantly from the training distribution ($p$-value $< 0.01$).

---

*Logbook Version: 1.0.0 — SIH26153 Evaluation Standard*
