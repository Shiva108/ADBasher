import { useState, useEffect } from "react";
import { useParams } from "react-router-dom";
import api from "../utils/api";
import { io } from "socket.io-client";
import { SOCKET_URL } from "../config";
import { showError, showSuccess, showWarning } from "../utils/toast.jsx";
import toast from "react-hot-toast";
import Pagination from "../components/Pagination";
import {
  Activity,
  Download,
  StopCircle,
  Target,
  Key,
  AlertTriangle,
  Clock,
  CheckCircle2,
  TrendingUp,
  Search,
  Filter,
} from "lucide-react";

export default function CampaignDashboard() {
  const { campaignId } = useParams();
  const [campaign, setCampaign] = useState(null);
  const [findings, setFindings] = useState([]);
  const [socket, setSocket] = useState(null);
  const [loading, setLoading] = useState(true);

  // Pagination and filtering state
  const [currentPage, setCurrentPage] = useState(1);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const ITEMS_PER_PAGE = 10;

  useEffect(() => {
    // Fetch initial campaign data
    fetchCampaign();
    fetchFindings();

    // Setup WebSocket connection
    const newSocket = io(SOCKET_URL);

    newSocket.on("connect", () => {
      console.log("WebSocket connected");
      newSocket.emit("subscribe_campaign", { campaign_id: campaignId });
    });

    newSocket.on("campaign_update", (data) => {
      setCampaign(data);
    });

    newSocket.on("new_finding", (finding) => {
      setFindings((prev) => [finding, ...prev]);
    });

    setSocket(newSocket);

    // Cleanup
    return () => {
      if (newSocket) {
        newSocket.emit("unsubscribe_campaign", { campaign_id: campaignId });
        newSocket.disconnect();
      }
    };
  }, [campaignId]);

  const fetchCampaign = async () => {
    try {
      const data = await api.get(`/campaigns/${campaignId}`);
      setCampaign(data);
      setLoading(false);
    } catch (error) {
      showError("Failed to fetch campaign: " + error.message);
      setLoading(false);
    }
  };

  const fetchFindings = async () => {
    try {
      const data = await api.get(`/campaigns/${campaignId}/findings`);
      setFindings(data.findings);
    } catch (error) {
      showError("Failed to fetch findings: " + error.message);
    }
  };

  const handleStop = async () => {
    toast(
      (t) => (
        <div>
          <p className="font-semibold mb-2">Stop this campaign?</p>
          <p className="text-sm text-slate-300 mb-3">
            This will gracefully stop all running attacks.
          </p>
          <div className="flex space-x-2">
            <button
              onClick={async () => {
                toast.dismiss(t.id);
                try {
                  await api.post(`/campaigns/${campaignId}/stop`);
                  showSuccess("Campaign stopped successfully");
                  fetchCampaign();
                } catch (error) {
                  showError("Failed to stop campaign: " + error.message);
                }
              }}
              className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-sm"
            >
              Stop
            </button>
            <button
              onClick={() => toast.dismiss(t.id)}
              className="px-3 py-1 bg-slate-600 hover:bg-slate-700 text-white rounded text-sm"
            >
              Cancel
            </button>
          </div>
        </div>
      ),
      {
        duration: 5000,
        style: {
          background: "#1e293b",
          color: "#e2e8f0",
          border: "1px solid #475569",
        },
      }
    );
  };

  const handleDownloadReport = async () => {
    try {
      const response = await fetch(`/api/campaigns/${campaignId}/report`);
      if (!response.ok) throw new Error("Report not available");

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `adbasher_report_${campaignId}.md`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      showSuccess("Report downloaded successfully");
    } catch (error) {
      showWarning("Report not yet available");
    }
  };

  const formatElapsed = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    return `${hours}h ${minutes}m ${secs}s`;
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "text-red-500 bg-red-900/20 border-red-700";
      case "high":
        return "text-orange-500 bg-orange-900/20 border-orange-700";
      case "medium":
        return "text-amber-500 bg-amber-900/20 border-amber-700";
      default:
        return "text-blue-500 bg-blue-900/20 border-blue-700";
    }
  };

  // Filter and paginate findings
  const getFilteredFindings = () => {
    let filtered = findings;

    // Apply severity filter
    if (severityFilter !== "all") {
      filtered = filtered.filter(
        (f) => f.severity?.toLowerCase() === severityFilter
      );
    }

    // Apply search filter
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (f) =>
          f.title?.toLowerCase().includes(query) ||
          f.type?.toLowerCase().includes(query) ||
          JSON.stringify(f.details).toLowerCase().includes(query)
      );
    }

    return filtered;
  };

  const filteredFindings = getFilteredFindings();
  const totalPages = Math.ceil(filteredFindings.length / ITEMS_PER_PAGE);
  const paginatedFindings = filteredFindings.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [severityFilter, searchQuery]);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-emerald-500"></div>
          <p className="mt-4 text-slate-400">Loading campaign...</p>
        </div>
      </div>
    );
  }

  if (!campaign) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="text-center text-red-400">Campaign not found</div>
      </div>
    );
  }

  const phases = [
    { name: "Reconnaissance", key: "Reconnaissance" },
    { name: "Cred Attacks", key: "Credential Attacks" },
    { name: "Post-Exploit", key: "Post-Exploitation" },
    { name: "Lateral Movement", key: "Lateral Movement" },
    { name: "Reporting", key: "Generating Report" },
  ];

  const getPhaseStatus = (phaseName) => {
    if (campaign.current_phase === phaseName) return "current";
    if (campaign.progress > phases.findIndex((p) => p.key === phaseName) * 20)
      return "complete";
    return "pending";
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">
            {campaign.name}
          </h1>
          <div className="flex items-center space-x-4 text-sm text-slate-400">
            <span className="flex items-center space-x-1">
              <Clock className="h-4 w-4" />
              <span>{formatElapsed(campaign.elapsed_seconds)}</span>
            </span>
            <span className="flex items-center space-x-1">
              <Activity className="h-4 w-4" />
              <span className="capitalize">{campaign.status}</span>
            </span>
          </div>
        </div>

        <div className="flex space-x-3">
          {campaign.status === "running" && (
            <button
              onClick={handleStop}
              className="flex items-center space-x-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md transition-colors"
            >
              <StopCircle className="h-4 w-4" />
              <span>Stop</span>
            </button>
          )}

          <button
            onClick={handleDownloadReport}
            className="flex items-center space-x-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-md transition-colors"
          >
            <Download className="h-4 w-4" />
            <span>Report</span>
          </button>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-6">
        <div className="flex justify-between items-center mb-4">
          <span className="text-lg font-semibold text-white">
            {campaign.current_phase}
          </span>
          <span className="text-2xl font-bold text-emerald-500">
            {campaign.progress}%
          </span>
        </div>

        <div className="w-full bg-slate-700 rounded-full h-3 mb-4">
          <div
            className="bg-gradient-to-r from-emerald-600 to-emerald-400 h-3 rounded-full transition-all duration-500"
            style={{ width: `${campaign.progress}%` }}
          />
        </div>

        {/* Phase Indicators */}
        <div className="flex justify-between">
          {phases.map((phase, idx) => {
            const status = getPhaseStatus(phase.key);
            return (
              <div key={idx} className="flex flex-col items-center">
                <div
                  className={`w-3 h-3 rounded-full mb-1 ${
                    status === "complete"
                      ? "bg-emerald-500"
                      : status === "current"
                      ? "bg-blue-500 animate-pulse"
                      : "bg-slate-600"
                  }`}
                />
                <span className="text-xs text-slate-400">{phase.name}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm mb-1">Targets Discovered</p>
              <p className="text-3xl font-bold text-white">
                {campaign.statistics?.targets || 0}
              </p>
            </div>
            <Target className="h-12 w-12 text-slate-600" />
          </div>
        </div>

        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm mb-1">Credentials Found</p>
              <p className="text-3xl font-bold text-emerald-500">
                {campaign.statistics?.credentials || 0}
              </p>
            </div>
            <Key className="h-12 w-12 text-emerald-600" />
          </div>
        </div>

        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm mb-1">Vulnerabilities</p>
              <p className="text-3xl font-bold text-amber-500">
                {campaign.statistics?.vulnerabilities || 0}
              </p>
            </div>
            <AlertTriangle className="h-12 w-12 text-amber-600" />
          </div>
        </div>
      </div>

      {/* Findings */}
      <div className="bg-slate-800 rounded-lg border border-slate-700">
        <div className="px-6 py-4 border-b border-slate-700">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold text-white flex items-center space-x-2">
              <TrendingUp className="h-5 w-5" />
              <span>Findings ({filteredFindings.length})</span>
              {campaign.status === "running" && (
                <span className="text-xs text-slate-400">(Auto-refresh)</span>
              )}
            </h2>
          </div>

          {/* Search and Filter Controls */}
          <div className="flex space-x-3">
            {/* Search */}
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search findings..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
              />
            </div>

            {/* Severity Filter */}
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-400 pointer-events-none" />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="pl-10 pr-8 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:border-emerald-500 appearance-none cursor-pointer"
              >
                <option value="all">All Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
        </div>

        <div className="divide-y divide-slate-700">
          {paginatedFindings.length === 0 ? (
            <div className="p-12 text-center text-slate-500">
              <TrendingUp className="h-16 w-16 mx-auto mb-4 opacity-50" />
              <p>
                {findings.length === 0
                  ? "No findings yet. Campaign is in progress..."
                  : "No findings match your filters."}
              </p>
            </div>
          ) : (
            paginatedFindings.map((finding, idx) => (
              <div
                key={idx}
                className="p-6 hover:bg-slate-750 transition-colors"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-semibold border ${getSeverityColor(
                        finding.severity
                      )}`}
                    >
                      {finding.severity?.toUpperCase()}
                    </span>
                    <span className="text-xs text-slate-500">
                      {finding.type === "credential"
                        ? "🔑 Credential"
                        : "🚨 Vulnerability"}
                    </span>
                  </div>
                  {finding.timestamp && (
                    <span className="text-xs text-slate-500">
                      {new Date(finding.timestamp).toLocaleTimeString()}
                    </span>
                  )}
                </div>

                <h3 className="text-lg font-semibold text-white mb-2">
                  {finding.title}
                </h3>

                {finding.details && (
                  <div className="space-y-1 text-sm">
                    {Object.entries(finding.details).map(([key, value]) =>
                      value ? (
                        <div key={key} className="flex">
                          <span className="text-slate-400 w-32 capitalize">
                            {key}:
                          </span>
                          <span className="text-white font-mono">
                            {String(value)}
                          </span>
                        </div>
                      ) : null
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-6 py-4 border-t border-slate-700">
            <Pagination
              currentPage={currentPage}
              totalPages={totalPages}
              onPageChange={setCurrentPage}
            />
          </div>
        )}
      </div>
    </div>
  );
}
