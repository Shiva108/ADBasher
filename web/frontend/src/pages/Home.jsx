import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import api from "../utils/api";
import {
  PlayCircle,
  Clock,
  CheckCircle,
  XCircle,
  TrendingUp,
} from "lucide-react";

export default function Home() {
  const [campaigns, setCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCampaigns = async () => {
      try {
        const data = await api.get("/campaigns");
        setCampaigns(data.campaigns || []);
        setLoading(false);
      } catch (error) {
        console.error("Failed to fetch campaigns:", error);
        setLoading(false);
      }
    };

    fetchCampaigns();
    const interval = setInterval(fetchCampaigns, 5000); // Auto-refresh every 5s
    return () => clearInterval(interval);
  }, []);

  const getStatusIcon = (status) => {
    switch (status) {
      case "running":
        return <PlayCircle className="h-5 w-5 text-blue-500 animate-pulse" />;
      case "completed":
        return <CheckCircle className="h-5 w-5 text-emerald-500" />;
      case "failed":
        return <XCircle className="h-5 w-5 text-red-500" />;
      default:
        return <Clock className="h-5 w-5 text-slate-400" />;
    }
  };

  const formatElapsed = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
  };

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-emerald-500"></div>
          <p className="mt-4 text-slate-400">Loading campaigns...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">
          Penetration Test Campaigns
        </h1>
        <p className="text-slate-400">
          Manage and monitor Active Directory assessments
        </p>
      </div>

      {campaigns.length === 0 ? (
        <div className="bg-slate-800 rounded-lg p-12 text-center border border-slate-700">
          <TrendingUp className="h-16 w-16 text-slate-600 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">
            No campaigns yet
          </h3>
          <p className="text-slate-400 mb-6">
            Create your first penetration test campaign to get started
          </p>
          <Link
            to="/new-campaign"
            className="inline-block bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-3 rounded-md font-medium transition-colors"
          >
            Create Campaign
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {campaigns.map((campaign) => (
            <Link
              key={campaign.campaign_id}
              to={`/campaign/${campaign.campaign_id}`}
              className="bg-slate-800 rounded-lg p-6 border border-slate-700 hover:border-emerald-500 transition-colors"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-2">
                  {getStatusIcon(campaign.status)}
                  <span className="text-sm font-medium text-slate-400 capitalize">
                    {campaign.status}
                  </span>
                </div>
                <span className="text-xs text-slate-500">
                  {formatElapsed(campaign.elapsed_seconds)}
                </span>
              </div>

              <h3 className="text-lg font-semibold text-white mb-2">
                {campaign.name}
              </h3>

              <div className="mb-4">
                <div className="flex justify-between text-sm text-slate-400 mb-1">
                  <span>{campaign.current_phase}</span>
                  <span>{campaign.progress}%</span>
                </div>
                <div className="w-full bg-slate-700 rounded-full h-2">
                  <div
                    className="bg-emerald-500 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${campaign.progress}%` }}
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4 text-center">
                <div>
                  <div className="text-2xl font-bold text-white">
                    {campaign.statistics?.targets || 0}
                  </div>
                  <div className="text-xs text-slate-400">Targets</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-emerald-500">
                    {campaign.statistics?.credentials || 0}
                  </div>
                  <div className="text-xs text-slate-400">Creds</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-amber-500">
                    {campaign.statistics?.vulnerabilities || 0}
                  </div>
                  <div className="text-xs text-slate-400">Vulns</div>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
