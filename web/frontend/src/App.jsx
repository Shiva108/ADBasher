import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { lazy, Suspense } from "react";
import { Toaster } from "react-hot-toast";

// Lazy load route components for code splitting
const Home = lazy(() => import("./pages/Home"));
const NewCampaign = lazy(() => import("./pages/NewCampaign"));
const CampaignDashboard = lazy(() => import("./pages/CampaignDashboard"));

// Loading component
function LoadingFallback() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
      <div className="text-center">
        <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-emerald-500 mb-4"></div>
        <p className="text-slate-400">Loading...</p>
      </div>
    </div>
  );
}

function App() {
  return (
    <Router>
      <Toaster position="top-right" />
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        {/* Navigation */}
        <nav className="bg-slate-800/50 backdrop-blur-sm border-b border-slate-700">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center h-16">
              <a
                href="/"
                className="text-2xl font-bold text-emerald-500 hover:text-emerald-400 transition-colors"
              >
                ADBasher
              </a>
              <div className="text-slate-400 text-sm">
                Active Directory Penetration Testing Framework
              </div>
            </div>
          </div>
        </nav>

        {/* Routes with Suspense */}
        <Suspense fallback={<LoadingFallback />}>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/new-campaign" element={<NewCampaign />} />
            <Route
              path="/campaign/:campaignId"
              element={<CampaignDashboard />}
            />
          </Routes>
        </Suspense>
      </div>
    </Router>
  );
}

export default App;
