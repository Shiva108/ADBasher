import { Link } from 'react-router-dom'
import { Shield, Activity } from 'lucide-react'

export default function Navigation() {
  return (
    <nav className="bg-slate-800 border-b border-slate-700">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center">
            <Link to="/" className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-emerald-500" />
              <span className="text-xl font-bold text-white">ADBasher</span>
            </Link>
          </div>
          
          <div className="flex items-center space-x-4">
            <Link
              to="/"
              className="text-slate-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium"
            >
              <Activity className="inline h-4 w-4 mr-1" />
              Campaigns
            </Link>
            
            <Link
              to="/new-campaign"
              className="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-md text-sm font-medium transition-colors"
            >
              New Campaign
            </Link>
          </div>
        </div>
      </div>
    </nav>
  )
}
