import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import axios from 'axios'
import { io } from 'socket.io-client'
import { 
  Activity, Download, StopCircle, Target, Key, 
  AlertTriangle, Clock, CheckCircle2, TrendingUp 
} from 'lucide-react'

export default function CampaignDashboard() {
  const { campaignId } = useParams()
  const [campaign, setCampaign] = useState(null)
  const [findings, setFindings] = useState([])
  const [socket, setSocket] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Fetch initial campaign data
    fetchCampaign()
    fetchFindings()

    // Setup WebSocket connection
    const newSocket = io('http://localhost:5000')
    
    newSocket.on('connect', () => {
      console.log('WebSocket connected')
      newSocket.emit('subscribe_campaign', { campaign_id: campaignId })
    })

    newSocket.on('campaign_update', (data) => {
      setCampaign(data)
    })

    newSocket.on('new_finding', (finding) => {
      setFindings(prev => [finding, ...prev])
    })

    setSocket(newSocket)

    // Cleanup
    return () => {
      if (newSocket) {
        newSocket.emit('unsubscribe_campaign', { campaign_id: campaignId })
        newSocket.disconnect()
      }
    }
  }, [campaignId])

  const fetchCampaign = async () => {
    try {
      const response = await axios.get(`/api/campaigns/${campaignId}`)
      setCampaign(response.data)
      setLoading(false)
    } catch (error) {
      console.error('Failed to fetch campaign:', error)
      setLoading(false)
    }
  }

  const fetchFindings = async () => {
    try {
      const response = await axios.get(`/api/campaigns/${campaignId}/findings`)
      setFindings(response.data.findings)
    } catch (error) {
      console.error('Failed to fetch findings:', error)
    }
  }

  const handleStop = async () => {
    if (confirm('Are you sure you want to stop this campaign?')) {
      try {
        await axios.post(`/api/campaigns/${campaignId}/stop`)
        fetchCampaign()
      } catch (error) {
        alert('Failed to stop campaign: ' + error.message)
      }
    }
  }

  const handleDownloadReport = async () => {
    try {
      const response = await axios.get(`/api/campaigns/${campaignId}/report`, {
        responseType: 'blob'
      })
      
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `adbasher_report_${campaignId}.md`)
      document.body.appendChild(link)
      link.click()
      link.remove()
    } catch (error) {
      alert('Report not yet available')
    }
  }

  const formatElapsed = (seconds) => {
    const hours = Math.floor(seconds / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    const secs = Math.floor(seconds % 60)
    return `${hours}h ${minutes}m ${secs}s`
  }

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'text-red-500 bg-red-900/20 border-red-700'
      case 'high':
        return 'text-orange-500 bg-orange-900/20 border-orange-700'
      case 'medium':
        return 'text-amber-500 bg-amber-900/20 border-amber-700'
      default:
        return 'text-blue-500 bg-blue-900/20 border-blue-700'
    }
  }

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-emerald-500"></div>
          <p className="mt-4 text-slate-400">Loading campaign...</p>
        </div>
      </div>
    )
  }

  if (!campaign) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="text-center text-red-400">Campaign not found</div>
      </div>
    )
  }

  const phases = [
    { name: 'Reconnaissance', key: 'Reconnaissance' },
    { name: 'Cred Attacks', key: 'Credential Attacks' },
    { name: 'Post-Exploit', key: 'Post-Exploitation' },
    { name: 'Lateral Movement', key: 'Lateral Movement' },
    { name: 'Reporting', key: 'Generating Report' }
  ]

  const getPhaseStatus = (phaseName) => {
    if (campaign.current_phase === phaseName) return 'current'
    if (campaign.progress > phases.findIndex(p => p.key === phaseName) * 20) return 'complete'
    return 'pending'
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">{campaign.name}</h1>
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
          {campaign.status === 'running' && (
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
          <span className="text-lg font-semibold text-white">{campaign.current_phase}</span>
          <span className="text-2xl font-bold text-emerald-500">{campaign.progress}%</span>
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
            const status = getPhaseStatus(phase.key)
            return (
              <div key={idx} className="flex flex-col items-center">
                <div
                  className={`w-3 h-3 rounded-full mb-1 ${
                    status === 'complete' ? 'bg-emerald-500' :
                    status === 'current' ? 'bg-blue-500 animate-pulse' :
                    'bg-slate-600'
                  }`}
                />
                <span className="text-xs text-slate-400">{phase.name}</span>
              </div>
            )
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
          <h2 className="text-xl font-semibold text-white flex items-center space-x-2">
            <TrendingUp className="h-5 w-5" />
            <span>Recent Findings</span>
            {campaign.status === 'running' && (
              <span className="text-xs text-slate-400">(Auto-refresh)</span>
            )}
          </h2>
        </div>

        <div className="divide-y divide-slate-700">
          {findings.length === 0 ? (
            <div className="p-12 text-center text-slate-500">
              <TrendingUp className="h-16 w-16 mx-auto mb-4 opacity-50" />
              <p>No findings yet. Campaign is in progress...</p>
            </div>
          ) : (
            findings.map((finding, idx) => (
              <div key={idx} className="p-6 hover:bg-slate-750 transition-colors">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${getSeverityColor(finding.severity)}`}>
                      {finding.severity?.toUpperCase()}
                    </span>
                    <span className="text-xs text-slate-500">
                      {finding.type === 'credential' ? '🔑 Credential' : '🚨 Vulnerability'}
                    </span>
                  </div>
                  {finding.timestamp && (
                    <span className="text-xs text-slate-500">
                      {new Date(finding.timestamp).toLocaleTimeString()}
                    </span>
                  )}
                </div>

                <h3 className="text-lg font-semibold text-white mb-2">{finding.title}</h3>

                {finding.details && (
                  <div className="space-y-1 text-sm">
                    {Object.entries(finding.details).map(([key, value]) => (
                      value && (
                        <div key={key} className="flex">
                          <span className="text-slate-400 w-32 capitalize">{key}:</span>
                          <span className="text-white font-mono">{String(value)}</span>
                        </div>
                      )
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
