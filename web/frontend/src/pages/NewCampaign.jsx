import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import { ArrowRight, ArrowLeft, Shield, Target, Settings, Bell, CheckCircle } from 'lucide-react'

export default function NewCampaign() {
  const navigate = useNavigate()
  const [step, setStep] = useState(1)
  const [formData, setFormData] = useState({
    name: '',
    domain: '',
    targets: '',
    username: '',
    password: '',
    attack_profile: 'balanced',
    enable_post_exploit: true,
    enable_lateral_movement: false,
    notification_email: ''
  })

  const updateField = (field, value) => {
    setFormData({ ...formData, [field]: value })
  }

  const handleSubmit = async () => {
    try {
      // Convert targets string to array
      const targetsArray = formData.targets
        .split('\n')
        .map(t => t.trim())
        .filter(t => t.length > 0)

      const payload = {
        ...formData,
        targets: targetsArray
      }

      const response = await axios.post('/api/campaigns', payload)
      const campaignId = response.data.campaign_id

      // Navigate to campaign dashboard
      navigate(`/campaign/${campaignId}`)
    } catch (error) {
      alert('Failed to create campaign: ' + (error.response?.data?.error || error.message))
    }
  }

  const renderStep = () => {
    switch (step) {
      case 1:
        return (
          <div className="space-y-6">
            <div className="flex items-center space-x-3 mb-6">
              <Shield className="h-8 w-8 text-emerald-500" />
              <div>
                <h2 className="text-2xl font-bold text-white">Campaign Details</h2>
                <p className="text-slate-400">Basic information about this assessment</p>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Campaign Name *
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => updateField('name', e.target.value)}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:border-emerald-500"
                placeholder="Q4 2024 Security Assessment"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Domain Name *
              </label>
              <input
                type="text"
                value={formData.domain}
                onChange={(e) => updateField('domain', e.target.value)}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:border-emerald-500"
                placeholder="victim.local"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Notification Email (Optional)
              </label>
              <input
                type="email"
                value={formData.notification_email}
                onChange={(e) => updateField('notification_email', e.target.value)}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:border-emerald-500"
                placeholder="pentester@company.com"
              />
              <p className="mt-1 text-sm text-slate-500">
                Receive alerts when critical findings are discovered
              </p>
            </div>
          </div>
        )

      case 2:
        return (
          <div className="space-y-6">
            <div className="flex items-center space-x-3 mb-6">
              <Target className="h-8 w-8 text-emerald-500" />
              <div>
                <h2 className="text-2xl font-bold text-white">Target Configuration</h2>
                <p className="text-slate-400">Define attack targets and credentials</p>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Target IP Addresses / CIDR Ranges *
              </label>
              <textarea
                value={formData.targets}
                onChange={(e) => updateField('targets', e.target.value)}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:border-emerald-500 font-mono text-sm"
                rows={6}
                placeholder={'192.168.1.10\n10.0.0.0/24\ndc01.victim.local'}
              />
              <p className="mt-1 text-sm text-slate-500">
                One target per line. Supports IPs, CIDR notation, and hostnames.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Username (Optional)
                </label>
                <input
                  type="text"
                  value={formData.username}
                  onChange={(e) => updateField('username', e.target.value)}
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:border-emerald-500"
                  placeholder="Domain\\User"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Password (Optional)
                </label>
                <input
                  type="password"
                  value={formData.password}
                  onChange={(e) => updateField('password', e.target.value)}
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:border-emerald-500"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <div className="bg-blue-900/20 border border-blue-700 rounded-md p-4">
              <p className="text-sm text-blue-300">
                💡 <strong>Tip:</strong> Credentials are optional. ADBasher will attempt to discover
                and compromise credentials automatically.
              </p>
            </div>
          </div>
        )

      case 3:
        return (
          <div className="space-y-6">
            <div className="flex items-center space-x-3 mb-6">
              <Settings className="h-8 w-8 text-emerald-500" />
              <div>
                <h2 className="text-2xl font-bold text-white">Attack Configuration</h2>
                <p className="text-slate-400">Select attack modules and OpSec profile</p>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-3">
                Attack Profile
              </label>
              <div className="grid grid-cols-3 gap-4">
                {['stealth', 'balanced', 'aggressive'].map((profile) => (
                  <button
                    key={profile}
                    onClick={() => updateField('attack_profile', profile)}
                    className={`p-4 rounded-lg border-2 transition-all ${
                      formData.attack_profile === profile
                        ? 'border-emerald-500 bg-emerald-900/20'
                        : 'border-slate-700 bg-slate-800 hover:border-slate-600'
                    }`}
                  >
                    <div className="text-center">
                      <div className="text-lg font-semibold text-white capitalize mb-1">
                        {profile}
                      </div>
                      <div className="text-xs text-slate-400">
                        {profile === 'stealth' && 'Slow, randomized timing'}
                        {profile === 'balanced' && 'Recommended for most'}
                        {profile === 'aggressive' && 'Fast, more detectable'}
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              <label className="block text-sm font-medium text-slate-300">
                Attack Modules
              </label>

              <label className="flex items-center space-x-3 p-4 bg-slate-800 rounded-lg border border-slate-700 cursor-pointer hover:border-slate-600">
                <input
                  type="checkbox"
                  checked={formData.enable_post_exploit}
                  onChange={(e) => updateField('enable_post_exploit', e.target.checked)}
                  className="w-5 h-5 text-emerald-600 rounded focus:ring-emerald-500"
                />
                <div className="flex-1">
                  <div className="text-white font-medium">Post-Exploitation</div>
                  <div className="text-sm text-slate-400">
                   BloodHound, secretsdump, LSASS dumping (requires credentials)
                  </div>
                </div>
              </label>

              <label className="flex items-center space-x-3 p-4 bg-slate-800 rounded-lg border border-slate-700 cursor-pointer hover:border-slate-600">
                <input
                  type="checkbox"
                  checked={formData.enable_lateral_movement}
                  onChange={(e) => updateField('enable_lateral_movement', e.target.checked)}
                  className="w-5 h-5 text-emerald-600 rounded focus:ring-emerald-500"
                />
                <div className="flex-1">
                  <div className="text-white font-medium">Lateral Movement</div>
                  <div className="text-sm text-slate-400">
                    PSExec, WMIExec, SMBExec across network (requires admin)
                  </div>
                </div>
              </label>

              <div className="bg-amber-900/20 border border-amber-700 rounded-md p-4">
                <p className="text-sm text-amber-300">
                  ⚠️ <strong>Note:</strong> Persistence modules are disabled by default. 
                  They can be manually enabled from the dashboard after careful review.
                </p>
              </div>
            </div>
          </div>
        )

      case 4:
        return (
          <div className="space-y-6">
            <div className="flex items-center space-x-3 mb-6">
              <CheckCircle className="h-8 w-8 text-emerald-500" />
              <div>
                <h2 className="text-2xl font-bold text-white">Review & Launch</h2>
                <p className="text-slate-400">Confirm settings and start campaign</p>
              </div>
            </div>

            <div className="bg-slate-800 rounded-lg border border-slate-700 p-6 space-y-4">
              <div>
                <div className="text-sm text-slate-400">Campaign Name</div>
                <div className="text-lg text-white font-medium">{formData.name || 'Untitled Campaign'}</div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-slate-400">Domain</div>
                  <div className="text-white">{formData.domain || 'Not specified'}</div>
                </div>
                <div>
                  <div className="text-sm text-slate-400">Attack Profile</div>
                  <div className="text-white capitalize">{formData.attack_profile}</div>
                </div>
              </div>

              <div>
                <div className="text-sm text-slate-400 mb-1">Targets</div>
                <div className="bg-slate-900 rounded p-3 font-mono text-sm text-white max-h-32 overflow-y-auto">
                  {formData.targets || 'No targets specified'}
                </div>
              </div>

              <div>
                <div className="text-sm text-slate-400 mb-2">Enabled Modules</div>
                <div className="flex flex-wrap gap-2">
                  <span className="px-3 py-1 bg-emerald-900/30 text-emerald-400 rounded-full text-sm border border-emerald-700">
                    Reconnaissance
                  </span>
                  <span className="px-3 py-1 bg-emerald-900/30 text-emerald-400 rounded-full text-sm border border-emerald-700">
                    Credential Attacks
                  </span>
                  {formData.enable_post_exploit && (
                    <span className="px-3 py-1 bg-emerald-900/30 text-emerald-400 rounded-full text-sm border border-emerald-700">
                      Post-Exploitation
                    </span>
                  )}
                  {formData.enable_lateral_movement && (
                    <span className="px-3 py-1 bg-emerald-900/30 text-emerald-400 rounded-full text-sm border border-emerald-700">
                      Lateral Movement
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="bg-red-900/20 border border-red-700 rounded-md p-4">
              <p className="text-sm text-red-300">
                🚨 <strong>Warning:</strong> This will launch an active penetration test. 
                Ensure you have proper authorization before proceeding.
              </p>
            </div>
          </div>
        )

      default:
        return null
    }
  }

  const canProceed = () => {
    if (step === 1) {
      return formData.name && formData.domain
    }
    if (step === 2) {
      return formData.targets.trim().length > 0
    }
    return true
  }

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Progress Indicator */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="flex items-center">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center font-semibold ${
                  i <= step
                    ? 'bg-emerald-600 text-white'
                    : 'bg-slate-700 text-slate-400'
                }`}
              >
                {i}
              </div>
              {i < 4 && (
                <div
                  className={`w-24 h-1 ${
                    i < step ? 'bg-emerald-600' : 'bg-slate-700'
                  }`}
                />
              )}
            </div>
          ))}
        </div>
        <div className="flex justify-between mt-2">
          <span className="text-xs text-slate-400">Details</span>
          <span className="text-xs text-slate-400">Targets</span>
          <span className="text-xs text-slate-400">Settings</span>
          <span className="text-xs text-slate-400">Review</span>
        </div>
      </div>

      {/* Form Content */}
      <div className="bg-slate-800 rounded-lg p-8 border border-slate-700">
        {renderStep()}
      </div>

      {/* Navigation Buttons */}
      <div className="flex justify-between mt-6">
        <button
          onClick={() => setStep(step - 1)}
          disabled={step === 1}
          className="flex items-center space-x-2 px-6 py-3 bg-slate-700 text-white rounded-md hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>Back</span>
        </button>

        {step < 4 ? (
          <button
            onClick={() => setStep(step + 1)}
            disabled={!canProceed()}
            className="flex items-center space-x-2 px-6 py-3 bg-emerald-600 text-white rounded-md hover:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <span>Next</span>
            <ArrowRight className="h-4 w-4" />
          </button>
        ) : (
          <button
            onClick={handleSubmit}
            disabled={!canProceed()}
            className="flex items-center space-x-2 px-8 py-3 bg-emerald-600 text-white rounded-md hover:bg-emerald-700 font-semibold transition-colors text-lg disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <span>🚀 Launch Campaign</span>
          </button>
        )}
      </div>
    </div>
  )
}
