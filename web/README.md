# ADBasher Web Dashboard

## One-Click Launch 🚀

Transform ADBasher into a modern, point-and-click Active Directory penetration testing platform.

### Quick Start

```bash
# 1. Start the dashboard
docker-compose up -d

# 2. Open browser
http://localhost:3000

# 3. Create your first campaign!
```

That's it! The web interface will guide you through the rest.

---

## Features

### ✨ Campaign Creation Wizard

- **4-step guided setup** - Details → Targets → Settings → Review
- **Smart validation** - Prevents misconfigurations
- **Pre-built templates** - Stealth, Balanced, Aggressive profiles
- **Visual OpSec controls** - Easy attack customization

### 📊 Real-Time Dashboard

- **Live progress tracking** - See attacks as they happen
- **WebSocket updates** - Instant notifications
- **Statistics panel** - Targets, credentials, vulnerabilities
- **Phase indicators** - Know exactly where you are

### 🔍 Interactive Findings

- **Auto-refresh** - New findings appear instantly
- **Severity filtering** - Focus on critical issues
- **Detailed drill-down** - Click any finding for full details
- **Export options** - PDF, Markdown, STIX 2.1

### 🎯 One-Click Reporting

- **Executive summary** - PDF generation
- **Technical report** - Markdown with full details
- **IOC export** - STIX 2.1 for threat intelligence
- **Remediation checklist** - Actionable next steps

---

## Architecture

```text
┌─────────────────────────────────────┐
│  React Dashboard (Port 3000)        │
│  - Campaign Wizard                  │
│  - Real-time Attack Viewer          │
│  - Interactive Reports              │
└──────────────┬──────────────────────┘
               │ WebSocket + REST API
┌──────────────▼──────────────────────┐
│  Flask Backend (Port 5000)          │
│  - Campaign Management              │
│  - Attack Orchestration             │
│  - Findings API                     │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  ADBasher Core (Existing)           │
│  - 106+ Attack Modules              │
│  - Database (SQLite)                │
│  - Reporting Engine                 │
└─────────────────────────────────────┘
```

---

## API Endpoints

### Campaigns

- `POST /api/campaigns` - Create new campaign
- `GET /api/campaigns` - List all campaigns
- `GET /api/campaigns/<id>` - Get campaign status
- `POST /api/campaigns/<id>/stop` - Stop campaign
- `GET /api/campaigns/<id>/findings` - Get findings
- `GET /api/campaigns/<id>/report` - Download report

### WebSocket Events

- `subscribe_campaign` - Subscribe to campaign updates
- `campaign_update` - Campaign status changed
- `new_finding` - New finding discovered

---

## Development

### Manual Setup (without Docker)

**Backend**:

```bash
cd web
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5000
```

**Frontend**:

```bash
cd web/frontend
npm install
npm run dev
# Runs on http://localhost:3000
```

### Project Structure

```text
ADBasher/
├── web/
│   ├── app.py                 # Flask backend
│   ├── requirements.txt
│   └── frontend/
│       ├── src/
│       │   ├── pages/
│       │   │   ├── Home.jsx          # Campaign list
│       │   │   ├── NewCampaign.jsx   # Creation wizard
│       │   │   └── CampaignDashboard.jsx  # Live dashboard
│       │   ├── components/
│       │   │   └── Navigation.jsx    # Top nav bar
│       │   ├── App.jsx
│       │   └── main.jsx
│       ├── package.json
│       └── vite.config.js
├── docker-compose.yml         # One-command deployment
├── Dockerfile.backend
└── core/                      # Existing ADBasher modules
```

---

## Usage Guide

### Creating a Campaign

1. **Navigate to "New Campaign"**
2. **Step 1: Details**

   - Enter campaign name
   - Specify target domain
   - Add notification email (optional)

3. **Step 2: Targets**

   - Add IP addresses or CIDR ranges
   - Optionally provide credentials
   - One target per line

4. **Step 3: Settings**

   - Choose attack profile (Stealth/Balanced/Aggressive)
   - Enable/disable modules
   - Review OpSec settings

5. **Step 4: Review & Launch**
   - Verify all settings
   - Click "Launch Campaign"
   - Automatically redirects to dashboard

### Monitoring Progress

- **Progress bar** shows overall completion (0-100%)
- **Phase indicators** show current attack stage
- **Statistics** update in real-time
- **Findings panel** auto-refreshes every 5 seconds

### Stopping a Campaign

- Click the "Stop" button in the dashboard
- Confirms before stopping
- Generates partial report with findings so far

### Exporting Results

- Click "Report" button
- Downloads Markdown report immediately
- Use API for other formats (STIX, CSV)

---

## Configuration

### Attack Profiles

**Stealth Mode**:

- Randomized timing (5-30s delays)
- Single-threaded attacks
- Mimics normal user behavior
- Lowest detection risk

**Balanced** (Recommended):

- Moderate timing (2-10s delays)
- Parallel attacks (3 threads)
- Good balance of speed vs stealth
- Suitable for most assessments

**Aggressive**:

- Minimal timing (0.5-2s delays)
- Highly parallel (10+ threads)
- Fastest results
- Higher detection risk

### Modules

All modules are enabled by default except:

- **Persistence** - Disabled (requires manual opt-in)
- **Lateral Movement** - Optional (requires admin creds)

---

## Security Considerations

### Authentication

- **Currently**: No authentication (localhost only)
- **Production**: Add JWT authentication before exposing

### Authorization

- Upload proof of authorization in campaign wizard
- Store authorization documents with session

### Data Handling

- Credentials stored encrypted (Fernet)
- Session data isolated per campaign
- Automatic cleanup after 30 days

---

## Troubleshooting

### Backend won't start

```bash
# Check Python version
python --version  # Requires 3.10+

# Install dependencies
cd web && pip install -r requirements.txt
```

### Frontend won't start

```bash
# Check Node version
node --version  # Requires 18+

# Clear cache and reinstall
cd web/frontend
rm -rf node_modules package-lock.json
npm install
```

### WebSocket connection fails

- Ensure backend is running on port 5000
- Check browser console for errors
- Verify CORS settings in `app.py`

### Campaign stuck at 0%

- Check backend logs for errors
- Verify targets are reachable
- Ensure orchestrator is properly initialized

---

## Roadmap

### v1.1 (Next Release)

- [ ] User authentication (JWT)
- [ ] Team collaboration (multi-user)
- [ ] Email notifications
- [ ] Slack/Teams webhooks

### v1.2 (Future)

- [ ] AI attack suggestions
- [ ] Campaign comparison
- [ ] Mobile app
- [ ] Custom module builder

---

## Screenshots

> Note: Screenshots would include the wizard, dashboard, and findings panel.

---

## Contributing

Contributions welcome! Areas of interest:

- Additional attack profiles
- Custom UI themes
- Integration with other tools
- Documentation improvements

---

## License

Same as ADBasher core project.

---

## Support

For issues or questions:

1. Check troubleshooting section above
2. Review API documentation
3. Open GitHub issue with details

---

Built with ❤️ using Flask, React, and Socket.IO
