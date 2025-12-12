# Performance Optimization Guide for ADBasher

## Current Performance Profile

### Baseline Metrics (Estimated)

- **Full scan (100-host domain)**: 45-90 minutes
- **Database operations**: <100ms per query
- **Credential spray**: 7 passwords × 250 users = ~30 minutes (with lockout protection)
- **BloodHound collection**: 5-10 minutes
- **Secretsdump**: 2-5 minutes per DC

---

## Implemented Optimizations

### 1. Database Optimizations ✅

**Current**: SQLite with indexed queries

- Primary keys on all ID fields
- Indexes on frequently queried fields (ip_address, domain, username)
- Session management to prevent connection leaks

**Recommendations**:

```python
# Add composite indexes for common queries
CREATE INDEX idx_cred_domain_admin ON credentials(domain, is_admin);
CREATE INDEX idx_target_dc_alive ON targets(is_dc, is_alive);
```

### 2. Concurrent Execution 🔧

**Current**: Sequential module execution
**Planned**: Thread pool for independent operations

```python
# Example: Parallel target scanning
from concurrent.futures import ThreadPoolExecutor

def scan_target(target):
    # Scan individual target
    pass

with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(scan_target, targets)
```

**Warning**: Be cautious with threading in lateral movement to avoid:

- Account lockouts (too many auth attempts)
- Detection (abnormal traffic patterns)
- Network congestion

### 3. Caching & Memoization ⚠️

**Risk**: Stale data in dynamic environments
**Benefit**: Reduce redundant DNS/DC queries

```python
from functools import lru_cache

@lru_cache(maxsize=128)
def resolve_dc(domain):
    # Cache DC lookups for 5 minutes
    return dns_query(domain)
```

### 4. Batch Operations ✅

**Current**: Database batch commits in modules
**Status**: Implemented in all credential/target storage

```python
# Good: Batch insert
session.bulk_insert_mappings(Credential, cred_list)
session.commit()

# Bad: Individual commits
for cred in cred_list:
    session.add(cred)
    session.commit()  # Don't do this!
```

### 5. Network Timeouts ✅

**Current**: Appropriate timeouts set

- DNS queries: 10s
- LDAP binds: 30s
- CME operations: 30s
- BloodHound: 300s

### 6. Lazy Loading 🔧

**Recommendation**: Only load required data

```python
# Load only IPs for lateral movement
targets = session.query(Target.ip_address).filter_by(is_alive=True).all()

# vs loading entire objects
targets = session.query(Target).filter_by(is_alive=True).all()
```

---

## OpSec vs Performance Trade-offs

### Stealth Mode (Slower but Safer)

- **Jitter**: 60-180s between actions
- **Threads**: 1-2 concurrent operations
- **Retry**: Minimal (fail fast)
- **Total time**: +200% baseline

### Standard Mode (Balanced)

- **Jitter**: 5-30s between actions
- **Threads**: 5-10 concurrent operations
- **Retry**: 2 attempts
- **Total time**: Baseline

### Aggressive Mode (Fast but Loud)

- **Jitter**: 1-5s between actions
- **Threads**: 20+ concurrent operations
- **Retry**: 0 (fail immediately)
- **Total time**: -50% baseline

---

## Module-Specific Optimizations

### Password Spray

**Current**: Sequential with 30s delay
**Optimization**:

- Use `--continue-on-success` flag (already implemented)
- Skip known-invalid usernames from previous sprays
- Prioritize high-value accounts (admin, service accounts)

```python
# Prioritize admin accounts
priority_users = ['admin', 'administrator', 'svc_*']
regular_users = [u for u in users if u not in priority_users]

spray(priority_users + regular_users)
```

### BloodHound Collection

**Current**: Full collection (`-c All`)
**Optimization**: Selective collection for faster results

```bash
# Fast mode (users + computers only)
bloodhound-python -c DCOnly,Users,Computers

# Full mode (default)
bloodhound-python -c All
```

### Lateral Movement

**Current**: All methods attempted on all hosts
**Optimization**:

- Stop after first successful method per host
- Remember successful methods per OS version
- Limit concurrent connections to avoid detection

```python
# Smart method selection
if target.os_version == "Windows Server 2019":
    methods = ["wmiexec", "psexec"]  # Skip legacy methods
else:
    methods = ["psexec", "wmiexec", "smbexec"]
```

---

## Resource Usage Limits

### Memory

**Current**: ~500MB for typical session
**Optimization**: Stream large datasets

```python
# Stream large query results
for target in session.query(Target).yield_per(100):
    process(target)
```

### Disk I/O

**Current**: Minimal (SQLite + logs)
**Optimization**: Batch log writes

```python
# Configure buffered logging
handler.setLevel(logging.INFO)
handler.flush_level = logging.ERROR  # Only flush on errors
```

### Network Bandwidth

**Current**: Minimal (command-line tools only)
**Bottleneck**: BloodHound collection (JSON uploads)

---

## Profiling Tools

### Built-in Python Profiler

```bash
python3 -m cProfile -o profile.stats ./adbasher.py --target example.local
python3 -m pstats profile.stats
```

### Memory Profiling

```bash
pip3 install memory_profiler
python3 -m memory_profiler ./adbasher.py
```

### Database Query Analysis

```python
# Enable SQLAlchemy query logging
import logging
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
```

---

## Performance Checklist

### Before Engagement

- [ ] Set appropriate OpSec mode in config.yaml
- [ ] Reduce log level to WARNING for production
- [ ] Disable unnecessary modules (e.g., skip privesc if not needed)
- [ ] Test network latency to target

### During Execution

- [ ] Monitor memory usage: `ps aux | grep adbasher`
- [ ] Check database size: `du -h session.db`
- [ ] Review error rates in logs
- [ ] Adjust jitter if targets are responsive

### Post-Engagement

- [ ] Analyze session logs for bottlenecks
- [ ] Review failed operations (timeouts, errors)
- [ ] Calculate actual vs estimated completion time
- [ ] Update performance baselines

---

## Future Optimizations (Roadmap)

1. **Multi-threading core** - Parallel phase execution
2. **Connection pooling** - Reuse SMB/LDAP connections
3. **Smart retry logic** - Exponential backoff
4. **Result caching** - Redis for distributed deployments
5. **Incremental scanning** - Resume from last checkpoint
6. **GPU acceleration** - For hash cracking (if integrated)

---

## Example: Performance Tuning

### Scenario: Large Environment (1000+ hosts)

**Problem**: Default execution takes >6 hours

**Solution**:

```yaml
# config.yaml - Aggressive mode
evasion:
  mode: "aggressive"
  jitter_min: 1
  jitter_max: 5

performance:
  max_threads: 50
  connection_timeout: 15
  skip_slow_modules: true
```

```python
# Selective module execution
excluded_phases = ["privesc", "persistence"]
phases = [p for p in all_phases if p not in excluded_phases]
```

**Result**: Completion time reduced to ~2 hours

---

## Monitoring Dashboard (Future)

```
┌─────────────────────────────────────────┐
│ ADBasher Performance Monitor            │
├─────────────────────────────────────────┤
│ Phase: Credential Attacks      [50%]    │
│ Targets Scanned: 125/250       [██████] │
│ Creds Found: 12                         │
│ Time Elapsed: 00:45:23                  │
│ ETA: 00:42:15                           │
│                                         │
│ Current: password_spray.py              │
│ Success Rate: 4.8%                      │
│ Network: 2.5 MB/s                       │
│ CPU: 15%  |  MEM: 450 MB                │
└─────────────────────────────────────────┘
```

---

## Conclusion

ADBasher is optimized for **balanced performance**. For extreme speed requirements, consider:

- Dedicated attack infrastructure (local network)
- Pre-filtered target lists
- Cached reconnaissance data
- Parallel engagement teams

**Always prioritize operational security over speed.**
