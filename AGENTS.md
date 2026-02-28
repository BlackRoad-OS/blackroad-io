# BlackRoad OS Agent Instructions

> Comprehensive guide for AI agents working on BlackRoad OS repositories.

## Quick Reference

| Item | Value |
|------|-------|
| Organization | BlackRoad-OS |
| Main Project | BlackRoad Empire |
| Branch Pattern | `claude/{task}-{session-id}` |
| Commit Format | `{type}: {description}` |
| PR Required | Yes, always |

---

## 1. Before You Start

### 1.1 Verify Your Context

```bash
# Check current branch
git branch --show-current

# Verify remote
git remote -v

# Check status
git status
```

### 1.2 Required Environment Variables

Ensure these are available (check with Cloudflare KV or secrets manager):

```
GITHUB_TOKEN          # GitHub API access
CLOUDFLARE_API_TOKEN  # Cloudflare services
CLOUDFLARE_ACCOUNT_ID # Cloudflare account
ANTHROPIC_API_KEY     # Claude API (your own!)
SALESFORCE_*          # CRM sync (if applicable)
VERCEL_TOKEN          # Vercel deployments
DIGITALOCEAN_TOKEN    # DO infrastructure
PI_CLUSTER_API_KEY    # Edge compute
```

---

## 2. Branch Naming Convention

**CRITICAL: Incorrect branch names will cause PR failures!**

### Pattern
```
claude/{type}-{description}-{session-suffix}
```

### Examples
- `claude/fix-auth-bug-AbC123`
- `claude/feature-dashboard-XyZ789`
- `claude/docs-api-update-DeF456`
- `claude/setup-projects-apis-BaL5E`

### Types
| Type | Use Case |
|------|----------|
| `fix` | Bug fixes |
| `feature` | New features |
| `docs` | Documentation |
| `refactor` | Code refactoring |
| `test` | Test additions |
| `setup` | Configuration/setup |
| `security` | Security fixes |

---

## 3. Commit Message Format

### Structure
```
{type}: {short description}

{optional body with details}

{optional footer with references}
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting (no code change)
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks
- `security`: Security improvements

### Examples
```bash
# Good
git commit -m "feat: add SHA-infinity hashing utility"
git commit -m "fix: resolve API timeout on large payloads"
git commit -m "docs: update agent instructions with PR validation"

# Bad
git commit -m "update stuff"
git commit -m "fix"
git commit -m "WIP"
```

---

## 4. Pull Request Guidelines

### 4.1 Pre-PR Checklist

Before creating a PR, verify:

- [ ] Branch follows naming convention (`claude/*`)
- [ ] All commits follow message format
- [ ] No secrets or credentials in code
- [ ] Tests pass (if applicable)
- [ ] Linting passes (if applicable)
- [ ] Documentation updated (if needed)
- [ ] Hash verification passes (for critical files)

### 4.2 PR Template

```markdown
## Summary
- Brief description of changes
- Why these changes were made

## Changes Made
- List of specific changes

## Testing
- How changes were tested
- Test results

## Hash Verification
- Content hash (SHA-256): `{hash}`
- Verification string: `{sha-infinity-string}`

## Related Issues
- Fixes #123
- Related to #456

---
Session: https://claude.ai/code/session_{id}
```

### 4.3 Common PR Failures & Solutions

| Failure | Cause | Solution |
|---------|-------|----------|
| Branch name invalid | Not matching `claude/*` | Rename branch or create new |
| Push rejected | Branch protection | Create PR instead of direct push |
| Merge conflict | Outdated base | Rebase on latest main |
| Tests failing | Code issues | Fix tests before PR |
| Hash mismatch | Content changed | Regenerate hashes |

---

## 5. State Synchronization

### 5.1 The State Triangle

```
       GitHub Projects
           /    \
          /      \
         /        \
  Cloudflare ---- Salesforce
    (State)        (CRM)
```

### 5.2 Sync Flow

1. **On PR Create**:
   - Add to GitHub Project
   - Create Salesforce record
   - Store state in Cloudflare KV

2. **On PR Merge**:
   - Update GitHub Project status
   - Update Salesforce record
   - Update Cloudflare state
   - Trigger deployment (if applicable)

3. **On State Change**:
   - Webhook to sync service
   - Bidirectional sync
   - Conflict resolution: newest wins

### 5.3 Cloudflare KV Keys

```javascript
// Project state
project:{projectId}:{itemId}

// PR state
pr:{repo}:{prNumber}

// Agent session
agent:{agentId}:{sessionId}

// Deployment state
deploy:{provider}:{projectId}:{deployId}
```

---

## 6. Hashing Requirements

### 6.1 When to Hash

- Configuration file changes
- API contract changes
- Security-sensitive changes
- Cross-repository sync data

### 6.2 SHA-256 Quick Reference

```javascript
// JavaScript
import { SHA256 } from './utils/hash.js';
const hash = await SHA256.hash('content');
```

```python
# Python
from utils.hash import SHA256
hash = SHA256.hash('content')
```

### 6.3 SHA-Infinity for Critical Data

```javascript
// JavaScript
import { SHAInfinity } from './utils/hash.js';
const result = await SHAInfinity.hash('content', {
  iterations: 1000,
  includeMetadata: true
});
// result.verificationString = '$sha-inf$1000$salt$hash'
```

```python
# Python
from utils.hash import SHAInfinity
result = SHAInfinity.hash('content', iterations=1000)
# result.verification_string = '$sha-inf$1000$salt$hash'
```

---

## 7. API Integration Reference

### 7.1 Primary APIs

| Service | Purpose | Config File |
|---------|---------|-------------|
| GitHub | Source control, Projects | `config/apis.json` |
| Cloudflare | State, CDN, Workers | `config/cloudflare-state.json` |
| Salesforce | CRM, detailed records | `config/salesforce-crm.json` |
| Vercel | Edge deployments | `config/vercel.json` |
| DigitalOcean | Infrastructure | `config/digitalocean.json` |
| Claude | AI agents | `config/claude-agents.json` |
| Pi Cluster | Edge compute | `config/pi-cluster.json` |

### 7.2 Health Check Endpoints

Always verify API availability before operations:

```bash
# Cloudflare
curl -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  https://api.cloudflare.com/client/v4/user/tokens/verify

# GitHub
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/rate_limit

# Vercel
curl -H "Authorization: Bearer $VERCEL_TOKEN" \
  https://api.vercel.com/v2/user
```

---

## 8. Mobile Development

### 8.1 Supported Tools

| Tool | Platform | Use Case |
|------|----------|----------|
| Working Copy | iOS | Git operations |
| Termius | iOS/Android | SSH access |
| iSH | iOS | Linux shell |
| Shellfish | iOS | SFTP |
| Pyto | iOS | Python scripts |

### 8.2 Working Copy URL Schemes

```
# Clone repository
working-copy://clone?remote=git@github.com:BlackRoad-OS/blackroad-io.git

# Push changes
working-copy://x-callback-url/push/?repo=blackroad-io

# Pull latest
working-copy://x-callback-url/pull/?repo=blackroad-io
```

---

## 9. Task Management

### 9.1 Using TodoWrite Tool

Always use the TodoWrite tool to track progress:

```javascript
// Example todo structure
{
  "content": "Implement API endpoint",
  "status": "in_progress", // pending | in_progress | completed
  "activeForm": "Implementing API endpoint"
}
```

### 9.2 Task Status Flow

```
pending -> in_progress -> completed
              |
              v
         (if blocked)
              |
              v
          pending (with blocker task added)
```

---

## 10. Error Handling

### 10.1 Retry Strategy

For transient failures:

```
Attempt 1: Immediate
Attempt 2: Wait 2 seconds
Attempt 3: Wait 4 seconds
Attempt 4: Wait 8 seconds
```

### 10.2 Common Errors

| Error | Action |
|-------|--------|
| Rate limited | Implement backoff, switch to haiku model |
| Auth failed | Check token expiration, refresh |
| Merge conflict | Rebase, resolve manually |
| Build failed | Check logs, fix issues |
| Timeout | Increase timeout or chunk request |

---

## 11. Security Guidelines

### 11.1 Never Commit

- API keys or tokens
- Passwords
- Private keys
- `.env` files with real values
- Customer data

### 11.2 Always Do

- Use environment variables
- Rotate credentials regularly
- Audit access logs
- Report suspicious activity

---

## 12. Quick Start Checklist

New agent starting work? Follow this:

1. [ ] Read this document fully
2. [ ] Verify branch naming
3. [ ] Check environment variables
4. [ ] Review relevant config files
5. [ ] Create TodoWrite plan
6. [ ] Make small, focused commits
7. [ ] Hash critical changes
8. [ ] Create PR with full description
9. [ ] Verify CI passes
10. [ ] Update state in Cloudflare/Salesforce

---

## 13. Support

- **Issues**: https://github.com/BlackRoad-OS/blackroad-io/issues
- **Discussions**: https://github.com/BlackRoad-OS/blackroad-io/discussions
- **Documentation**: See `/config/*.json` for detailed configurations

---

*Last Updated: 2026-01-27*
*Version: 2.0.0*
