# Installing Nuclei on Windows

Nuclei is a fast vulnerability scanner based on YAML templates. Phase 5 uses it for template-based scanning.

---

## Option 1: Chocolatey (Recommended)

**Requirements**: Chocolatey package manager + Admin privileges

```powershell
# Install Nuclei
choco install nuclei -y

# Verify installation
nuclei -version
```

**Expected output**:
```
Nuclei v3.x.x (latest)
```

**Update Nuclei templates** (important - templates contain vulnerability signatures):
```bash
nuclei -update-templates
```

---

## Option 2: Binary Download (No Admin Required)

1. **Download the latest release**:
   - Go to: https://github.com/projectdiscovery/nuclei/releases/latest
   - Download: `nuclei_3.x.x_windows_amd64.zip`

2. **Extract and add to PATH**:
   ```powershell
   # Extract to your preferred location
   Expand-Archive nuclei_3.x.x_windows_amd64.zip -DestinationPath C:\Tools\nuclei

   # Add to PATH (current session)
   $env:PATH += ";C:\Tools\nuclei"

   # Add to PATH (permanent - requires restart)
   [Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\Tools\nuclei", "User")
   ```

3. **Verify installation**:
   ```bash
   nuclei -version
   ```

4. **Download templates**:
   ```bash
   nuclei -update-templates
   ```

---

## Option 3: Docker (Already Set Up)

If you want to run Nuclei in Docker instead of installing it:

**Create a Nuclei Docker wrapper script** (`nuclei.ps1`):
```powershell
# Save as nuclei.ps1 in your PATH
docker run --rm -it projectdiscovery/nuclei:latest $args
```

**Usage**:
```bash
./nuclei.ps1 -version
./nuclei.ps1 -u http://localhost:3000 -t cves/
```

**Note**: You'll need to modify `src/sentinel/tools/scanning/nuclei_tool.py` to use the Docker wrapper.

---

## Post-Installation Verification

### 1. Check Nuclei is accessible:
```bash
nuclei -version
```

### 2. Run a basic scan against Juice Shop:
```bash
nuclei -u http://localhost:3000 -tags xss -severity high,critical
```

### 3. Test from Python:
```python
from sentinel.tools.scanning.nuclei_tool import NucleiTool, NucleiSeverity
import asyncio

async def test():
    tool = NucleiTool()
    result = await tool.execute(
        target="http://localhost:3000",
        severity=[NucleiSeverity.HIGH, NucleiSeverity.CRITICAL],
        tags=["xss"]
    )
    print(f"Success: {result.success}")
    print(f"Findings: {result.metadata.get('total_findings', 0)}")

asyncio.run(test())
```

---

## Configuration in Sentinel

### Update `.env` (if needed):
```bash
# Optional: Override default Nuclei binary location
NUCLEI_PATH=C:\Tools\nuclei\nuclei.exe

# Optional: Custom template directory
NUCLEI_TEMPLATES=C:\nuclei-templates
```

### Verify settings:
```python
from sentinel.core.config import get_settings

settings = get_settings()
print(f"Nuclei path: {settings.nuclei_path}")
print(f"Templates: {settings.nuclei_templates}")
```

---

## Template Management

Nuclei's power comes from its templates. Keep them updated:

### Update templates:
```bash
nuclei -update-templates
```

### Template categories:
- `cves/` - CVE-based templates (most important)
- `vulnerabilities/` - Known vulnerability patterns
- `exposures/` - Exposed services and misconfigs
- `misconfiguration/` - Common misconfigurations
- `fuzzing/` - Fuzzing templates

### View available templates:
```bash
nuclei -tl  # List all templates
```

### Example scans:
```bash
# Scan for all CVEs
nuclei -u http://localhost:3000 -t cves/

# Scan for SQL injection only
nuclei -u http://localhost:3000 -tags sqli

# Scan with specific severity
nuclei -u http://localhost:3000 -severity critical,high

# Scan with rate limiting (important for production)
nuclei -u http://localhost:3000 -rate-limit 50 -concurrency 10
```

---

## Troubleshooting

### Issue: "nuclei: command not found"
**Solution**: Binary not in PATH. Use full path or add to PATH.

### Issue: "No templates found"
**Solution**: Run `nuclei -update-templates`

### Issue: "Permission denied"
**Solution**: Run PowerShell/CMD as Administrator or use Option 2 (binary download)

### Issue: Slow scans
**Solution**: Adjust rate limiting and concurrency:
```python
tool = NucleiTool()
tool.max_rate = 150  # requests per second
tool.concurrency = 25  # concurrent templates
```

### Issue: Too many false positives
**Solution**: Filter by severity:
```python
result = await tool.execute(
    target="http://localhost:3000",
    severity=[NucleiSeverity.CRITICAL, NucleiSeverity.HIGH],  # Ignore medium/low
    exclude_tags=["info"]  # Exclude informational findings
)
```

---

## Do I Need Nuclei?

**Short answer**: No, for Phase 5 completion.

**Why**:
- All 45 Phase 5 tests pass without Nuclei (mocked)
- ZAPTool works independently
- `GuardedVulnAgent` gracefully degrades if Nuclei is missing

**When you need it**:
- **Phase 6+**: Real vulnerability scanning against Juice Shop
- **Production**: Scanning actual targets
- **Integration tests**: Verifying tool functionality

**For now**:
- ZAPTool (already working) covers DAST scanning
- Existing attack tools in `src/sentinel/tools/attack/` work independently
- You can proceed to Phase 6 without Nuclei and install it later

---

## Alternative: Use ZAPTool Only

If you don't want to install Nuclei right now:

**Update GuardedVulnAgent** to prefer ZAP:
```python
CATEGORY_TO_TOOLS = {
    HypothesisCategory.INJECTION: ["sqli_tool", "zap_scan"],  # Remove nuclei_scan
    HypothesisCategory.XSS: ["xss_tool", "zap_scan"],
    # ... etc
}
```

ZAP is already running and accessible at `http://localhost:8080` (verified in Phase 5 checks).

---

## Summary

**Easiest**: `choco install nuclei -y` (requires admin)
**No admin**: Download binary + add to PATH
**No install**: Use ZAPTool only (already working)
**Docker**: Create wrapper script

**Recommendation**: Install it when you start Phase 6 (exploitation), not urgently needed for Phase 5 completion.
