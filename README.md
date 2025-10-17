# Enhanced Mist Cloud MCP Server

## Overview

A Model Context Protocol (MCP) server providing complete access to the Juniper Mist Cloud API with advanced security analysis, diagnostics, and EVPN fabric.
Offers ability to troubleshoot individual devices via shell command over if no REST API exist.

## Key Features

### 🛡️ **Security-First Design**
- **Token Privilege Analysis** - Detects overly broad permissions and security risks
- **Risk Assessment** - Identifies violations of least-privilege principles
- **Configurable Security Thresholds** - Environment-based security controls
- **Audit Trail Support** - Comprehensive logging and compliance tracking

### 🔧 **Complete API Coverage (35+ Tools)**
- **Authentication & User Management** (3 tools) - User privileges, audit logs
- **Organization Management** (10 tools) - Stats, inventory, templates, sites, networks, WLANs
- **Site Management** (7 tools) - Device configs, WLANs, statistics, insights
- **Device Management** (5 tools) - Statistics, actions, shell commands, enhanced device info
- **EVPN Fabric Management** (3 tools) - Organization/site topologies, detailed analysis
- **Client Management** (3 tools) - Wireless, wired, and NAC client search
- **Events & Monitoring** (2 tools) - Alarms and device events
- **MSP Management** (2 tools) - MSP info and organization management
- **System Diagnostics** (5 tools) - Health monitoring, connectivity testing, performance analysis

### 🏗️ **EVPN Fabric Architecture Support**
- **Comprehensive Documentation Module** - Expert-level EVPN technical knowledge
- **Fabric Type Analysis** - IP-CLOS, Core-Distribution ERB/CRB, EVPN Multihoming
- **Technical Guidance** - Type-2/Type-5 coexistence, BGP peering strategies, performance optimization
- **Conditional Integration** - Smart recommendations based on actual fabric characteristics

### 📊 **Advanced Diagnostics & Monitoring**
- **Performance Tracking** - Response times, success rates, API usage patterns
- **System Health Monitoring** - Memory, CPU, error patterns, trend analysis
- **Enhanced Shell Execution** - WebSocket-based Junos command execution with timeout handling
- **Real-time Metrics** - Operation history, endpoint statistics, category-based analysis

## Architecture

### Core Components
- **Enhanced MCP Server** (`enhanced_mist_mcp_server.py`) - Main server with 35+ tools
- **EVPN Documentation Module** (`evpn_fabric_docs.py`) - Technical knowledge base with Juniper best practices

### Security Framework
- **Privilege Security Analyzer** - Detects dangerous token permissions
- **Risk Acknowledgment System** - Controlled override mechanisms
- **Environment-based Configuration** - Security thresholds via environment variables

### Technical Integrations
- **WebSocket Support** - Real-time shell command execution on Junos devices
- **Gateway Template Enhancement** - Automatic template matching and configuration analysis
- **Multi-transport Support** - stdio, HTTP, WebSocket protocols

## Requirements

### Dependencies
```bash
pip3 install fastmcp httpx websockets psutil python-dotenv uvicorn starlette
```

### Required Environment Variables
```bash
MIST_API_TOKEN=your_api_token_here
MIST_BASE_URL=https://api.mist.com  # or custom URL
```

### Security Configuration (Optional)
```bash
MIST_STRICT_SECURITY_MODE=true     # Enable security blocking
MIST_SECURITY_RISKS_ACKNOWLEDGED=false  # Require explicit risk acknowledgment
MIST_MAX_ADMIN_ORGS=1             # Max orgs with admin privileges
MIST_MAX_WRITE_ORGS=3             # Max orgs with write privileges
MIST_MAX_ADMIN_MSPS=1             # Max MSPs with admin privileges
MIST_MAX_WRITE_MSPS=1             # Max MSPs with write privileges
MIST_MAX_ORGS_PER_MSP=5           # Max orgs per MSP
```

## Installation & Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd enhanced-mist-mcp-server
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your Mist API token
   ```

4. **Validate configuration**
   ```bash
   python enhanced_mist_mcp_server.py --validate-config
   ```

## Usage

### Basic Startup
```bash
# Default stdio transport (most common for MCP)
python enhanced_mist_mcp_server.py
python enhanced_mist_mcp_server.py --transport stdio
 
# HTTP/SSE transport on specific port
python enhanced_mist_mcp_server.py -t sse -p 8080

# HTTP transport
python enhanced_mist_mcp_server.py -t http -H 0.0.0.0 -p 8080

# HTTPS transport
python enhanced_mist_mcp_server.py -t sse -p 8443 --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem
```

### Advanced Options
```bash
python enhanced_mist_mcp_server.py \
  --host 127.0.0.1 \
  --port 30040 \
  --log-level DEBUG \
  --security-check
```

### Command Line Options
```
Options:
  -H, --host HOST           Server host (default: 127.0.0.1)
  -t, --transport TRANSPORT Transport type: stdio (pipes), sse (HTTP), or http protocols
  -p, --port PORT          Server port (default: 30040)
  --ssl-crt PATH           path to certificate file for HTTPS
  --ssl-key PATH           path to SSL key file for HTTPS
  --log-level LEVEL        Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  --debug                  Enable maximum debug output
  --validate-config        Validate configuration and exit
  --security-check         Perform API token security analysis and exit
```

## Tool Categories

### Authentication & User Management
- `get_user_info` - Complete user profile and privilege analysis
- `get_audit_logs` - Organization/site audit log retrieval
- `analyze_token_security` - API token privilege security analysis

### Organization Management
- `get_organizations` - List accessible organizations
- `get_organization_stats` - Comprehensive org statistics with time controls
- `search_org_bgp_stats` - BGP statistics search with filtering
- `get_org_inventory` - Device inventory with type filtering
- `get_org_sites` - All sites with enhanced analysis
- `get_org_templates` - RF/Network/AP/Gateway templates
- `get_org_settings` - Organization configuration settings
- `search_org_devices` - Device search by MAC/serial
- `get_org_networks` - WAN Assurance networks for SSR/SRX
- `get_org_wlans` - Organization-wide WLAN configurations
- `count_org_nac_clients` - NAC client count

### Site Management
- `get_site_info` - Detailed site information
- `get_site_devices` - Device configurations with gateway template enhancement
- `get_site_wlans` - Site WLAN configurations
- `get_site_stats` - Site performance metrics
- `get_site_insights` - SLE metrics and insights

### Device Management
- `get_device_stats` - Device performance metrics
- `device_action` - Perform device actions (restart, locate, etc.)
- `execute_custom_shell_command` - Enhanced shell command execution with timeout
- `get_enhanced_device_info` - Comprehensive device data with optional shell integration
- `get_device_events` - Device events with enhanced analysis

### EVPN Fabric Management
- `get_org_evpn_topologies` - Organization-level EVPN fabrics
- `get_site_evpn_topologies` - Site-specific EVPN fabrics
- `get_evpn_topologies_details` - Detailed topology analysis with technical guidance

### Client Management
- `search_org_wireless_clients` - Wireless client search with comprehensive filtering
- `search_org_wired_clients` - Wired client search with port-level visibility
- `search_org_nac_clients` - NAC client search with compliance tracking

### Events & Monitoring
- `get_alarms` - Alarm management with enhanced analysis
- `get_device_events` - Device events with filtering and analysis

### MSP Management
- `get_msp_info` - MSP information
- `get_msp_orgs` - Organizations under MSP management

### System Diagnostics
- `get_service_health_report` - Comprehensive service health monitoring
- `test_mist_connectivity` - API connectivity testing across endpoints
- `debug_server_status` - Server configuration and dependency status
- `export_diagnostics_json` - Diagnostics data export for external analysis
- `get_performance_trends` - Performance trend analysis with configurable windows

### Security Tools
- `analyze_token_security` - API token privilege security analysis
- `acknowledge_security_risks` - Controlled security risk acknowledgment

### Utility Tools
- `make_mist_api_call` - Generic API interface with security validation

## Security Features

### Token Privilege Analysis
The server automatically analyzes API token privileges to detect security risks:

- **CRITICAL Risks**: Admin privileges to multiple organizations or MSPs
- **HIGH Risks**: Write privileges to multiple organizations or excessive MSP access
- **Configurable Thresholds**: Environment variable control of risk levels
- **Blocking Capability**: Optional execution blocking for dangerous tokens

### Risk Mitigation
- **Principle of Least Privilege**: Automatic detection of overprivileged tokens
- **Alternative Solutions**: Recommendations for token scoping and access patterns
- **Audit Trail**: Comprehensive logging of security decisions and overrides

## EVPN Fabric Capabilities

### Supported Fabric Types
- **IP-CLOS** (Edge routing) - Full EVPN-VXLAN from access to core
- **Core-Distribution ERB** (Distribution routing) - EVPN in core/distribution, L2 access
- **Core-Distribution CRB** (Core routing) - Centralized routing at core
- **EVPN Multihoming** (Collapsed-core) - 2-4 core devices with ESI-LAG

### Technical Features
- **Type-2/Type-5 Route Coexistence** - Automatic in fabric version ≥3
- **BGP Peering Strategies** - EBGP underlay with iBGP overlay analysis
- **Performance Optimization** - Large fabric discovery and MAC-VRF scaling
- **Enhanced OISM** - Optimized Intersubnet Multicast integration
- **Configuration Drift Detection** - Template vs device state comparison

## Monitoring & Diagnostics

### Performance Metrics
- **Response Time Tracking** - P50, P90, P95, P99 percentiles
- **API Usage Analysis** - Category and endpoint statistics
- **Success Rate Monitoring** - Request success/failure tracking
- **Resource Utilization** - Memory and CPU usage monitoring

### Health Monitoring
- **Service Uptime** - Continuous uptime tracking
- **Error Pattern Analysis** - Top error patterns and frequency
- **System Resource Monitoring** - Memory, CPU, and connection tracking
- **Rate Limit Tracking** - API rate limit monitoring and reporting

## Troubleshooting

### Common Issues

**WebSocket Commands Not Working**
```bash
# Install WebSocket support
pip3 install websockets
```

**API Authentication Errors**
```bash
# Validate configuration
python3 enhanced_mist_mcp_server.py --validate-config
```

**Security Blocking**
```bash
# Check token privileges
python3 enhanced_mist_mcp_server.py --security-check

# Override if needed (after risk assessment)
export MIST_SECURITY_RISKS_ACKNOWLEDGED=true
```

### Debug Mode
```bash
python3 enhanced_mist_mcp_server.py --debug --log-level DEBUG
```

## Version History

- **v4.0** - Logic and Docs in separate file
- **v3.1** - Complete API Coverage with Security Analysis
- **v3.0** - Enhanced EVPN Fabric Management
- **v2.0** - Security Framework Integration
- **v1.0** - Initial MCP Server Implementation

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 👤 Author

**Patrik Bok** (<pbok@juniper.net>)

- GitHub: [@r2600r](https://github.com/r2600r)

---

**Note**: This server requires a valid Juniper Mist Cloud API token with appropriate privileges. Use the built-in security analysis tools to ensure your token follows the principle of least privilege.