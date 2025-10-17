#!/usr/bin/env python3
"""
EVPN Fabric Architecture Documentation Module
==============================================

Dedicated documentation module containing comprehensive EVPN fabric knowledge
extracted from Juniper Networks Data Center EVPN-VXLAN Fabric Architecture Guide.

This module provides structured documentation that the MCP server can reference
while keeping the main server code minimal and focused.

Key Technical Areas Covered:
- Organization vs Site Level Fabric Architecture
- EVPN Type 2 and Type 5 Route Coexistence
- BGP Peering Strategies and Policy Adjustments
- Discovery Optimization for Large Organizations
- Fabric Topology Design Patterns
"""

# =============================================================================
# TOOL's DESCRIPTION AND LOGIC DOCUMENTATION
# =============================================================================

EVPN_ORG_TOOL_DOC = """
    EVPN FABRIC TOOL #1: Organization-Level EVPN Topology Manager

    Function: Retrieves organization-level EVPN fabrics that span multiple sites
            or manage cross-site fabric coordination. Organization fabrics are
            used when pods/buildings are distributed across different sites,
            each requiring different configurations from separate site templates.

    API Used: GET /api/v1/orgs/{org_id}/evpn_topologies?for_site=any

    EVPN Fabric Architecture Understanding:
    =====================================
    1. **Organization-Level Fabrics:**
    - ?for_site=any" in API call returns fabrics in any sites within the organization with their unique topology_id
    - Span multiple sites within an organization
    - site_only_fabric = false is return
    - Multiple fabrics per org supported but are not common


    2. **Site-Level Fabrics:**
    - site_only_fabric = true is return
    - Contained within a single site boundary
    - Share the same switch template configuration
    - Multiple fabrics can exist within one site
    - Used for localized network segments

    Response Handling:
    - site fabric when site_only_fabric is true is return
    - organization fabric when site_only_fabric is false is return
    - Returns JSON array of organization-level EVPN fabrics
    - Shows fabric names, topology types, and creation timestamps
    - Reports underlay/overlay configuration (AS numbers, subnets)
    - Contains pod assignments and site relationships
    - Includes border leaf and routing configuration
    - Shows fabric version and modification history

    Enhanced Features:
    - Fabric scope analysis (org vs site level)
    - Cross-site topology validation
    - Pod distribution across multiple sites
    - Template inheritance tracking
    - Centralized policy enforcement status

    Use Cases:
    - Multi-site campus network management
    - Healthcare system with multiple hospital locations
    - Enterprise networks spanning multiple buildings/sites
    - Cross-site EVPN fabric coordination and troubleshooting
    - Organization-wide fabric policy enforcement
"""

EVPN_SITE_TOOL_DOC = """
    EVPN FABRIC TOOL #2: Site-Level EVPN Topology Manager

    Function: Retrieves site_only_fabric EVPN fabrics contained within a single site.
            Site fabrics are smaller, localized deployments that share the same and contains side_id in the API call.
            switch template and are managed independently from organization fabrics.
            Multiple fabrics can exist within a single site.

    API Used: GET /api/v1/sites/{site_id}/evpn_topologies

    Site Fabric Characteristics:
    ===========================
    - Localized within single site boundary
    - Share common switch template configuration
    - Independent from org-level fabrics
    - Multiple fabrics per site supported
    - Optimized for site-specific network segments


    Response Handling:
    - Returns JSON array of site-specific EVPN fabrics
    - when site_only_fabric = true is return
    - Shows fabric names, topology IDs, and site assignments
    - Reports pod configurations within the site
    - Contains underlay/overlay settings specific to site
    - Includes switch role assignments and fabric membership
    - Shows border leaf configuration for site connectivity

    Enhanced Features:
    - Site fabric enumeration and analysis
    - Pod-to-switch mapping within site
    - Fabric health and connectivity status
    - Switch role validation (spine/leaf/border)
    - Intra-site topology optimization insights

    Use Cases:
    - Single-site fabric management and troubleshooting
    - Site-specific network segment isolation
    - Localized EVPN policy enforcement
    - Site fabric health monitoring and optimization
    - Multi-fabric site architecture analysis

    Optimization Notes:
    - Use inventory-based filtering to reduce API calls
    - Focus on sites with significant switch deployments
    - Combine with device statistics for fabric performance analysis
"""

EVPN_DETAILS_TOOL_DOC = """
    EVPN FABRIC TOOL #3: Comprehensive Topology Detail Analyzer

    - Used when network pods/buildings are distributed across sites
    - Each site could get different configurations from switch templates
    - Single switch templates can be assigned to multiple sites, but site can only has one switch template
    - Switch template uses rules which are user defined and can be assigned to devices
    - Rules in switch template define port profiles assigment to specific port or port ranges and other setting including additional cli commands
    - Rules in switch templates can be matched to device beased on device model, name of device or user defined roles (e.g. spine, leaf, border)
    - Rules provide much more depper granularity and flexibility in switch template configuration
    - Provides centralized fabric management and cross-site coordination
    - Examples: Campus networks, multi-building healthcare systems

    Function: Get detailed EVPN topology information for a site or organization and topology ID.
    - site_only_fabric = true is return , Site-Level Fabrics, use site_id,  /api/v1/sites/{site_id}/evpn_topologies/{topology_id}
    - site_only_fabric = false is return, Multi Site Fabrics, use org_id,  /api/v1/orgs/{org_id}/evpn_topologies/{topology_id}


    Accepts either site_id or org_id (one must be provided) along with topology_id.

    API Used:
    - /api/v1/sites/{site_id}/evpn_topologies/{topology_id}
    - /api/v1/orgs/{org_id}/evpn_topologies/{topology_id}

    Summarizes:
    - Number of pods
    - Number of switches
    - Fabric type  (edge/core/distribution, collapsed-core, bridged)
    - Fabric version
    - Switch models, MACs, router IDs, roles
    - Pod names
    - Topology type and AS numbers
    - Underlay/overlay info
    - Local IRB interfaces (other_ip_configuration)
    - auto_loopback_subnet and auto_router_id_subnet
    - Border leaf and core-as-border settings
    - VXLAN VNI to VLAN mappings
"""

SITE_DEVICES_TOOL_DOC = """

    Function: Get device configurations for a site by type
    CRITICAL DECISION TREE - READ CAREFULLY:
    ┌─ Do you KNOW the exact device types present at this site? ─┐
    │                                                            │
    ├─ YES (user specified OR previously discovered)             │
    │  └─ Use get_site_devices(site_id, device_type) directly    │
    │                                                            │
    └─ NO (unknown site OR user didn't specify device types)     │
        └─ MANDATORY: Use get_org_inventory() FIRST              │
            └─ Then call get_site_devices() for each discovered type    

    API: GET /api/v1/sites/{site_id}/devices

    Parameters: site_id (required), device_type (optional, defaults to "ap")
    WARNING: Without device_type, only returns APs. For all configs, call separately for each type.
    Returns: Device configurations for specified type only
    Use: Get actual device configurations after knowing what types exist

    Function: Get device configurations for a site by type with gateway template integration
    API: GET /api/v1/sites/{site_id}/devices + GET /api/v1/orgs/{org_id}/gatewaytemplates
    Parameters: site_id (required), device_type (optional, defaults to "ap")
    WARNING: Without device_type, only returns APs. For all configs, call separately for each type.
    Returns: Device configurations for specified type with enhanced gateway template data
    Use: Get actual device configurations after knowing what types exist

    GATEWAY ENHANCED CONFIGURATION RETRIEVAL:
    When device_type="gateway" or when gateways are detected in the response:
    - Automatically retrieves organization gateway templates via get_org_templates(org_id,gatewaytemplates)
    - Matches gateway devices to their assigned gateway template using gatewaytemplate_id
    - Supplements basic gateway device config with full template configuration including:
    * Complete interface configurations
    * Routing policies and protocols (BGP, OSPF, static routes)
    * Security zones and policies
    * NAT and firewall rules
    * VPN tunnel configurations
    * WAN edge and SD-WAN policies
    * DHCP and DNS configurations
    - Provides template vs device configuration comparison for drift detection
    - Returns merged configuration showing both Mist-managed settings and template-defined config
    - Enables bulk configuration analysis without individual shell command delays

    TEMPLATE MATCHING LOGIC:
    - Uses gatewaytemplate_id from device configuration
    - Falls back to site-level gatewaytemplate_id if device-level not specified
    - Handles cases where gateways use organization default templates
    - Provides template inheritance hierarchy information

    CONFIGURATION DRIFT DETECTION:
    - Compares template-defined configuration with device-reported configuration
    - Identifies deviations between intended (template) and actual (device) state
    - Enables proactive configuration management and compliance reporting
    - Supports bulk configuration validation across gateway fleet

    IMPORTANT: By default (when no device_type is specified), this function ONLY returns Access Points (APs).
    EFFICIENCY: Use inventory first only when discovering unknown device types,
    For known device types, call get_site_devices directly with specific device_type
    Example: If you know site has only switches, call get_site_devices(site_id, "switch") directly 

"""     

EXECUTE_CUSTOM_SHELL_COMMAND = """


    Execute a custom shell command on a Junos device (with enhanced timeout handling)

    IMPORTANT: Use this tool ONLY when the required information is NOT available via API.
    For BGP statistics, use get_org_bgp_peers_enhanced() instead - it's much faster and 
    provides bulk data without individual device delays.

    Enhanced function to execute commands on devices where no API endpoints are available.

    EVPN FABRIC HEALTH ANALYSIS - USE CASES:
    ========================================
    For comprehensive EVPN fabric health checks, use this tool to verify:

    1. EVPN Control Plane Status (DETAILED):
        - show evpn instance extensive         # VNI status with detail
        - show evpn database extensive         # MAC/IP table with timestamps
        - show route table bgp.evpn.0          # EVPN route table
        - show evpn l3-context                 # L3 VNI context
        
    2. BGP Session Details (when get_org_bgp_peers_enhanced insufficient):
        - show bgp summary                     # Quick peer overview
        - show bgp neighbor <ip> extensive     # Detailed peer info
        - show route receive-protocol bgp <neighbor>
        - show route advertising-protocol bgp <neighbor>
        
    3. VXLAN Data Plane Verification:
        - show interfaces vtep extensive       # VTEP details
        - show pfe vxlan nh-usage              # Nexthop usage (EX4400/QFX)
        - show evpn instance extensive         # EVPN instance details
        
    4. Underlay Health (IPv4 or IPv6 based fabrics):
        - show route table inet6.0            # IPv6 underlay routes
        - show route table inet.0             # IPv4 underlay routes
        - show bfd session extensive          # BFD state with detail
        - show interfaces terse | match "up|down"  # Interface status
        
    5. MAC Learning and Troubleshooting:
        - show ethernet-switching table       # Local MAC table (includes GBP)
        - show ethernet-switching mac-learning-log  # MAC learn events
        - show evpn arp-table                 # EVPN ARP entries

    6. System route capacity utilization
        - show pfe route summary hw         # Hadware capacity of Packefe Forwarding Engine (PFE )

    INTERPRETING JUNOS LICENSE WARNINGS:
    When you see "Warning: License key missing" in BGP/OSPF/EVPN output:
    - This is informational only
    - The protocol still operates fully
    - Focus on actual state (Established/Active/Idle) not license warnings but warn user that is is breaching Juniper license agreement

    DO NOT USE for BGP peer status - use get_org_bgp_peers_enhanced() instead.

    API Used: POST /api/v1/sites/{site_id}/devices/{device_id}/shell/execute

    Parameters:
        site_id: Site identifier
        device_id: Device identifier  
        command: Shell command to execute
        timeout: Command timeout in seconds (5-300, default: 30)

    Returns:
        JSON with command output, execution time, and status
"""

GET_ENHANCED_DEVICE_INFO = """
    Get device configuration and details statistic via API and specific health info from junos shell commands
    device_id format must be full MAC address,  e.g. "bc0ffe15c700" prepended by"00000000-0000-0000-1000-"
    Example: "00000000-0000-0000-1000-bc0ffe15c700

    PARAMETERS:
    - device_id: Format "00000000-0000-0000-1000-{12-char-mac}"
    - site_id: Site identifier

    IMPORTANT: This function combines API data retrieval with multiple shell commands to provide a comprehensive device information 

    RETURNS: combination of API (device configuration and device statistics) and output of commands:
    - junos version
    - junos uptime
    - cpu and memory statistics
    - detailed interface statistics (traffic, errors, discards)
    - configuration commit history
    - route summary statistics
    - connected clients information
    - module statistics
    - virtual chassis details
    - ARP & MAC Table Statistics
    - last configuration commit status
    - show chassis hardware brief - hardware model and serial
    - show system alarms - current active alarms
    - show chassis alarms - chassis related alarms - IMPORTANT: Ignore all licese warnings and alarms, device function correctly without licenses, remommended to purchase licenses only for production enviroments
    - show system core-dumps - junos os core dump files for Juniper TAC,if present often indicates crashes
    - show route summary - routing table summary
    - show log messages | last 100 - recent log messages

    USE CASES:
    - Initial device discovery and overview
    - Basic device health assessment
    - Troubleshooting connectivity and performance issues
    """

GET_BGP_PEERS_ENHANCED_DOC = """

CRITICAL TOOL FOR EVPN FABRIC HEALTH ANALYSIS
==============================================

Function: Retrieve and analyze BGP peer statistics across the entire organization.
This is the PRIMARY tool for validating BGP state on any device or EVPN fabric control plane health.

EVPN FABRIC HEALTH WORKFLOW - ALWAYS USE THIS TOOL:
========================================================
When analyzing EVPN fabric health , this tool and other vitals tools in following order should be called IMMEDIATELY after 
topology validation and alarm checking:

1. BGP Session States: Are all underlay/overlay peers Established?
3. Peer Stability: Check for session flaps or high flap counts
4. Route Counts: Verify expected route counts per peer
5. Performance: Check uptime and convergence metrics

Other tools to use AFTER BGP check:
- get_site_devices() for switch configurations in case configuration casued issues
- execute_custom_shell_command() for EVPN-specific details (database, VTEPs)
- get_org_stats() for device health and performance
- check wired client events for any issues 
- check wireless client events for any issues if the are any AP in same site
- check NAC events for any issues if dot1x is used and configured in the fabric


EVPN FABRIC HEALTH CHECK - RECOMMENDED USAGE:
==============================================

Step 1 - Discovery Mode (Get ALL BGP peers):
    get_org_bgp_peers_enhanced(
        org_id="xxx",
        discovery_mode=True  # or omit all filters
    )
    → Returns comprehensive BGP health with automatic analysis
    → Identifies issues
    → Groups by status, ASN, route types

Step 2 - Troubleshoot Specific Issues (if Step 1 shows problems):
    # Check peers in non-Established state
    get_org_bgp_peers_enhanced(
        org_id="xxx",
        peer_status="idle"  # or "active", "connect"
    )
    
    # Check specific site's BGP peers
    get_org_bgp_peers_enhanced(
        org_id="xxx",
        site_id="yyy"
    )
    
    # Check EVPN overlay peers
    get_org_bgp_peers_enhanced(
        org_id="xxx",
        route_type="evpn"
    )

Step 3 - Detailed EVPN Validation (use shell commands AFTER BGP check):
    Only use execute_custom_shell_command() for:
    - show evpn database (MAC/IP learning)
    - show evpn instance (VNI status)
    - show interfaces vtep (VTEP health)
    - show evpn ip-prefix-database (Type 5 routes)



WHY THIS TOOL IS SUPERIOR TO SHELL COMMANDS FOR BGP:
====================================================
✓ Single API call retrieves ALL BGP peers across entire fabric
✓ Automatic health analysis and scoring
✓ No per-device delay (shell commands take ~5-10 seconds EACH)
✓ Structured JSON response vs parsing CLI output
✓ Built-in filtering, pagination, and time-range support
✓ Historical data available (duration: 1h, 1d, 1w, 1m)

API Used: GET /api/v1/orgs/{org_id}/stats/bgp_peers/search

Parameters:
    org_id (str): Organization ID (REQUIRED)
    bgp_peer (str): BGP peer IP address or hostname filter
    neighbor_mac (str): Neighbor device MAC address filter
    site_id (str): Filter by specific site
    vrf_name (str): VRF name filter
    mac (str): Local device MAC address filter
    start (int): Start time as Unix timestamp (overrides duration)
    end (int): End time as Unix timestamp (used with start)
    duration (str): Time period - "1h", "6h", "1d", "1w", "1m" (default: "6h")
    limit (int): Max entries per page (default: 100, max: 1000)
    page (int): Page number for pagination (default: 1)
    peer_status (str): Filter by BGP state (established, idle, active, connect, opensent, openconfirm)
    asn (str): Filter by Autonomous System Number
    route_type (str): Filter by route type (ipv4, ipv6, evpn, l3vpn)
    discovery_mode (bool): Auto-enabled when no filters provided

Discovery Mode (Auto-enabled when no filters):
    When discovery_mode=True or no filters provided:
    - Returns ALL BGP peers for comprehensive health overview
    - Provides aggregate statistics and health summary
    - Groups results by peer status, ASN, and route types
    - Calculates overall health score (0-100)
    - Identifies potential issues automatically
    - Shows peer distribution and performance metrics

Returns:
    JSON with:
    - bgp_peers: Array of BGP peer objects with detailed metrics
    - bgp_analysis: Comprehensive health analysis (in discovery mode)
    - health_summary: Overall status and health score
    - peer_status_summary: Count by state (established/idle/down)
    - as_distribution: Peers grouped by ASN
    - route_type_distribution: Peers by address family
    - performance_metrics: Uptime, routes, flaps, health indicators
    - network_topology: Unique ASNs, EVPN/IPv4/IPv6 peer counts
    
Example Workflow for EVPN Fabric Health Check:
    1. Get user info and topology → identify org_id, site_id
    2. Check alarms → get_alarms()
    3. CHECK BGP HEALTH → get_org_bgp_peers_enhanced(org_id, discovery_mode=True)
    4. IF health_score < 90 → investigate specific issues with filters
    5. THEN use shell commands for EVPN-specific details (database, VTEPs)
    6. Analyze events for historical patterns
"""

GET_ORG_STATS_TOOL_DOC = """

    ORGANIZATION TOOL #2: Enhanced Organization Statistics Analyzer with Multiple Stats Types
    
    Function: Retrieves comprehensive statistics and metrics for a specific organization
              with support for multiple specialized statistics endpoints including general stats,
              assets, devices, MX edges, and other infrastructure components with flexible 
              time range and filtering controls
    
    API Used: Multiple Mist API endpoints based on stats_type parameter:
    - GET /api/v1/orgs/{org_id}/stats (general organization statistics)
    - GET /api/v1/orgs/{org_id}/stats/assets (asset tracking and management statistics)  
    - GET /api/v1/orgs/{org_id}/stats/devices (device-specific statistics across all device types)
    - GET /api/v1/orgs/{org_id}/stats/mxedges (MX Edge statistics for SD-WAN and edge computing)
    - GET /api/v1/orgs/{org_id}/stats/bgp_peers (BGP peering statistics for routing analysis)
    - GET /api/v1/orgs/{org_id}/stats/sites (site-level aggregated statistics)
    - GET /api/v1/orgs/{org_id}/stats/clients (client connection and usage statistics)
    
    Parameters:
    - org_id (str): Organization ID to retrieve statistics for (required)
    - stats_type (str): Type of statistics to retrieve (default: "general")
                       Valid values: "general", "assets", "devices", "mxedges", "bgp_peers", 
                                   "sites", "clients", "tunnels", "wireless", "wired"
    - page (int): Page number for pagination (default: 1)
    - limit (int): Maximum number of entries per page (default: 100, max: 1000)
    - start (int): Start time as Unix timestamp (optional, overrides duration)
    - end (int): End time as Unix timestamp (optional, used with start)
    - duration (str): Time period when start/end not specified (default: "1d")
                     Valid values: "1h", "1d", "1w", "1m"
    - device_type (str): Filter by device type for device stats (ap, switch, gateway, mxedge)
    - site_id (str): Filter by specific site ID for scoped statistics
    
    Response Handling:
    - Returns JSON with comprehensive organization metrics and statistics based on type
    - Shows total counts, performance metrics, and time-series data for the specified type
    - Includes specialized metrics per stats type (assets: tracking/location, devices: health/performance)
    - Reports network performance statistics over specified time range
    - Contains Service Level Expectation (SLE) metrics where applicable
    - Shows alarm and event summary statistics for the time period
    - Supports pagination for large datasets with next page indicators
    
    Time Range Logic:
    - If start & end provided: Uses specific timestamp range (Unix timestamps)
    - If only duration provided: Uses relative time period from now
    - Default duration: "1d" (last 24 hours)
    - Statistics data updated every 10 minutes, recommended 1-hour intervals for trends
    
    Enhanced Features:
    - Multi-endpoint support for specialized statistics types
    - Flexible time range control (absolute timestamps or relative duration)
    - Pagination support for large organizations with many resources
    - Device-type filtering for focused analysis
    - Site-scoped statistics for multi-site organizations
    - Trend analysis compared to previous periods using time series data
    - Performance benchmarking against org baselines over time
    - Geographic distribution of resources and usage patterns
    - Health score calculation and reporting with historical context
    - Resource utilization efficiency metrics with time-based analysis
    - Enhanced error handling and fallback mechanisms
    
    Stats Type Descriptions:
    - "general": Overall organization health, sites, devices, users, performance
    - "assets": Asset tracking, location services, asset management metrics
    - "devices": Device health, performance, connectivity across all device types
    - "mxedges": MX Edge specific stats for SD-WAN, tunnels, edge services
    - "bgp_peers": BGP routing statistics, peer status, route advertisements
    - "sites": Site-level aggregated statistics and performance metrics
    - "clients": Wireless and wired client statistics, sessions, usage patterns
    - "tunnels": VPN and overlay tunnel statistics, performance, availability
    - "wireless": Wi-Fi specific statistics, RF performance, client experience
    - "wired": Ethernet/switch statistics, port utilization, link performance
    
    Use Cases:
    - Comprehensive organization health monitoring with specialized focus areas
    - Asset management and tracking analysis for location-aware deployments
    - Device fleet management and performance optimization across device types
    - SD-WAN and edge computing performance analysis via MX Edge stats
    - Network routing analysis and BGP peer performance monitoring
    - Multi-site performance comparison and benchmarking
    - Client experience analysis across wireless and wired infrastructure
    - Capacity planning and resource allocation based on historical trends
    - Performance trend analysis and reporting over custom time ranges
    - Executive summary and KPI reporting with specific date ranges and focus
    - Multi-organization comparison and benchmarking over time periods
    - Compliance reporting with specific audit time windows
    - Historical analysis for troubleshooting performance issues
"""

SEARCH_ORG_WIRED_CLIENTS_DOC = """
    CLIENT TOOL #2: Search Organization Wired Clients
    
    Function: Search for wired clients across an organization with detailed
              filtering options for switch-connected devices
    
    API Used: GET /api/v1/orgs/{org_id}/wired_clients/search
    
    Parameters:
    - org_id (str): Organization ID (required)
    - auth_state (str): Authentication state
    - auth_method (str): Authentication method used
    - source (str): Source of client learning (lldp, mac)
    - site_id (str): Filter by specific site
    - device_mac (str): Gateway/Switch MAC where client connected
    - mac (str): Client MAC address (partial/full)
    - port_id (str): Switch port where client connected
    - vlan (int): VLAN ID
    - ip_address (str): Client IP address
    - manufacture (str): Client manufacturer
    - text (str): General search (MAC, hostname, username)
    - nacrule_id (str): NAC rule ID if matched
    - dhcp_hostname (str): DHCP hostname
    - dhcp_fqdn (str): DHCP FQDN
    - dhcp_client_identifier (str): DHCP client identifier
    - dhcp_vendor_class_identifier (str): DHCP vendor class
    - dhcp_request_params (str): DHCP request parameters
    - limit (int): Maximum results (default: 100)
    - start (int): Start time (epoch or relative)
    - end (int): End time (epoch or relative)
    - duration (str): Time duration (e.g., 1d, 1w)
    
    Response Handling:
    - Returns JSON array of wired clients matching criteria
    - Shows client MAC, IP, and connection port details
    - Reports authentication status and method
    - Includes DHCP information and fingerprinting
    - Shows VLAN assignments and NAC rule matches
    - Reports switch/port connection information
    
    Enhanced Features:
    - DHCP fingerprinting and analysis
    - NAC integration and rule tracking
    - Port-level client visibility
    - LLDP neighbor discovery
    - Authentication method tracking
    - Manufacturer identification
    
    Use Cases:
    - Troubleshoot wired connectivity issues
    - Audit switch port usage and connections
    - Track NAC policy enforcement
    - Monitor VLAN assignments
    - Investigate unauthorized devices
    - Generate wired client inventory
"""    

SEARCH_ORG_NAC_CLIENTS_DOC = """
    CLIENT TOOL #3: Search Organization NAC Clients
    
    Function: Search for NAC (Network Access Control) clients across an organization
              with comprehensive filtering for policy enforcement and compliance
    
    API Used: GET /api/v1/orgs/{org_id}/nac_clients/search
    
    Parameters:
    - org_id (str): Organization ID (required)
    - nacrule_id (str): NAC Policy Rule ID if matched
    - nacrule_matched (bool): Whether NAC rule was matched
    - auth_type (str): Authentication type (eap-tls, eap-peap, mab, psk, etc.)
    - vlan (str): VLAN name or ID assigned
    - nas_vendor (str): Vendor of NAS device
    - idp_id (str): SSO/Identity Provider ID if used
    - ssid (str): SSID name
    - username (str): Username presented by client
    - timestamp (float): Start time in epoch
    - site_id (str): Site ID filter
    - ap (str): AP MAC connected to
    - mac (str): Client MAC address
    - mdm_managed (bool): Filter by MDM management status
    - status (str): Connection status (permitted, denied, session_started, session_ended)
    - type (str): Client type (wireless, wired)
    - mdm_compliance (str): MDM compliance status
    - family (str): Client family (Phone/Tablet, Access Point, etc.)
    - model (str): Client model
    - os (str): Client operating system
    - hostname (str): Client hostname
    - mfg (str): Client manufacturer
    - mdm_provider (str): MDM provider (intune, jamf, etc.)
    - sort (str): Sort options (- prefix for DESC)
    - usermac_label (list): Labels from usermac entry
    - ingress_vlan (str): Vendor-specific VLAN in RADIUS
    - start (int): Start time (epoch or relative)
    - end (int): End time (epoch or relative)
    - duration (str): Time duration (default: 1d)
    - limit (int): Max results (default: 100)
    - page (int): Page number (default: 1)
    
    Response Handling:
    - Returns JSON array of NAC clients with compliance details
    - Shows authentication type and status
    - Reports NAC rule matches and policy enforcement
    - Includes MDM integration and compliance status
    - Shows device profiling and classification
    - Reports connection status and session details
    
    Enhanced Features:
    - NAC policy rule tracking and analysis
    - MDM integration and compliance monitoring
    - Multi-factor authentication tracking
    - Device profiling and fingerprinting
    - Session state management
    - Identity provider integration
    
    Use Cases:
    - Monitor NAC policy enforcement
    - Track MDM compliance across devices
    - Audit authentication methods and success rates
    - Investigate policy violations
    - Generate compliance reports
    - Troubleshoot NAC authentication issues
"""    

SEARCH_ORG_WIRELLESS_CLIENTS_DOC = """
    CLIENT TOOL #1: Search Organization Wireless Clients
    
    Function: Search for wireless clients across an organization with comprehensive
              filtering options and client details
    
    API Used: GET /api/v1/orgs/{org_id}/clients/search
    
    Parameters:
    - org_id (str): Organization ID (required)
    - site_id (str): Filter by specific site ID
    - mac (str): Partial/full MAC address to search
    - ip_address (str): Client IP address
    - hostname (str): Partial/full hostname
    - band (str): Radio band (24, 5, 6)
    - device (str): Device type (e.g., Mac, iPhone, Android)
    - os (str): Operating system (for Marvis Client app users)
    - model (str): Device model (for Marvis Client app users)
    - ap (str): AP MAC where client connected
    - psk_id (str): PSK ID for PPSK authentication
    - psk_name (str): PSK name for PPSK authentication
    - username (str): Username for 802.1X authentication
    - vlan (str): VLAN assignment
    - ssid (str): SSID name
    - text (str): General text search (MAC, hostname, username, IP)
    - limit (int): Maximum results (default: 100)
    - start (int): Start time (epoch or relative)
    - end (int): End time (epoch or relative)
    - duration (str): Time duration (e.g., 1d, 1w)
    
    Response Handling:
    - Returns JSON array of wireless clients matching criteria
    - Shows client MAC, IP, hostname, and connection details
    - Reports authentication method and status
    - Includes device type, OS, and model information
    - Shows connection metrics (RSSI, data rates, band)
    - Reports VLAN assignments and PSK details
    
    Enhanced Features:
    - Multi-dimensional search capabilities
    - Real-time and historical client data
    - Authentication method tracking
    - Device fingerprinting and classification
    - Connection quality metrics
    - Roaming history and patterns
    
    Use Cases:
    - Troubleshoot client connectivity issues
    - Track specific devices across the network
    - Audit authentication methods and success rates
    - Monitor client distribution across bands/SSIDs
    - Investigate security incidents
    - Generate client inventory reports
"""    


# =============================================================================
# CRITICAL TECHNICAL FACTS FROM JUNIPER DOCUMENTATION
# =============================================================================

EVPN_TECHNICAL_FACTS = {
    "type_2_type_5_coexistence": {
        "overview": """
        Enhanced EVPN Type 2 and Type 5 Route Coexistence (2024-2025)
        
        Type 2 Routes: Advertise MAC/IP bindings from end systems  
        Type 5 Routes: Advertise IP prefixes for inter-subnet routing
        
        - Automatic coexistence in edge,core,distribution fabrics version ≥3 improves MAC-VRF scaling:
        - Automatic coexistence support for collasped core or EVPN multihoming(MIST) with 2-4 cores,farbic version ≥5.
        - QFX5120 without coexistence: max 56k IPv4 ARP entries
        - QFX5120 with coexistence: max 200k IPv4 ARP entries
        - Type 5 routes preferred over Type 2 (except ESI-LAG learned routes)
        """,
        "configuration_requirements": [
            "Fabric version ≥3 for automatic Type-2/Type-5 coexistence",
            "Policy statement evpn_export_type5 for selective Type 5 advertisement", 
            "For OSPF, asymmetric Type 2 routing is required for IRB,done by vpn_export_type5 policy, add term to disable Type 5 export for IRB subnet configured for OSPF ",
            "For eBGP peering, TTL > 2 is required if nexthop is direct and not via ESI lag",
            "Enhanced OISM support for optimized multicast with Type 5 routes, require MAC VRF instance",
        ],
        "mist_automation": [
            "Automatic Type-2/Type-5 coexistence if fabric_version is higher than 3",
            "Auto-generated evpn_export_type5 policy for host/direct routes",
            "Enhanced OISM for multicast optimization avaliable via additional_cli n configuration, requires MAC VRF. MIST auto-configures MAC VRF only for ipv6 underlay",
            "Seamless scaling for QFX5120, EX4400, EX4100 platforms"
        ]
    },
    
    "bgp_peering_strategies": {
        "underlay_peering": {
            "protocol": "EBGP (External BGP)",
            "design": "Unique AS per device (private AS range 65001+)",
            "benefits": ["Fast convergence with BFD", "Simple policy control", "Vendor interoperability"],
            "mist_implementation": [
                "Auto-provisioned private AS numbers per device",
                "BFD enabled with 1000ms intervals for fast convergence",
                "ECMP load balancing across equal-cost paths",
                "Point-to-point /31 addressing between layers",
                "Support for 2-byte or 4-byte AS numbers",
                "MAC VRF instance configured automaticaly for IPv6 underlay"
                "IPv4 underaly uses default switch VRF"
            ]
        },
        "overlay_peering": {
            "ipv4_fabric": {
                "protocol": "EBGP for both underlay and overlay",
                "design": "Full mesh in given pod, where access peers only with distribution, distribution peers with core and core peers with border,VTEP over IPv4 Loopback",
                "peering": "Spine devices as route reflectors, leaf devices as clients",
                "benefits": ["simplier, easy to remember addressing", "Custom loopback assigment", "Scalable design"],
                "mist_support": "Full IPv4 fabric support"
            },
            "ipv6_fabric": {
                "protocol": "eBGP for both underlay and overlay (Junos OS 21.2R2+)",
                "design": "IPv6 interface addressing with IPv6 BGP sessions, VTEP over IPv6 Loopback",
                "benefits": ["Extended addressing", "Automatic MAC-VRF support", "OISM-BDNE capability"],
                "mist_support": "Full IPv6 fabric support"
            }
        }
    },
    
    "overlay_service_types": {
        "edge": {
            "routing_location": "Access/Leaf devices (IP-CLOS in Mist Campus)",
            "complexity": "Higher complexity, optimal performance",
            "vtep_location": "Access/Leaf devices and Core (if no Service Block)",
            "irb_interfaces": "Access/Leaf devices",
            "best_for": "East-west traffic optimization, microsegmentation with GBP, maximum scale",
            "co-existance": "Automatic Type-2/Type-5 coexistence (fabric_version is higher than 3)",
            "mist_name": "IP-CLOS",
            "characteristics": [
                "Optimal east-west traffic patterns",
                "Support for microsegmentation with Group-Based Policy (GBP)",
                "Maximum fabric scalability",
                "Single or multi-site fabric support"
            ]
        },
        "distribution": {
            "routing_location": "Distribution devices (ERB - Edge Routed Bridging)",
            "complexity": "Moderate complexity, stable design",
            "vtep_location": "Distribution devices and Core/Service Block",
            "irb_interfaces": "Distribution devices",
            "best_for": "East-west traffic, distributed gateway, access layer stability",
            "co-existance": "Automatic Type-2/Type-5 coexistence (fabric_version is higher than 3)",
            "mist_name": "Core-Distribution ERB",
            "characteristics": [
                "Access switches remain Layer 2 only (no BGP/EVPN needed)",
                "Optimized for east-west traffic patterns",
                "Stable design for large enterprise deployments"
            ]
        },
        "core": {
            "routing_location": "Core devices (CRB - Centrally Routed Bridging)",
            "complexity": "Moderate complexity",
            "vtep_location": "Core, Distribution, and Service Block devices",
            "irb_interfaces": "Core devices",
            "best_for": "North-south traffic optimization, centralized routing control",
            "mist_name": "Core-Distribution CRB",
            "characteristics": [
                "Optimized for north-south traffic patterns",
                "Centralized routing and policy enforcement",
                "Simpler access layer requirements"
            ]
        },
        "collapsed-core": {
            "routing_location": "Core devices only (2-4 device limit)",
            "complexity": "Simplest design, limited scale",
            "vtep_location": "Core devices only",
            "irb_interfaces": "Core devices only",
            "best_for": "Small to medium deployments, simplified operations",
            "co-existance": "Automatic Type-2/Type-5 coexistence (fabric_version is higher than 5)",
            "mist_name": "EVPN Multihoming",
            "characteristics": [
                "Maximum 4 core devices supported",
                "No Service Block/Border capability", 
                "Maximum 100 access devices",
                "ESI-LAG multihoming from access layer"
            ]
        },
        "bridged": {
            "routing_location": "External to fabric",
            "complexity": "Simplest - pure Layer 2 extension",
            "vtep_location": "Access devices and Service Block (if enabled)",
            "irb_interfaces": "None (external routing required)",
            "best_for": "Legacy applications, Layer 2 extension, migration scenarios",
            "characteristics": [
                "Pure Layer 2 fabric extension",
                "External routing dependency",
                "Caution needed with firewall-based routing (ARP/DHCP load)"
            ]
        }
    },

    "campus_fabric_architectures": {
        "ip_clos": {
            "description": "Full EVPN-VXLAN fabric from access to core",
            "routing_type": "edge",
            "characteristics": [
                "All devices run EVPN-VXLAN",
                "Maximum scalability and performance",
                "Group-Based Policy (GBP) microsegmentation",
                "Optimal east-west traffic handling"
            ],
            "mist_workflow": "Campus Fabric IP CLOS",
            "use_cases": ["Large enterprise", "Data center interconnect", "Maximum performance requirements"]
        },
        "core_distribution_erb": {
            "description": "EVPN-VXLAN in core/distribution, Layer 2 access",
            "routing_type": "distribution",
            "characteristics": [
                "Access switches remain simple Layer 2",
                "ESI-LAG multihoming to distribution",
                "Standards-based LACP connectivity",
                "Gradual migration path from legacy"
            ],
            "mist_workflow": "Campus Fabric Core-Distribution ERB",
            "use_cases": ["Enterprise with existing access layer", "Gradual EVPN migration"]
        },
        "core_distribution_crb": {
            "description": "EVPN-VXLAN with centralized routing at core",
            "routing_type": "core", 
            "characteristics": [
                "Centralized routing and policy control",
                "Optimized north-south traffic",
                "Simpler distribution layer design"
            ],
            "mist_workflow": "Campus Fabric Core-Distribution CRB",
            "use_cases": ["North-south heavy traffic", "Centralized policy requirements"]
        },
        "evpn_multihoming": {
            "description": "Collapsed core with EVPN multihoming",
            "routing_type": "collapsed-core",
            "characteristics": [
                "2-4 core devices maximum",
                "ESI-LAG active-active multihoming",
                "Eliminates need for MC-LAG/VRRP",
                "Standards-based alternative to proprietary solutions"
            ],
            "mist_workflow": "Campus Fabric EVPN Multihoming",
            "use_cases": ["Small to medium enterprise", "MC-LAG replacement", "Simplified operations"]
        }
    },

    "performance_optimization": {
        "large_organization_discovery": {
            "problem": "Inefficient to check every device for EVPN/BGP data",
            "solution": "Use device filtering and model-based optimization (?type=switch)",
            "optimization_strategy": [
                "Filter devices by type=switch before EVPN analysis",
                "Check device models for EVPN capability",
                "Target Border/access devices with VTEP functionality",
                "Skip non-EVPN access devices for BGP analysis"
            ],         
            "switch_model_indicators": {
                "evpn_capable": ["EX4100", "EX4400", "EX4650", "EX9200", "QFX5110", "QFX5120", "QFX5130", "QFX5700", "QFX10000"],
                "high_scale": ["QFX5120", "QFX5130", "QFX5700", "QFX10000", "EX9200"],
                "minimum_fabric_size": 4
            }
        },
        "mac_vrf_scaling": {
            "issue": "VTEP scaling with multiple MAC-VRF instances",
            "solutions": [
                "Enable Type-2/Type-5 coexistence (fabric_version is higher than 53)",
                "Configure shared tunnels on QFX5000/EX4400 series",
                "Optimize MAC learning with EVPN control plane",
                "configure set forwarding-options evpn-vxlan shared-tunnels",
                "Use Enhanced OISM for multicast efficiency"
            ],
            "mist_optimizations": [
                "Automatic shared tunnel configuration",
                "Type-2/Type-5 coexistence by default",
                "Enhanced OISM integration",
                "BFD fast convergence (1000ms/3000ms)"
            ]
        },
        "enhanced_oism": {
            "description": "Optimized Intersubnet Multicast with EVPN integration",
            "benefits": [
                "Eliminates multicast flooding in EVPN fabric",
                "Supports PIM passive mode integration", 
                "Supplemental Bridge Domain (SBD) optimization",
                "IGMP snooping proxy mode support"
            ],
            "mist_integration": [
                "Automatic SBD configuration",
                "PIM passive mode on all VRFs",
                "IGMP snooping proxy automation",
                "Multi-VRF multicast isolation"
            ]
        }
    },
    "mist_specific_features": {
        "automation_capabilities": [
            "Zero-touch fabric provisioning",
            "Automatic AS number assignment",
            "BFD configuration with optimal timers",
            "ECMP load balancing enablement",
            "Type-2/Type-5 coexistence automation"
        ],
        "ai_operations": [
            "Marvis AI for fabric troubleshooting",
            "Anomaly detection for EVPN routes",
            "Predictive fabric health monitoring",
            "Automated root cause analysis"
        ],
        "monitoring_integration": [
            "Real-time BGP session monitoring",
            "VXLAN tunnel health tracking",
            "ESI-LAG load balancing statistics",
            "SLE (Service Level Expectation) metrics"
        ]
    },
    ## UNUSED PORTION
    
    "ospf_evpn_integration": {
        "use_cases": [
            "OISM (Optimized Intersubnet Multicast) implementations",
            "PIM multicast routing integration with EVPN fabric",
            "External connectivity requiring OSPF adjacencies"
        ],
        "configuration_considerations": [
            "OSPF used on server leaf devices for multicast routing",
            "PIM (Protocol Independent Multicast) configuration on border leafs",
            "Integration with external PIM routers and RP (Rendezvous Point)",
            "OSPF areas design for optimal multicast forwarding"
        ],
        "multicast_integration": """
        # OSPF configuration on server leaf for OISM
        set protocols ospf area 0.0.0.0 interface lo0.0 passive
        set protocols ospf area 0.0.0.0 interface irb.100 passive  
        set protocols ospf area 0.0.0.0 interface irb.200 passive
        
        # PIM configuration for multicast routing
        set protocols pim interface all
        set protocols pim rp static address 192.168.255.1
        """
    },


}

# =============================================================================
# FABRIC HEALTH AND TROUBLESHOOTING PATTERNS  
# =============================================================================

FABRIC_HEALTH_INDICATORS = {
    "healthy_fabric_signs": [
        "All spine-leaf BGP sessions established",
        "EVPN routes properly advertised and received",
        "VXLAN tunnels established between VTEPs",
        "MAC learning working across fabric",
        "No duplicate MAC detections",
        "No routing loops or black holes"
    ],
    "common_issues": {
        "bgp_peering_failures": [
            "AS number conflicts in EBGP design",
            "BFD session failures due to timing", 
            "ECMP load balancing not functioning",
            "Point-to-point link addressing issues (/31)",
            "Loopback IP conflicts"
        ],
        "evpn_overlay_issues": [
            "Route target import/export policy issues",
            "VNI to VLAN mapping inconsistencies",
            "IRB interface subnet overlaps",
            "Type-2/Type-5 route preference conflicts",
            "ESI-LAG configuration inconsistencies", 
            "Enhanced OISM multicast forwarding failures"            
        ],
        "vxlan_dataplane_issues": [
            "VTEP reachability problems",
            "MTU mismatches causing fragmentation",
            "VNI encapsulation/decapsulation errors",
            "MAC address table overflow"
        ],
        "mist_platform_specific": [
            "Template synchronization delays",
            "Campus fabric workflow configuration errors",
            "Site vs organization-level fabric conflicts",
            "Device adoption into wrong fabric topology",
            "Device commit errors"
        ]        
    }
}

# =============================================================================
# INTEGRATION HELPER FUNCTIONS
# =============================================================================

def get_tool_documentation(tool_name: str) -> str:
    """
    Retrieve comprehensive documentation for specific EVPN tool
    Updated with 2024-2025 Mist campus fabric context
    """
    try:
        docs = {
            'get_org_evpn_topologies': EVPN_ORG_TOOL_DOC,
            'get_site_evpn_topologies': EVPN_SITE_TOOL_DOC,
            'get_evpn_topologies_details': EVPN_DETAILS_TOOL_DOC,
            'get_site_devices': SITE_DEVICES_TOOL_DOC,
            'execute_custom_shell_command': EXECUTE_CUSTOM_SHELL_COMMAND,
            'get_enhanced_device_info': GET_ENHANCED_DEVICE_INFO,
            'get_org_bgp_peers_enhanced': GET_BGP_PEERS_ENHANCED_DOC,
            'get_org_stats_enhanced': GET_ORG_STATS_TOOL_DOC,
            'search_org_wired_clients': SEARCH_ORG_WIRED_CLIENTS_DOC,
            'search_org_nac_clients': SEARCH_ORG_NAC_CLIENTS_DOC,
            'search_org_wireless_clients': SEARCH_ORG_WIRELLESS_CLIENTS_DOC
        }
        doc = docs.get(tool_name)
        if isinstance(doc, str) and doc.strip():
            return doc
    except Exception:
        # Fall through to default message on any failure
        pass
    return f"Documentation for '{tool_name}' not available."

def get_technical_fact(category: str, subcategory: str = None) -> dict:
    """
    Retrieve specific technical facts from enhanced Juniper documentation
    
    Args:
        category: Main category (e.g., 'overlay_service_types')
        subcategory: Optional subcategory for nested facts
        
    Returns:
        Dictionary containing relevant technical information
    """
    fact = EVPN_TECHNICAL_FACTS.get(category, {})
    if subcategory and isinstance(fact, dict):
        return fact.get(subcategory, {})
    return fact

def get_discovery_strategy() -> dict:
    """
    Get optimized discovery strategy for large organizations (2024-2025)
    """
    return EVPN_TECHNICAL_FACTS['performance_optimization']['large_organization_discovery']

def get_mist_fabric_types() -> dict:
    """
    Get Mist-specific campus fabric architecture types
    """
    return EVPN_TECHNICAL_FACTS['campus_fabric_architectures']

def get_fabric_health_indicators() -> dict:
    """
    Get enhanced fabric health indicators including Mist-specific metrics
    """
    return FABRIC_HEALTH_INDICATORS


# =============================================================================
# USAGE EXAMPLES FOR MCP SERVER INTEGRATION
# =============================================================================

"""
Integration Example in MCP Server:

# In your main MCP server file:
from evpn_fabric_docs import get_tool_documentation, get_technical_fact

@safe_tool_definition("get_org_evpn_topologies", "evpn")
async def get_org_evpn_topologies(org_id: str) -> str:
    '''
    Organization-Level EVPN Topology Manager
    
    For detailed documentation, see evpn_fabric_docs module.
    '''
    try:
        # Your existing implementation
        result = await original_implementation(org_id)
        
        # Optionally enhance with documentation
        enhanced_result = json.loads(result)
        enhanced_result["documentation_reference"] = "See evpn_fabric_docs.EVPN_ORG_TOOL_DOC"
        
        return json.dumps(enhanced_result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed: {str(e)}"}, indent=2)

# Access technical facts:
type2_type5_info = get_technical_fact('type_2_type_5_coexistence')
bgp_strategy = get_technical_fact('bgp_peering_strategies', 'underlay_peering')
discovery_optimization = get_discovery_strategy()
"""

if __name__ == "__main__":
    # Display documentation module summary
    print("EVPN Fabric Documentation Module Summary")
    print("=" * 50)
    print(f"Tool Documentations: 3")
    print(f"Technical Fact Categories: {len(EVPN_TECHNICAL_FACTS)}")
    print(f"Health Indicators: {len(FABRIC_HEALTH_INDICATORS)}")
    print(f"Integration Functions: 6")
    print("\nKey Technical Areas:")
    for category in EVPN_TECHNICAL_FACTS.keys():
        print(f"  • {category.replace('_', ' ').title()}")
    print("\nMist Campus Fabric Types:")
    mist_fabrics = EVPN_TECHNICAL_FACTS['campus_fabric_architectures']
    for fabric_name, details in mist_fabrics.items():
        print(f"  • {fabric_name.replace('_', ' ').title()}: {details['description']}")
