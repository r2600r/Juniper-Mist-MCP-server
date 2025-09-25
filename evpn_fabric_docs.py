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
# ORGANIZATION VS SITE LEVEL FABRIC ARCHITECTURE
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
    - site_specific_fabric = false is return
    - Multiple fabrics per org supported but are not common


    2. **Site-Level Fabrics:**
    - site_specific_fabric = true is return
    - Contained within a single site boundary
    - Share the same switch template configuration
    - Multiple fabrics can exist within one site
    - Used for localized network segments

    Response Handling:
    - site fabric when site_specific_fabric is true is return
    - organization fabric when site_specific_fabric is false is return
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

    Function: Retrieves site-specific EVPN fabrics contained within a single site.
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
    - when site_specific_fabric = true is return
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
    - site_specific_fabric = true is return , Site-Level Fabrics, use site_id,  /api/v1/sites/{site_id}/evpn_topologies/{topology_id}
    - site_specific_fabric = false is return, Multi Site Fabrics, use org_id,  /api/v1/orgs/{org_id}/evpn_topologies/{topology_id}


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
            "Automatic Type-2/Type-5 coexistence in fabric version ≥3",
            "Auto-generated evpn_export_type5 policy for host/direct routes",
            "Integrated with Enhanced OISM for multicast optimization",
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
                "Support for 2-byte or 4-byte AS numbers"
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
            "co-existance": "Automatic Type-2/Type-5 coexistence (fabric version ≥3)",
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
            "co-existance": "Automatic Type-2/Type-5 coexistence (fabric version ≥3)",
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
            "co-existance": "Automatic Type-2/Type-5 coexistence (fabric version ≥5)",
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
                "Target spine/leaf devices with VTEP functionality",
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
                "Enable Type-2/Type-5 coexistence (automatic in fabric v≥3)",
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
    docs = {
        'get_org_evpn_topologies': EVPN_ORG_TOOL_DOC,
        'get_site_evpn_topologies': EVPN_SITE_TOOL_DOC, 
        'get_evpn_topologies_details': EVPN_DETAILS_TOOL_DOC,
        'get_site_devices': SITE_DEVICES_TOOL_DOC
    }
    return docs.get(tool_name, "Documentation not available")

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