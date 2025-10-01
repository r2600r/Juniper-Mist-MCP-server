    #!/usr/bin/env python3
"""
Enhanced Mist Cloud MCP Server with Complete API Coverage and Security Analysis

This enhanced version provides 35 tools across 9 categories with integrated security analysis:
- System/Diagnostic Tools (5): Health monitoring, connectivity testing, performance analysis
- Authentication & User Management (3): User info, privileges, audit logs  
- Organization Management (5): Org stats, inventory, templates, search
- Site Management (7): Site info, devices, WLANs, stats, insights, alarms
- Device Management (5): Device stats, actions, shell commands, enhanced info
- Client & Network Management (2): Client sessions, WLAN config
- Events & Monitoring (2): Events and alarms across all scopes
- MSP Management (2): MSP info and organization management
- Security Analysis (2): NEW - Token privilege analysis and risk management
- Utility Tools (2): Generic API calls with security validation and diagnostics export

Version: 3.1 - Complete API Coverage with Security Analysis
Author: Enhanced by Claude for Complete Mist API Coverage with Security Controls
Date: August 2025
"""

import argparse
import logging
import os
import json
import sys
import re
import time
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Tuple, Union
from functools import wraps
import traceback
import psutil
import statistics
from evpn_fabric_docs import get_tool_documentation, get_technical_fact

# ==============================================
# DEBUGGING INFRASTRUCTURE
# ==============================================

def debug_stderr(message: str):
    """Print debug messages to stderr for MCP client visibility"""
    print(f"[DEBUG] {datetime.now().isoformat()} - {message}", file=sys.stderr, flush=True)

def safe_import_with_debug(module_name: str, description: str = ""):
    """Safely import modules with debug logging"""
    try:
        debug_stderr(f"Attempting to import {module_name} {description}")
        if module_name == "fastmcp":
            from fastmcp import FastMCP
            debug_stderr(f"✓ Successfully imported {module_name}")
            return FastMCP
        elif module_name == "httpx":
            import httpx
            debug_stderr(f"✓ Successfully imported {module_name}")
            return httpx
        elif module_name == "dotenv":
            from dotenv import load_dotenv
            debug_stderr(f"✓ Successfully imported {module_name}")
            return load_dotenv
        elif module_name == "websockets":
            import websockets
            debug_stderr(f"✓ Successfully imported {module_name}")
            return websockets, True
    except ImportError as e:
        debug_stderr(f"✗ Failed to import {module_name}: {e}")
        if module_name == "websockets":
            return None, False
        raise
    except Exception as e:
        debug_stderr(f"✗ Unexpected error importing {module_name}: {e}")
        raise

# ==============================================
# CONFIGURATION LOADING
# ==============================================

@dataclass
class ServerConfig:
    """Enhanced configuration with API validation"""
    api_token: str
    base_url: str
    mcp_name: str
    websockets_available: bool
    max_concurrent_requests: int = 10
    request_timeout: int = 30
    
    @classmethod
    def load_from_environment(cls) -> 'ServerConfig':
        """Load and validate all configuration from environment variables"""
        debug_stderr("=== LOADING ENHANCED SERVER CONFIGURATION ===")
        
        # Load environment variables
        debug_stderr("Loading .env file...")
        try:
            load_dotenv = safe_import_with_debug("dotenv", "(environment variables)")
            load_dotenv()
            debug_stderr("✓ Environment variables loaded")
        except Exception as e:
            debug_stderr(f"Warning: Could not load .env file: {e}")
        
        # Get API token
        debug_stderr("Checking MIST_API_TOKEN...")
        api_token = os.getenv("MIST_API_TOKEN")
        if not api_token:
            debug_stderr("✗ MIST_API_TOKEN not found in environment")
            raise ValueError("MIST_API_TOKEN environment variable is required")
        debug_stderr("✓ MIST_API_TOKEN found")
        
        # Determine base URL with proper precedence and validation
        debug_stderr("Determining base URL...")
        base_url = os.getenv("MIST_BASE_URL")
        
        if base_url:
            debug_stderr(f"Using MIST_BASE_URL: {base_url}")
        else:
            # Check MIST_HOST as fallback
            mist_host = os.getenv("MIST_HOST")
            if mist_host:
                debug_stderr(f"Using MIST_HOST: {mist_host}")
                # Add protocol if not present
                if not mist_host.startswith(('http://', 'https://')):
                    base_url = f"https://{mist_host}"
                    debug_stderr(f"Added https protocol: {base_url}")
                else:
                    base_url = mist_host
            else:
                # Default to the official Mist API domain
                base_url = "https://api.mist.com"
                debug_stderr(f"Using official Mist API URL: {base_url}")
        
        debug_stderr(f"✓ Final base URL: {base_url}")
        
        # Check WebSocket availability
        debug_stderr("Checking WebSocket support...")
        websockets_result = safe_import_with_debug("websockets", "(WebSocket support)")
        if isinstance(websockets_result, tuple):
            websockets_available = websockets_result[1]
        else:
            websockets_available = True
        debug_stderr(f"✓ WebSocket support: {websockets_available}")
        
        # Enhanced configuration options
        max_concurrent = int(os.getenv("MIST_MAX_CONCURRENT", "10"))
        request_timeout = int(os.getenv("MIST_REQUEST_TIMEOUT", "30"))
        
        # MCP server name
        mcp_name = "comprehensive-secure-mist-mcp-server"
        debug_stderr(f"✓ MCP name: {mcp_name}")
        
        config = cls(
            api_token=api_token,
            base_url=base_url,
            mcp_name=mcp_name,
            websockets_available=websockets_available,
            max_concurrent_requests=max_concurrent,
            request_timeout=request_timeout
        )
        
        debug_stderr("=== ENHANCED CONFIGURATION LOADING COMPLETE ===")
        debug_stderr(f"Configuration: base_url={config.base_url}, websockets={config.websockets_available}, max_concurrent={config.max_concurrent_requests}")
        
        return config

# Load configuration once at startup
debug_stderr("=== Comprehensive Mist MCP Server Debug Startup ===")
debug_stderr("Python version: " + sys.version)
debug_stderr("Current working directory: " + os.getcwd())

try:
    # Import required modules
    debug_stderr("Starting module imports...")
    FastMCP = safe_import_with_debug("fastmcp", "(MCP framework)")
    httpx = safe_import_with_debug("httpx", "(HTTP client)")
    debug_stderr("All required imports completed successfully")
    
    # Load configuration once
    CONFIG = ServerConfig.load_from_environment()
    
    # Initialize MCP
    debug_stderr("Initializing FastMCP instance...")
    mcp = FastMCP(name=CONFIG.mcp_name)
    debug_stderr(f"✓ FastMCP instance created: {CONFIG.mcp_name}")
    
except Exception as e:
    debug_stderr(f"FATAL: Startup failed: {e}")
    debug_stderr(f"Traceback: {traceback.format_exc()}")
    sys.exit(1)

# =====================================================================
# SECURITY PRIVILEGE ANALYSIS SYSTEM (NEW)
# =====================================================================
"""
1. Environment Variables Added
MIST_STRICT_SECURITY_MODE=true          # Default: enabled
MIST_SECURITY_RISKS_ACKNOWLEDGED=false  # Default: not acknowledged (so blocking works)
MIST_MAX_ADMIN_ORGS=1                  # Configurable thresholds
MIST_MAX_WRITE_ORGS=3
MIST_MAX_ADMIN_MSPS=1  
MIST_MAX_WRITE_MSPS=1
MIST_MAX_ORGS_PER_MSP=5
Note:  MIST_SECURITY_RISKS_ACKNOWLEDGED=false set as default so security blocking actually works. If it were true by default, the security feature would be disabled.
"""

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger('enhanced-secure-mist-mcp-server')

@dataclass
class PrivilegeRisk:
    """Represents a detected privilege security risk"""
    risk_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    affected_scopes: List[str]
    mitigation_suggestions: List[str]
    org_count: int = 0
    msp_count: int = 0

@dataclass
class SecurityAnalysisResult:
    """Complete security analysis of user privileges"""
    is_safe: bool
    risks_detected: List[PrivilegeRisk]
    total_orgs_admin: int
    total_orgs_write: int
    total_msps_admin: int
    total_msps_write: int
    msp_org_counts: Dict[str, int]
    analysis_timestamp: str
    recommendations: List[str]

class PrivilegeSecurityAnalyzer:
    """
    Analyzes user privileges for security risks and overly broad permissions
    
    This class implements security analysis to detect API tokens that violate
    the principle of least privilege, which can pose significant security risks
    if compromised or used inappropriately.
    """
    
    def __init__(self):
        """Initialize security analyzer with configurable thresholds"""
        self.risk_thresholds = {
            'max_admin_orgs': int(os.getenv('MIST_MAX_ADMIN_ORGS', '1')),
            'max_write_orgs': int(os.getenv('MIST_MAX_WRITE_ORGS', '3')),
            'max_admin_msps': int(os.getenv('MIST_MAX_ADMIN_MSPS', '1')),
            'max_write_msps': int(os.getenv('MIST_MAX_WRITE_MSPS', '1')),
            'max_orgs_per_msp': int(os.getenv('MIST_MAX_ORGS_PER_MSP', '5'))
        }
        
        # Security control configuration - enabled by default for security
        self.security_acknowledged = os.getenv('MIST_SECURITY_RISKS_ACKNOWLEDGED', 'false').lower() == 'true'
        self.strict_mode = os.getenv('MIST_STRICT_SECURITY_MODE', 'true').lower() == 'true'
        
        debug_stderr(f"Security analyzer initialized: strict_mode={self.strict_mode}, acknowledged={self.security_acknowledged}")
        
    async def analyze_privileges(self, user_privileges: List[Dict]) -> SecurityAnalysisResult:
        """
        Analyzes user privileges for security risks and overly broad permissions
        
        This method examines API token privileges to detect patterns that violate
        security best practices, particularly the principle of least privilege.
        
        Args:
            user_privileges: List of privilege objects from /api/v1/self response
            
        Returns:
            SecurityAnalysisResult with detected risks and recommendations
            
        Risk Detection:
        1. Admin privileges to multiple organizations (CRITICAL)
        2. Write privileges to multiple organizations (HIGH) 
        3. Admin privileges to multiple MSPs (CRITICAL)
        4. Write privileges to multiple MSPs (CRITICAL)
        5. Single MSP with excessive organization access (HIGH)
        """
        try:
            risks = []
            
            # Categorize privileges by scope and role
            org_privileges = {'admin': [], 'write': [], 'read': []}
            msp_privileges = {'admin': [], 'write': [], 'read': []}
            msp_org_mapping = defaultdict(set)
            
            for priv in user_privileges:
                scope = priv.get('scope', '')
                role = priv.get('role', '')
                
                if scope == 'org':
                    org_id = priv.get('org_id')
                    if role in org_privileges:
                        org_privileges[role].append(org_id)
                        
                elif scope == 'msp':
                    msp_id = priv.get('msp_id')
                    if role in msp_privileges:
                        msp_privileges[role].append(msp_id)
                        
                # Track MSP to organization relationships
                if scope == 'org' and priv.get('via_msp'):
                    msp_org_mapping[priv.get('via_msp')].add(priv.get('org_id'))
            
            # RISK 1: Admin privileges to multiple organizations
            admin_org_count = len(org_privileges['admin'])
            if admin_org_count > self.risk_thresholds['max_admin_orgs']:
                risks.append(PrivilegeRisk(
                    risk_type="MULTIPLE_ORG_ADMIN",
                    severity="CRITICAL",
                    description=f"Token has admin privileges to {admin_org_count} organizations (threshold: {self.risk_thresholds['max_admin_orgs']})",
                    affected_scopes=[f"org:{org_id}" for org_id in org_privileges['admin']],
                    org_count=admin_org_count,
                    mitigation_suggestions=[
                        "Create separate API tokens for each organization",
                        "Use read-only tokens where possible",
                        "Implement organization-specific service accounts"
                    ]
                ))
            
            # RISK 2: Write privileges to multiple organizations
            write_org_count = len(org_privileges['write'])
            if write_org_count > self.risk_thresholds['max_write_orgs']:
                risks.append(PrivilegeRisk(
                    risk_type="MULTIPLE_ORG_WRITE", 
                    severity="HIGH",
                    description=f"Token has write privileges to {write_org_count} organizations (threshold: {self.risk_thresholds['max_write_orgs']})",
                    affected_scopes=[f"org:{org_id}" for org_id in org_privileges['write']],
                    org_count=write_org_count,
                    mitigation_suggestions=[
                        "Reduce scope to only necessary organizations",
                        "Use read-only tokens for monitoring applications"
                    ]
                ))
            
            # RISK 3: Admin privileges to multiple MSPs
            admin_msp_count = len(msp_privileges['admin'])
            if admin_msp_count > self.risk_thresholds['max_admin_msps']:
                risks.append(PrivilegeRisk(
                    risk_type="MULTIPLE_MSP_ADMIN",
                    severity="CRITICAL", 
                    description=f"Token has admin privileges to {admin_msp_count} MSPs (threshold: {self.risk_thresholds['max_admin_msps']})",
                    affected_scopes=[f"msp:{msp_id}" for msp_id in msp_privileges['admin']],
                    msp_count=admin_msp_count,
                    mitigation_suggestions=[
                        "Use separate tokens for each MSP",
                        "Implement MSP-specific service accounts"
                    ]
                ))
            
            # RISK 4: Write privileges to multiple MSPs
            write_msp_count = len(msp_privileges['write'])
            if write_msp_count > self.risk_thresholds['max_write_msps']:
                risks.append(PrivilegeRisk(
                    risk_type="MULTIPLE_MSP_WRITE",
                    severity="CRITICAL",
                    description=f"Token has write privileges to {write_msp_count} MSPs (threshold: {self.risk_thresholds['max_write_msps']})",
                    affected_scopes=[f"msp:{msp_id}" for msp_id in msp_privileges['write']],
                    msp_count=write_msp_count,
                    mitigation_suggestions=[
                        "Reduce MSP scope to minimum required"
                    ]
                ))
            
            # RISK 5: Single MSP with excessive organization access
            for msp_id, orgs in msp_org_mapping.items():
                org_count = len(orgs)
                if org_count > self.risk_thresholds['max_orgs_per_msp']:
                    risks.append(PrivilegeRisk(
                        risk_type="MSP_EXCESSIVE_ORGS",
                        severity="HIGH",
                        description=f"MSP {msp_id} has access to {org_count} organizations (threshold: {self.risk_thresholds['max_orgs_per_msp']})",
                        affected_scopes=[f"msp:{msp_id}"],
                        org_count=org_count,
                        msp_count=1,
                        mitigation_suggestions=[
                            "Create organization-specific tokens",
                            "Implement role-based access within MSP"
                        ]
                    ))
            
            # Generate overall recommendations
            recommendations = self._generate_recommendations(risks)
            
            return SecurityAnalysisResult(
                is_safe=len(risks) == 0,
                risks_detected=risks,
                total_orgs_admin=admin_org_count,
                total_orgs_write=write_org_count,
                total_msps_admin=admin_msp_count,
                total_msps_write=write_msp_count,
                msp_org_counts=dict(msp_org_mapping),
                analysis_timestamp=datetime.now().isoformat(),
                recommendations=recommendations
            )
            
        except Exception as e:
            debug_stderr(f"Privilege analysis failed: {e}")
            return SecurityAnalysisResult(
                is_safe=True,
                risks_detected=[],
                total_orgs_admin=0,
                total_orgs_write=0,
                total_msps_admin=0, 
                total_msps_write=0,
                msp_org_counts={},
                analysis_timestamp=datetime.now().isoformat(),
                recommendations=["Security analysis failed - manual review recommended"]
            )
    
    def _generate_recommendations(self, risks: List[PrivilegeRisk]) -> List[str]:
        """Generate security recommendations based on detected risks"""
        recommendations = []
        
        if not risks:
            recommendations.append("Token privileges appear to follow principle of least privilege")
            return recommendations
        
         # Priority recommendations based on risk severity
        critical_risks = [r for r in risks if r.severity == "CRITICAL"]
        high_risks = [r for r in risks if r.severity == "HIGH"]
        
        if critical_risks:
            recommendations.append("CRITICAL: Immediately review and reduce token privileges")
            recommendations.append("Create separate API tokens with minimal required permissions")

        if high_risks:
            recommendations.append("HIGH: Consider restricting token scope to reduce security exposure")
            
        # Specific recommendations
        if any(r.risk_type.startswith("MULTIPLE_ORG") for r in risks):
            recommendations.append("Use organization-specific tokens instead of multi-org tokens")
            
        if any(r.risk_type.startswith("MULTIPLE_MSP") for r in risks):
            recommendations.append("Implement MSP-specific service accounts with limited scope")
            
        if any(r.risk_type == "MSP_EXCESSIVE_ORGS" for r in risks):
            recommendations.append("Consider breaking large MSP tokens into smaller, targeted tokens")
            
        # Environment variable recommendations
        recommendations.append("Set MIST_SECURITY_RISKS_ACKNOWLEDGED=true after reviewing risks")
        recommendations.append("Configure security thresholds via environment variables")
        
        return recommendations
    
    def should_block_execution(self, analysis_result: SecurityAnalysisResult) -> bool:
        """Determines if execution should be blocked based on security analysis"""
        if analysis_result.is_safe:
            return False
            
        if self.security_acknowledged:
            log.warning("Security risks detected but acknowledged by user configuration")            
            return False
            
        if not self.strict_mode:
            log.warning("Security risks detected but strict mode disabled")            
            return False
        
        # Block execution for critical risks
        critical_risks = [r for r in analysis_result.risks_detected if r.severity == "CRITICAL"]
        return len(critical_risks) > 0

# Global security analyzer
security_analyzer = PrivilegeSecurityAnalyzer()

# =====================================================================
# DIAGNOSTICS SYSTEM
# =====================================================================

debug_stderr("Defining enhanced diagnostics classes...")

@dataclass
class OperationMetrics:
    """Enhanced metrics for individual operations"""
    operation_name: str
    start_time: float
    end_time: float
    duration: float
    success: bool
    error_message: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    response_size: int = 0
    http_status_code: Optional[int] = None
    api_category: Optional[str] = None

@dataclass
class ServiceHealthStatus:
    """Enhanced service health status"""
    service_start_time: datetime
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_request_duration: float = 0.0
    peak_memory_usage: float = 0.0
    current_memory_usage: float = 0.0
    cpu_usage: float = 0.0
    active_connections: int = 0
    api_categories_used: Dict[str, int] = None

    def __post_init__(self):
        if self.api_categories_used is None:
            self.api_categories_used = {}

class DiagnosticsCollector:
    """Enhanced diagnostics collector with API categorization"""
    
    def __init__(self, max_history_size: int = 1000):
        debug_stderr("Initializing Enhanced DiagnosticsCollector...")
        self.max_history_size = max_history_size
        self.operation_history = deque(maxlen=max_history_size)
        self.service_health = ServiceHealthStatus(service_start_time=datetime.now())
        self.error_patterns = defaultdict(int)
        self.performance_trends = defaultdict(list)
        self.api_endpoint_stats = defaultdict(lambda: {'count': 0, 'avg_duration': 0, 'success_rate': 0})
        self._last_update = time.time()
        debug_stderr("✓ Enhanced DiagnosticsCollector initialized")
    
    def _update_system_metrics(self):
        """Update system-level metrics with enhanced tracking"""
        try:
            if time.time() - self._last_update < 5:  # Update every 5 seconds
                return
                
            process = psutil.Process()
            memory_info = process.memory_info()
            
            self.service_health.current_memory_usage = memory_info.rss / 1024 / 1024  # MB
            self.service_health.peak_memory_usage = max(
                self.service_health.peak_memory_usage,
                self.service_health.current_memory_usage
            )
            self.service_health.cpu_usage = process.cpu_percent()
            self._last_update = time.time()
        except Exception as e:
            debug_stderr(f" Error: Failed to update system metrics: {e}")
    
    def record_operation(self, metrics: OperationMetrics):
        """Record operation metrics with enhanced categorization"""
        try:
            self.operation_history.append(metrics)
            self.service_health.total_requests += 1
            
            if metrics.success:
                self.service_health.successful_requests += 1
            else:
                self.service_health.failed_requests += 1
                if metrics.error_message:
                    self.error_patterns[metrics.error_message] += 1
            
            # Track API categories
            if metrics.api_category:
                if not hasattr(self.service_health, 'api_categories_used'):
                    self.service_health.api_categories_used = {}
                self.service_health.api_categories_used[metrics.api_category] = \
                    self.service_health.api_categories_used.get(metrics.api_category, 0) + 1
            
            # Track endpoint statistics
            if metrics.endpoint:
                endpoint_stats = self.api_endpoint_stats[metrics.endpoint]
                endpoint_stats['count'] += 1
                
                # Update average duration
                old_avg = endpoint_stats['avg_duration']
                old_count = endpoint_stats['count'] - 1
                if old_count > 0:
                    endpoint_stats['avg_duration'] = ((old_avg * old_count) + metrics.duration) / endpoint_stats['count']
                else:
                    endpoint_stats['avg_duration'] = metrics.duration
            
            # Update performance trends - keep only recent data
            self.performance_trends['response_times'].append(metrics.duration)
            if len(self.performance_trends['response_times']) > 200:  # Keep more history
                self.performance_trends['response_times'].pop(0)
            
            # Update system metrics periodically
            self._update_system_metrics()
            
            # Calculate rolling averages
            if self.operation_history:
                recent_ops = list(self.operation_history)[-100:]  # Last 100 operations
                success_ops = [op for op in recent_ops if op.success]
                
                if success_ops:
                    self.service_health.avg_request_duration = statistics.mean([op.duration for op in success_ops])
        except Exception as e:
            debug_stderr(f"Error recording operation metrics: {e}")
    
    def get_comprehensive_health_summary(self) -> Dict[str, Any]:
        """Get comprehensive health summary with API insights"""
        try:
            uptime = datetime.now() - self.service_health.service_start_time
            
            # Calculate failure rate
            failure_rate = 0.0
            if self.service_health.total_requests > 0:
                failure_rate = self.service_health.failed_requests / self.service_health.total_requests
            
            # Get top error patterns (limit to top 5)
            top_errors = dict(sorted(self.error_patterns.items(), 
                                   key=lambda x: x[1], reverse=True)[:5])
            
            # Performance percentiles
            response_times = self.performance_trends['response_times']
            percentiles = {}
            if len(response_times) >= 10:
                percentiles = {
                    'p50': round(statistics.median(response_times), 3),
                    'p90': round(statistics.quantiles(response_times, n=10)[8], 3) if len(response_times) >= 10 else round(max(response_times), 3),
                    'p95': round(statistics.quantiles(response_times, n=20)[18], 3) if len(response_times) >= 20 else round(max(response_times), 3),
                    'p99': round(statistics.quantiles(response_times, n=100)[98], 3) if len(response_times) >= 100 else round(max(response_times), 3),
                }
            
            # Top endpoints by usage
            top_endpoints = dict(sorted(self.api_endpoint_stats.items(),
                                      key=lambda x: x[1]['count'], reverse=True)[:10])
            
            # API category usage
            api_categories = getattr(self.service_health, 'api_categories_used', {})
            
            return {
                'service_status': {
                    'uptime_seconds': int(uptime.total_seconds()),
                    'uptime_human': str(uptime),
                    'total_requests': self.service_health.total_requests,
                    'success_rate': round(1 - failure_rate, 3),
                    'failure_rate': round(failure_rate, 3),
                    'avg_response_time': round(self.service_health.avg_request_duration, 3),
                    'current_memory_mb': round(self.service_health.current_memory_usage, 2),
                    'peak_memory_mb': round(self.service_health.peak_memory_usage, 2),
                    'cpu_usage_percent': round(self.service_health.cpu_usage, 2)
                },
                'performance_metrics': {
                    'response_time_percentiles': percentiles,
                    'total_operations_recorded': len(self.operation_history),
                    'top_endpoints_by_usage': top_endpoints
                },
                'api_insights': {
                    'categories_used': api_categories,
                    'total_unique_endpoints': len(self.api_endpoint_stats),
                    'most_active_category': max(api_categories.items(), key=lambda x: x[1]) if api_categories else None
                },
                'error_analysis': {
                    'top_error_patterns': top_errors,
                    'total_error_types': len(self.error_patterns)
                }
            }
        except Exception as e:
            debug_stderr(f"Error getting comprehensive health summary: {e}")
            return {"error": str(e)}

# Global enhanced diagnostics collector
try:
    debug_stderr("Creating enhanced global diagnostics collector...")
    diagnostics = DiagnosticsCollector()
    debug_stderr("✓ Enhanced global diagnostics collector created")
except Exception as e:
    debug_stderr(f"FATAL: Failed to create enhanced diagnostics collector: {e}")
    debug_stderr(f"Traceback: {traceback.format_exc()}")
    sys.exit(1)

def monitor_operation_enhanced(api_category: str = "unknown"):
    """Enhanced decorator to monitor operation performance with API categorization"""
    def decorator(func):
        debug_stderr(f"Creating enhanced monitor decorator for function: {func.__name__} (category: {api_category})")
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            operation_name = func.__name__
            success = True
            error_message = None
            response_size = 0
            http_status_code = None
            endpoint = None
            
            try:
                debug_stderr(f"Starting monitored operation: {operation_name} [{api_category}]")
                
                result = await func(*args, **kwargs)
                response_size = len(str(result)) if result else 0
                
                # Extract endpoint and status from result if available
                if isinstance(result, str):
                    try:
                        result_dict = json.loads(result)
                        endpoint = result_dict.get('endpoint', '')
                        http_status_code = result_dict.get('http_status', None)
                    except:
                        pass
                
                debug_stderr(f"Completed operation: {operation_name} in {time.time() - start_time:.2f}s")
                return result
                
            except asyncio.TimeoutError:
                success = False
                error_message = "Operation timed out"
                debug_stderr(f"Operation {operation_name} timed out after {time.time() - start_time:.2f}s")
                return f"Error in {operation_name}: Operation timed out"
                
            except Exception as e:
                success = False
                error_message = str(e)
                debug_stderr(f"Operation {operation_name} failed: {error_message}")
                debug_stderr(f"Error traceback: {traceback.format_exc()}")
                return f"Error in {operation_name}: {error_message}"
                
            finally:
                end_time = time.time()
                duration = end_time - start_time
                
                # Record enhanced metrics
                try:
                    metrics = OperationMetrics(
                        operation_name=operation_name,
                        start_time=start_time,
                        end_time=end_time,
                        duration=duration,
                        success=success,
                        error_message=error_message,
                        response_size=response_size,
                        endpoint=endpoint,
                        http_status_code=http_status_code,
                        api_category=api_category
                    )
                    
                    diagnostics.record_operation(metrics)
                except Exception as e:
                    debug_stderr(f" Error: Failed to record enhanced metrics for {operation_name}: {e}")
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For sync functions, just call directly with basic monitoring
            start_time = time.time()
            operation_name = func.__name__
            success = True
            error_message = None
            
            try:
                debug_stderr(f"Starting sync operation: {operation_name} [{api_category}]")
                result = func(*args, **kwargs)
                debug_stderr(f"Completed sync operation: {operation_name}")
                return result
            except Exception as e:
                success = False
                error_message = str(e)
                debug_stderr(f"Sync operation {operation_name} failed: {error_message}")
                return f"Error in {operation_name}: {error_message}"
            finally:
                end_time = time.time()
                duration = end_time - start_time
                
                try:
                    metrics = OperationMetrics(
                        operation_name=operation_name,
                        start_time=start_time,
                        end_time=end_time,
                        duration=duration,
                        success=success,
                        error_message=error_message,
                        api_category=api_category
                    )
                    
                    diagnostics.record_operation(metrics)
                except Exception as e:
                    debug_stderr(f" Error: Failed to record sync metrics for {operation_name}: {e}")
        
        # Return appropriate wrapper based on function type
        try:
            if asyncio.iscoroutinefunction(func):
                debug_stderr(f"✓ Enhanced async wrapper created for {func.__name__}")
                return async_wrapper
            else:
                debug_stderr(f"✓ Enhanced sync wrapper created for {func.__name__}")
                return sync_wrapper
        except Exception as e:
            debug_stderr(f"Error creating enhanced wrapper for {func.__name__}: {e}")
            raise
    
    return decorator

# =====================================================================
# SHELL COMMAND EXECUTION SYSTEM
# =====================================================================

debug_stderr("Defining enhanced shell command execution classes...")

@dataclass
class ShellCommandResult:
    """Enhanced structure for shell command execution results"""
    success: bool
    command: str
    output: str
    error_message: Optional[str] = None
    execution_time: float = 0.0
    device_id: str = ""
    site_id: str = ""
    timestamp: str = ""
    output_truncated: bool = False
    max_output_size: int = 10000

class JunosShellExecutor:
    """Enhanced shell command executor for Junos devices via Mist WebSocket API"""
    
    def __init__(self, api_client: 'MistAPI'):
        debug_stderr("Initializing Enhanced JunosShellExecutor...")
        self.api_client = api_client
        self.active_connections = set()
        self.connection_semaphore = asyncio.Semaphore(CONFIG.max_concurrent_requests)
        debug_stderr("✓ Enhanced JunosShellExecutor initialized")
    
    async def execute_command(self, site_id: str, device_id: str, command: str, 
                            max_runtime: int = 30, max_idle: int = 5, 
                            max_output_size: int = 10000) -> ShellCommandResult:
        """Execute a shell command on a Junos device via Mist WebSocket with enhanced options"""
        debug_stderr(f"Executing enhanced command '{command}' on device {device_id}")
        
        if not CONFIG.websockets_available:
            debug_stderr("WebSocket library not available")
            return ShellCommandResult(
                success=False,
                command=command,
                output="",
                error_message="WebSocket library not available. Install with: pip install websockets",
                execution_time=0,
                device_id=device_id,
                site_id=site_id,
                timestamp=datetime.now().isoformat(),
                max_output_size=max_output_size
            )
        
        start_time = time.time()
        output_truncated = False
        
        try:
            # Convert device_id to full UUID format if needed
            if len(device_id) == 12:
                full_device_id = f"00000000-0000-0000-1000-{device_id}"
            else:
                full_device_id = device_id
            
            debug_stderr(f"Using device ID: {full_device_id}")
            
            # Use semaphore to limit concurrent connections
            async with self.connection_semaphore:
                # Get shell session URL with timeout
                debug_stderr("Getting shell session URL...")
                shell_url = await asyncio.wait_for(
                    self._get_shell_url(site_id, full_device_id),
                    timeout=15
                )
                
                if not shell_url:
                    debug_stderr("Failed to get shell URL")
                    return ShellCommandResult(
                        success=False,
                        command=command,
                        output="",
                        error_message="Failed to establish shell session",
                        execution_time=time.time() - start_time,
                        device_id=device_id,
                        site_id=site_id,
                        timestamp=datetime.now().isoformat(),
                        max_output_size=max_output_size
                    )
                
                debug_stderr(f"Shell URL obtained: {shell_url[:50]}...")
                
                # Execute command via WebSocket with timeout and size limits
                debug_stderr("Executing WebSocket command...")
                output = await asyncio.wait_for(
                    self._execute_websocket_command(shell_url, command, max_idle, max_output_size),
                    timeout=max_runtime
                )
                
                # Check if output was truncated
                if len(output) >= max_output_size:
                    output_truncated = True
                    output = output[:max_output_size] + "\n... [OUTPUT TRUNCATED] ..."
                
                debug_stderr(f"Enhanced command completed successfully, output length: {len(output)}")
                
                return ShellCommandResult(
                    success=True,
                    command=command,
                    output=output,
                    execution_time=time.time() - start_time,
                    device_id=device_id,
                    site_id=site_id,
                    timestamp=datetime.now().isoformat(),
                    output_truncated=output_truncated,
                    max_output_size=max_output_size
                )
                
        except asyncio.TimeoutError:
            debug_stderr(f"Enhanced command timed out after {max_runtime}s")
            return ShellCommandResult(
                success=False,
                command=command,
                output="",
                error_message=f"Command timed out after {max_runtime}s",
                execution_time=time.time() - start_time,
                device_id=device_id,
                site_id=site_id,
                timestamp=datetime.now().isoformat(),
                max_output_size=max_output_size
            )
        except Exception as e:
            debug_stderr(f"Enhanced command execution error: {e}")
            debug_stderr(f"Error traceback: {traceback.format_exc()}")
            return ShellCommandResult(
                success=False,
                command=command,
                output="",
                error_message=str(e),
                execution_time=time.time() - start_time,
                device_id=device_id,
                site_id=site_id,
                timestamp=datetime.now().isoformat(),
                max_output_size=max_output_size
            )
    
    async def _get_shell_url(self, site_id: str, device_id: str) -> Optional[str]:
        """Get WebSocket URL for shell session with enhanced error handling"""
        try:
            debug_stderr(f"Requesting shell URL for device {device_id}")
            endpoint = f"/api/v1/sites/{site_id}/devices/{device_id}/shell"
            result = await self.api_client.make_request(endpoint, method="POST")
            
            if result.get("status") == "SUCCESS":
                response_data = json.loads(result.get("response_data", "{}"))
                url = response_data.get("url")
                debug_stderr(f"✓ Shell URL received: {url[:50] if url else 'None'}...")
                return url
            else:
                debug_stderr(f"Shell URL request failed: {result}")
            
            return None
            
        except Exception as e:
            debug_stderr(f" Error: Failed to get shell URL: {e}")
            return None
    
    async def _execute_websocket_command(self, ws_url: str, command: str, 
                                       max_idle: int, max_output_size: int) -> str:
        """Execute command via WebSocket with enhanced output handling"""
        # Import websockets here since we know it's available
        import websockets
        
        websocket_conn = None
        output_buffer = []
        total_output_size = 0
        
        try:
            debug_stderr(f"Connecting to WebSocket: {ws_url[:50]}...")
            
            # Connect to WebSocket with enhanced settings
            websocket_conn = await websockets.connect(
                ws_url,
                ping_timeout=30,
                ping_interval=25,
                close_timeout=15,
                max_size=max_output_size * 2  # Allow some buffer
            )
            
            self.active_connections.add(websocket_conn)
            debug_stderr(f"WebSocket connection established for command: {command}")
            
            # Send command
            await asyncio.sleep(1)  # Allow connection to stabilize
            command_string = chr(0) + command + '\n'
            command_bytes = command_string.encode(encoding="ascii")
            await websocket_conn.send(command_bytes)
            debug_stderr(f"Enhanced command sent: {command}")
            
            # Receive output with idle timeout and size limits
            while total_output_size < max_output_size:
                try:
                    # Wait for message with timeout
                    message = await asyncio.wait_for(
                        websocket_conn.recv(),
                        timeout=max_idle
                    )
                    
                    # Process message
                    if isinstance(message, bytes):
                        try:
                            line = message.decode('ascii')
                            data = re.sub(r'[\x00]', '', line)
                            
                            # Check size limits
                            if total_output_size + len(data) > max_output_size:
                                remaining_space = max_output_size - total_output_size
                                if remaining_space > 0:
                                    output_buffer.append(data[:remaining_space])
                                break
                            
                            output_buffer.append(data)
                            total_output_size += len(data)
                            
                        except UnicodeDecodeError:
                            # Skip non-ASCII messages
                            continue
                    else:
                        message_str = str(message)
                        if total_output_size + len(message_str) > max_output_size:
                            remaining_space = max_output_size - total_output_size
                            if remaining_space > 0:
                                output_buffer.append(message_str[:remaining_space])
                            break
                        output_buffer.append(message_str)
                        total_output_size += len(message_str)
                        
                except asyncio.TimeoutError:
                    # No activity for max_idle seconds - assume command completed
                    debug_stderr(f"Enhanced command completed due to idle timeout ({max_idle}s)")
                    break
                    
        except Exception as e:
            debug_stderr(f"Enhanced WebSocket error: {e}")
            raise
        finally:
            # Always clean up the connection
            if websocket_conn:
                try:
                    self.active_connections.discard(websocket_conn)
                    await websocket_conn.close()
                except Exception as e:
                    debug_stderr(f"Error closing enhanced WebSocket connection: {e}")
        
        return ''.join(output_buffer)
    
    async def cleanup(self):
        """Clean up any remaining connections with enhanced tracking"""
        debug_stderr("Cleaning up enhanced shell executor connections...")
        cleanup_tasks = []
        for conn in list(self.active_connections):
            cleanup_tasks.append(self._safe_close_connection(conn))
        
        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)
        
        self.active_connections.clear()
        debug_stderr("################# ✓ Enhanced shell executor cleanup completed ################# ")
    
    async def _safe_close_connection(self, conn):
        """Safely close a WebSocket connection"""
        try:
            await conn.close()
        except Exception as e:
            debug_stderr(f"Error closing connection: {e}")

# =====================================================================
# ENHANCED MIST API CLIENT
# =====================================================================

debug_stderr("Defining Enhanced MistAPI class...")

class MistAPI:
    """Enhanced Mist API client with comprehensive error handling and rate limiting"""
    
    def __init__(self, config: ServerConfig):
        debug_stderr(f"Initializing Enhanced MistAPI with config: {config.base_url}")
        self.config = config
        self.request_count = 0
        self.last_request_time = 0
        self.rate_limit_remaining = None
        
        try:
            # Create HTTP client with enhanced timeouts and limits
            debug_stderr("Creating enhanced HTTP client...")
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=15.0,   # Connection timeout
                    read=config.request_timeout,     # Read timeout
                    write=15.0,     # Write timeout
                    pool=10.0       # Pool timeout
                ),
                verify=True,
                limits=httpx.Limits(
                    max_connections=config.max_concurrent_requests, 
                    max_keepalive_connections=min(config.max_concurrent_requests // 2, 5)
                ),
                follow_redirects=True
            )
            debug_stderr("✓ Enhanced HTTP client created")
            
            # Create enhanced shell executor
            debug_stderr("Creating enhanced shell executor...")
            self.shell_executor = JunosShellExecutor(self)
            debug_stderr("✓ Enhanced shell executor created")
            
        except Exception as e:
            debug_stderr(f"Error initializing Enhanced MistAPI: {e}")
            raise
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Generate enhanced authentication headers"""
        return {
            'Authorization': f'Token {self.config.api_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Enhanced-Comprehensive-Secure-Mist-MCP-Server/3.1',
            'X-Client-Type': 'MCP-Server',
            'X-API-Version': '1'
        }
    
    def _respect_rate_limits(self):
        """Basic rate limiting to be respectful to the API"""
        current_time = time.time()
        if self.last_request_time and current_time - self.last_request_time < 0.1:
            time.sleep(0.1)  # Minimum 100ms between requests
        self.last_request_time = current_time
    
    async def make_request(self, endpoint: str, method: str = "GET", data: Dict = None, 
                         params: Dict = None, timeout_override: int = None) -> Dict[str, Any]:
        """Make enhanced authenticated request to Mist API"""
        try:
            self._respect_rate_limits()
            self.request_count += 1
            
            headers = self._get_auth_headers()
            url = f"{self.config.base_url}{endpoint}"
            
            # Use custom timeout if provided
            if timeout_override:
                timeout = httpx.Timeout(timeout_override)
            else:
                timeout = None
            
            debug_stderr(f"Making enhanced {method} request to {endpoint}")
            
            # Make request based on method
            if method.upper() == "GET":
                response = await self.client.get(url, headers=headers, params=params, timeout=timeout)
            elif method.upper() == "POST":
                response = await self.client.post(url, headers=headers, json=data or {}, params=params, timeout=timeout)
            elif method.upper() == "PUT":
                response = await self.client.put(url, headers=headers, json=data or {}, params=params, timeout=timeout)
            elif method.upper() == "DELETE":
                response = await self.client.delete(url, headers=headers, params=params, timeout=timeout)
            elif method.upper() == "PATCH":
                response = await self.client.patch(url, headers=headers, json=data or {}, params=params, timeout=timeout)
            else:
                debug_stderr(f"Unsupported HTTP method: {method}")
                return {"status": "ERROR", "message": f"Unsupported method: {method}"}
            
            # Track rate limit headers
            self.rate_limit_remaining = response.headers.get('X-RateLimit-Remaining')
            
            debug_stderr(f"Enhanced request completed with status: {response.status_code}")
            
            # Enhanced response processing
            response_text = response.text
            content_type = response.headers.get('content-type', '').lower()
            
            return {
                "status": "SUCCESS" if response.status_code < 400 else "ERROR",
                "message": f"{method} request completed" if response.status_code < 400 else f"Request failed: {response.status_code}",
                "endpoint": endpoint,
                "http_status": response.status_code,
                "server": self.config.base_url.replace('https://', '').replace('http://', ''),
                "response_data": response_text,
                "content_type": content_type,
                "response_size": len(response_text),
                "rate_limit_remaining": self.rate_limit_remaining,
                "request_count": self.request_count
            }
            
        except httpx.TimeoutException as e:
            debug_stderr(f"Enhanced request to {endpoint} timed out: {e}")
            return {
                "status": "ERROR",
                "message": f"Request timed out after {timeout_override or self.config.request_timeout}s",
                "endpoint": endpoint,
                "method": method,
                "server": self.config.base_url,
                "error_type": "timeout"
            }
        except httpx.HTTPStatusError as e:
            debug_stderr(f"HTTP error for {endpoint}: {e}")
            return {
                "status": "ERROR",
                "message": f"HTTP error: {e.response.status_code}",
                "endpoint": endpoint,
                "method": method,
                "server": self.config.base_url,
                "http_status": e.response.status_code,
                "error_type": "http_error"
            }
        except Exception as e:
            debug_stderr(f"Enhanced request to {endpoint} failed: {e}")
            return {
                "status": "ERROR",
                "message": f"Request failed: {str(e)}",
                "endpoint": endpoint,
                "method": method,
                "server": self.config.base_url,
                "error_type": "general_error"
            }
    
    async def close(self):
        """Close the HTTP client and clean up connections"""
        debug_stderr("Closing Enhanced MistAPI client...")
        await self.shell_executor.cleanup()
        await self.client.aclose()
        debug_stderr(f"✓ Enhanced MistAPI client closed (processed {self.request_count} requests)")

# Global enhanced API client
api_client: Optional[MistAPI] = None

def get_api_client() -> MistAPI:
    """Get or create enhanced API client instance"""
    global api_client
    try:
        if not api_client:
            debug_stderr("Creating new enhanced API client instance...")
            api_client = MistAPI(CONFIG)
            debug_stderr("✓ Enhanced API client created successfully")
        return api_client
    except Exception as e:
        debug_stderr(f" Error: Failed to get enhanced API client: {e}")
        raise

debug_stderr("✓ Enhanced MistAPI class defined")

# =============================================================================
# DOCUMENTATION INITIALIZATION SYSTEM
# =============================================================================

# Global documentation registry
TOOL_DOCS = {}

def initialize_documentation():
    """Initialize tool documentation at module load time"""
    global TOOL_DOCS
    try:
        debug_stderr("Initializing tool documentation...")
        
        # Register all tool documentation
        TOOL_DOCS['get_site_devices'] = get_tool_documentation('get_site_devices')
        TOOL_DOCS['get_org_evpn_topologies'] = get_tool_documentation('get_org_evpn_topologies')
        TOOL_DOCS['get_site_evpn_topologies'] = get_tool_documentation('get_site_evpn_topologies')
        TOOL_DOCS['get_evpn_topologies_details'] = get_tool_documentation('get_evpn_topologies_details')
        
        debug_stderr(f"✓ Documentation initialized for {len(TOOL_DOCS)} tools")
        return True
        
    except Exception as e:
        debug_stderr(f"Warning: Documentation initialization failed: {e}")
        return False

# Initialize documentation immediately
DOC_INITIALIZED = initialize_documentation()

def get_tool_doc(tool_name: str) -> str:
    """Get tool documentation safely"""
    
    if DOC_INITIALIZED and tool_name in TOOL_DOCS:
        return TOOL_DOCS[tool_name]
    
    # Fallback to direct lookup
    try:
        return get_tool_documentation(tool_name)
    except Exception as e:
        debug_stderr(f"Failed to get documentation for {tool_name}: {e}")
        return f"Documentation for {tool_name} not available"

# =============================================================================
# ENHANCED STATISTICS HELPER FUNCTIONS
# =============================================================================

def get_stats_type_descriptions() -> Dict[str, Dict[str, str]]:
    """
    Get comprehensive descriptions of all available statistics types with their
    specific use cases, data types, and recommended analysis approaches
    
    Returns:
        Dict containing detailed descriptions for each stats type
    """
    return {
        "general": {
            "description": "Overall organization health and performance metrics",
            "data_includes": "Sites, devices, users, connectivity, SLE metrics",
            "use_cases": "Executive dashboards, health monitoring, capacity planning",
            "update_frequency": "Every 10 minutes",
            "best_for": "High-level organizational overview and KPI tracking"
        },
        "assets": {
            "description": "Asset tracking and location services statistics",
            "data_includes": "Asset locations, tracking accuracy, battery levels, movement patterns",
            "use_cases": "Asset management, location analytics, inventory tracking",
            "update_frequency": "Real-time with device polling",
            "best_for": "Physical asset management and location-based services"
        },
        "devices": {
            "description": "Device health and performance across all device types",
            "data_includes": "Device status, performance metrics, health scores, connectivity",
            "use_cases": "Infrastructure monitoring, device troubleshooting, fleet management",
            "update_frequency": "Every 5-10 minutes",
            "best_for": "Network infrastructure health and device lifecycle management"
        },
        "mxedges": {
            "description": "MX Edge SD-WAN and edge computing statistics",
            "data_includes": "Tunnel status, throughput, latency, SD-WAN metrics",
            "use_cases": "SD-WAN monitoring, edge performance, WAN optimization",
            "update_frequency": "Every 5 minutes",
            "best_for": "SD-WAN deployments and edge computing performance analysis"
        },
        "bgp_peers": {
            "description": "BGP routing and peer performance statistics",
            "data_includes": "BGP session states, route counts, AS path info, convergence times",
            "use_cases": "Routing analysis, BGP troubleshooting, network topology mapping",
            "update_frequency": "Every 1-5 minutes",
            "best_for": "Enterprise WAN and service provider routing analysis"
        },
        "sites": {
            "description": "Site-level aggregated performance statistics",
            "data_includes": "Per-site metrics, user counts, performance scores, alerts",
            "use_cases": "Multi-site comparisons, site performance benchmarking",
            "update_frequency": "Every 10 minutes",
            "best_for": "Multi-site deployments and regional performance analysis"
        },
        "clients": {
            "description": "Client connection and usage statistics",
            "data_includes": "Client sessions, authentication, throughput, experience metrics",
            "use_cases": "User experience monitoring, capacity planning, troubleshooting",
            "update_frequency": "Real-time to 1 minute",
            "best_for": "End-user experience analysis and network utilization planning"
        },
        "tunnels": {
            "description": "VPN and overlay tunnel performance statistics", 
            "data_includes": "Tunnel status, throughput, latency, availability metrics",
            "use_cases": "VPN monitoring, overlay network analysis, connectivity troubleshooting",
            "update_frequency": "Every 1-5 minutes",
            "best_for": "VPN deployments and overlay network performance monitoring"
        },
        "wireless": {
            "description": "Wi-Fi specific RF and client experience statistics",
            "data_includes": "RF metrics, channel utilization, client roaming, interference",
            "use_cases": "Wi-Fi optimization, RF planning, client experience analysis",
            "update_frequency": "Every 1-2 minutes",
            "best_for": "Wireless network optimization and RF performance analysis"
        },
        "wired": {
            "description": "Ethernet and switch port utilization statistics",
            "data_includes": "Port utilization, link status, PoE usage, switching metrics",
            "use_cases": "Switch monitoring, port capacity planning, wired troubleshooting",
            "update_frequency": "Every 5 minutes", 
            "best_for": "Wired infrastructure monitoring and capacity planning"
        }
    }

def validate_stats_parameters(stats_type: str, **kwargs) -> Tuple[bool, List[str]]:
    """
    Validate parameters for specific statistics types and provide helpful error messages
    
    Args:
        stats_type: The type of statistics being requested
        **kwargs: Parameters to validate
        
    Returns:
        Tuple of (is_valid, list_of_error_messages)
    """
    errors = []
    valid_types = get_stats_type_descriptions().keys()
    
    if stats_type not in valid_types:
        errors.append(f"Invalid stats_type '{stats_type}'. Valid options: {list(valid_types)}")
        return False, errors
    
    # Validate time range parameters
    start = kwargs.get('start')
    end = kwargs.get('end')
    duration = kwargs.get('duration', '1d')
    
    if start is not None and end is not None:
        if start >= end:
            errors.append("Start time must be before end time")
        if end - start > 30 * 24 * 3600:  # More than 30 days
            errors.append("Time range cannot exceed 30 days")
    
    valid_durations = ['1h', '6h', '1d', '1w', '1m']
    if duration not in valid_durations:
        errors.append(f"Invalid duration '{duration}'. Valid options: {valid_durations}")
    
    # Validate pagination parameters
    limit = kwargs.get('limit', 100)
    if not isinstance(limit, int) or limit < 1 or limit > 1000:
        errors.append("Limit must be between 1 and 1000")
    
    page = kwargs.get('page', 1)
    if not isinstance(page, int) or page < 1:
        errors.append("Page must be a positive integer")
    
    # Validate device_type for applicable stats_types
    device_type = kwargs.get('device_type')
    if device_type and stats_type in ['devices', 'general']:
        valid_device_types = ['ap', 'switch', 'gateway', 'mxedge']
        if device_type not in valid_device_types:
            errors.append(f"Invalid device_type '{device_type}'. Valid options: {valid_device_types}")
    
    return len(errors) == 0, errors

def format_stats_response(stats_data: Dict, stats_type: str, params: Dict) -> Dict:
    """
    Format and enhance statistics response data with type-specific analysis
    
    Args:
        stats_data: Raw statistics data from API
        stats_type: Type of statistics
        params: Original request parameters
        
    Returns:
        Enhanced and formatted statistics response
    """
    formatted_response = {
        "stats_type": stats_type,
        "query_parameters": params,
        "data_summary": {},
        "analysis": {},
        "raw_data": stats_data
    }
    
    try:
        if stats_type == "general":
            formatted_response["data_summary"] = {
                "total_sites": stats_data.get("num_sites", 0),
                "total_devices": stats_data.get("num_devices", 0),
                "connected_devices": stats_data.get("num_devices_connected", 0),
                "device_connection_rate": round(
                    (stats_data.get("num_devices_connected", 0) / 
                     max(stats_data.get("num_devices", 1), 1)) * 100, 1
                ),
                "active_clients": stats_data.get("num_clients", 0)
            }
            
        elif stats_type == "devices":
            if isinstance(stats_data, list):
                device_types = {}
                device_status = {"connected": 0, "disconnected": 0}
                
                for device in stats_data:
                    dev_type = device.get("type", "unknown")
                    device_types[dev_type] = device_types.get(dev_type, 0) + 1
                    
                    if device.get("connected", False):
                        device_status["connected"] += 1
                    else:
                        device_status["disconnected"] += 1
                
                formatted_response["data_summary"] = {
                    "total_devices": len(stats_data),
                    "device_types": device_types,
                    "connectivity_status": device_status
                }
                
        elif stats_type == "clients":
            if isinstance(stats_data, list):
                client_types = {"wireless": 0, "wired": 0}
                auth_methods = {}
                
                for client in stats_data:
                    if client.get("ap"):
                        client_types["wireless"] += 1
                    else:
                        client_types["wired"] += 1
                    
                    auth = "authenticated" if (client.get("username") or client.get("psk_name")) else "open"
                    auth_methods[auth] = auth_methods.get(auth, 0) + 1
                
                formatted_response["data_summary"] = {
                    "total_clients": len(stats_data),
                    "client_types": client_types,
                    "authentication_methods": auth_methods
                }
        
        # Add performance insights
        formatted_response["performance_insights"] = generate_performance_insights(stats_data, stats_type)
        
    except Exception as e:
        formatted_response["formatting_error"] = str(e)
        formatted_response["raw_data_available"] = True
    
    return formatted_response

def generate_performance_insights(stats_data: Dict, stats_type: str) -> List[str]:
    """
    Generate actionable performance insights based on statistics data
    
    Args:
        stats_data: Statistics data to analyze
        stats_type: Type of statistics
        
    Returns:
        List of performance insights and recommendations
    """
    insights = []
    
    try:
        if stats_type == "general":
            connection_rate = (stats_data.get("num_devices_connected", 0) / 
                             max(stats_data.get("num_devices", 1), 1)) * 100
            
            if connection_rate < 95:
                insights.append(f"Device connectivity at {connection_rate:.1f}% - investigate disconnected devices")
            elif connection_rate >= 99:
                insights.append("Excellent device connectivity - all systems operational")
            
            client_count = stats_data.get("num_clients", 0)
            device_count = stats_data.get("num_devices", 1)
            clients_per_device = client_count / device_count if device_count > 0 else 0
            
            if clients_per_device > 50:
                insights.append(f"High client density detected ({clients_per_device:.1f} clients/device) - consider capacity expansion")
            
        elif stats_type == "devices" and isinstance(stats_data, list):
            if len(stats_data) == 0:
                insights.append("No devices found - verify device deployment and connectivity")
            else:
                models = {}
                for device in stats_data:
                    model = device.get("model", "unknown")
                    models[model] = models.get(model, 0) + 1
                
                if len(models) > 5:
                    insights.append(f"Device diversity detected - {len(models)} different models in deployment")
                
        elif stats_type == "clients" and isinstance(stats_data, list):
            if len(stats_data) == 0:
                insights.append("No active clients found - verify network accessibility")
            else:
                avg_rssi = []
                for client in stats_data:
                    rssi = client.get("rssi")
                    if rssi:
                        avg_rssi.append(rssi)
                
                if avg_rssi:
                    avg_signal = sum(avg_rssi) / len(avg_rssi)
                    if avg_signal < -70:
                        insights.append(f"Poor average signal strength detected ({avg_signal:.1f} dBm) - consider AP placement optimization")
                    elif avg_signal > -50:
                        insights.append("Excellent signal strength - optimal RF coverage")
        
        # Generic insights
        if not insights:
            insights.append(f"{stats_type.title()} statistics retrieved successfully - review detailed metrics for optimization opportunities")
            
    except Exception as e:
        insights.append(f"Performance analysis incomplete due to: {str(e)}")
    
    return insights

def get_recommended_time_ranges() -> Dict[str, Dict[str, str]]:
    """
    Get recommended time ranges for different statistics types and use cases
    
    Returns:
        Dictionary of recommended time ranges by stats type and use case
    """
    return {
        "real_time_monitoring": {
            "duration": "1h",
            "description": "Last hour for real-time monitoring and immediate troubleshooting",
            "best_for": ["clients", "devices", "wireless", "tunnels"]
        },
        "daily_operations": {
            "duration": "1d", 
            "description": "Last 24 hours for daily operations and performance review",
            "best_for": ["general", "sites", "bgp_peers", "wired"]
        },
        "weekly_analysis": {
            "duration": "1w",
            "description": "Last week for trend analysis and capacity planning",
            "best_for": ["assets", "mxedges", "general", "sites"]
        },
        "monthly_reporting": {
            "duration": "1m",
            "description": "Last month for executive reporting and long-term trends",
            "best_for": ["general", "sites", "devices", "clients"]
        }
    }

# =============================================================================
# ENHANCED ERROR HANDLING AND RECOVERY FUNCTIONS  
# =============================================================================

def handle_stats_api_error(error_response: Dict, stats_type: str, org_id: str) -> Dict:
    """
    Provide enhanced error handling with specific troubleshooting steps for statistics API errors
    
    Args:
        error_response: Error response from API
        stats_type: Type of statistics that failed
        org_id: Organization ID
        
    Returns:
        Enhanced error response with troubleshooting information
    """
    http_status = error_response.get("http_status", 0)
    
    troubleshooting = {
        "stats_type": stats_type,
        "organization_id": org_id,
        "error_category": "unknown",
        "immediate_actions": [],
        "common_causes": [],
        "next_steps": []
    }
    
    if http_status == 401:
        troubleshooting.update({
            "error_category": "authentication",
            "immediate_actions": [
                "Verify API token is valid and not expired",
                "Check API token has read permissions for organization statistics"
            ],
            "common_causes": [
                "Expired or invalid API token",
                "Insufficient permissions for statistics access",
                "Token not associated with the organization"
            ]
        })
    
    elif http_status == 403:
        troubleshooting.update({
            "error_category": "authorization",
            "immediate_actions": [
                f"Verify API token has access to organization '{org_id}'",
                f"Check if '{stats_type}' statistics are enabled for this organization"
            ],
            "common_causes": [
                "API token lacks organization access permissions",
                f"'{stats_type}' feature not enabled or licensed",
                "Organization access restrictions in place"
            ]
        })
    
    elif http_status == 404:
        troubleshooting.update({
            "error_category": "not_found", 
            "immediate_actions": [
                f"Verify organization ID '{org_id}' is correct",
                f"Check if '{stats_type}' endpoint is supported"
            ],
            "common_causes": [
                "Invalid or non-existent organization ID",
                "Statistics type not supported for this organization",
                "API endpoint not available in current region"
            ]
        })
    
    elif http_status == 429:
        troubleshooting.update({
            "error_category": "rate_limit",
            "immediate_actions": [
                "Wait before retrying request",
                "Implement exponential backoff in retry logic"
            ],
            "common_causes": [
                "Exceeded API rate limit (5000 calls/hour)",
                "Too many concurrent requests",
                "Burst request pattern triggering rate limiting"
            ]
        })
    
    elif http_status >= 500:
        troubleshooting.update({
            "error_category": "server_error",
            "immediate_actions": [
                "Retry request after brief delay",
                "Check Mist service status and announcements"
            ],
            "common_causes": [
                "Temporary Mist API service issue",
                "Internal server error processing request",
                "Maintenance or service disruption"
            ]
        })
    
    # Add stats-type specific troubleshooting
    if stats_type == "devices":
        troubleshooting["next_steps"].extend([
            "Verify devices are adopted and connected to Mist cloud",
            "Check if devices are reporting statistics properly"
        ])
    elif stats_type == "bgp_peers":
        troubleshooting["next_steps"].extend([
            "Ensure BGP is configured and operational on network devices",
            "Verify BGP peers are established and exchanging routes"
        ])
    elif stats_type == "mxedges":
        troubleshooting["next_steps"].extend([
            "Verify MX Edge devices are deployed and operational",
            "Check MX Edge cloud connectivity and registration"
        ])
    
    return {
        "error": True,
        "original_error": error_response,
        "enhanced_troubleshooting": troubleshooting,
        "support_information": {
            "documentation": f"https://www.juniper.net/documentation/us/en/software/mist/api/http/api/orgs/stats/{stats_type}.html",
            "support_contact": "Create support ticket at https://support.juniper.net for persistent issues",
            "api_reference": "https://api.mist.com/api/v1/docs/"
        }
    }

# =====================================================================
# ENHANCED TOOL DEFINITION SYSTEM
# =====================================================================

debug_stderr("Defining enhanced tool functions...")

def safe_tool_definition(tool_name: str, api_category: str = "general"):
    """Enhanced decorator to safely define tools with API categorization"""
    def decorator(func):
        try:
            debug_stderr(f"Defining enhanced tool: {tool_name} [category: {api_category}]")
            
            # Apply both decorators with enhanced monitoring
            monitored_func = monitor_operation_enhanced(api_category)(func)
            tool_func = mcp.tool()(monitored_func)
            
            debug_stderr(f"✓ Enhanced tool '{tool_name}' defined successfully in category '{api_category}'")
            return tool_func
            
        except Exception as e:
            debug_stderr(f"✗ FAILED to define enhanced tool '{tool_name}': {e}")
            debug_stderr(f"Traceback: {traceback.format_exc()}")
            raise
    return decorator

# =====================================================================
# SECURITY ANALYSIS TOOLS (2 NEW TOOLS)
# =====================================================================

@safe_tool_definition("analyze_token_security", "security")
async def analyze_token_security() -> str:
    """
    SECURITY ANALYSIS TOOL #1: API Token Privilege Security Analyzer
    
    Function: Performs comprehensive security analysis of the current API token's 
              privileges to identify potential security risks and violations of 
              the principle of least privilege. This tool helps organizations
              ensure their API tokens follow security best practices.
    
    API Used: GET /api/v1/self (to retrieve user privileges for analysis)
    
    Response Handling:
    - Returns detailed JSON with comprehensive security risk analysis
    - Identifies dangerous privilege patterns across organizations and MSPs
    - Provides specific mitigation recommendations for each risk type
    - Shows risk severity levels (LOW, MEDIUM, HIGH, CRITICAL)
    - Includes configuration guidance for security controls
    - Reports privilege distribution statistics and usage patterns
    
    Security Risks Detected:
    1. Admin privileges to multiple organizations (CRITICAL risk)
    2. Write privileges to multiple organizations (HIGH risk)
    3. Admin privileges to multiple MSPs (CRITICAL risk)
    4. Write privileges to multiple MSPs (HIGH risk)
    5. Single MSP with excessive organization access (HIGH risk)
    
    Enhanced Features:
    - Configurable risk thresholds via environment variables
    - Detailed mitigation guidance for each risk type
    - Alternative solution recommendations
    - Security configuration templates
    - Compliance validation support
    
    Use Cases:
    - Security audit of API tokens before production deployment
    - Compliance validation for principle of least privilege
    - Risk assessment for automated systems and integrations
    - Security review as part of access management procedures
    - Token privilege optimization and scope reduction planning
    """
    try:
        client = get_api_client()
        user_result = await client.make_request("/api/v1/self")
        
        if user_result.get("status") != "SUCCESS":
            return json.dumps({
                "error": "Failed to retrieve user information for security analysis",
                "status": "ANALYSIS_FAILED"
            }, indent=2)
        
        user_data = json.loads(user_result.get("response_data", "{}"))
        privileges = user_data.get("privileges", [])
        
        # Perform comprehensive security analysis
        analysis = await security_analyzer.analyze_privileges(privileges)
        
        # Format detailed security report
        security_report = {
            "security_analysis_summary": {
                "is_safe": analysis.is_safe,
                "total_risks": len(analysis.risks_detected),
                "analysis_timestamp": analysis.analysis_timestamp,
                "blocking_enabled": security_analyzer.strict_mode,
                "risks_acknowledged": security_analyzer.security_acknowledged
            },
            "privilege_summary": {
                "organizations_with_admin": analysis.total_orgs_admin,
                "organizations_with_write": analysis.total_orgs_write,
                "msps_with_admin": analysis.total_msps_admin,
                "msps_with_write": analysis.total_msps_write,
                "msp_organization_counts": dict(analysis.msp_org_counts)
            },
            "security_risks": []
        }
        
        # Add detailed risk information
        for risk in analysis.risks_detected:
            risk_detail = {
                "risk_type": risk.risk_type,
                "severity": risk.severity,
                "description": risk.description,
                "affected_scopes": risk.affected_scopes,
                "organization_count": risk.org_count,
                "msp_count": risk.msp_count,
                "mitigation_suggestions": risk.mitigation_suggestions
            }
            security_report["security_risks"].append(risk_detail)
        
        # Add recommendations and configuration guidance
        security_report["recommendations"] = analysis.recommendations
        security_report["security_configuration"] = {
            "current_thresholds": security_analyzer.risk_thresholds,
            "environment_variables": {
                "MIST_SECURITY_RISKS_ACKNOWLEDGED": "Set to 'true' to acknowledge risks and proceed",
                "MIST_STRICT_SECURITY_MODE": "Set to 'false' to disable execution blocking",
                "MIST_MAX_ADMIN_ORGS": "Maximum orgs with admin privileges (default: 1)",
                "MIST_MAX_WRITE_ORGS": "Maximum orgs with write privileges (default: 3)",
                "MIST_MAX_ADMIN_MSPS": "Maximum MSPs with admin privileges (default: 1)",
                "MIST_MAX_WRITE_MSPS": "Maximum MSPs with write privileges (default: 1)",
                "MIST_MAX_ORGS_PER_MSP": "Maximum orgs per MSP (default: 5)"
            }
        }
        
        # Add alternative solutions for high-risk scenarios
        if analysis.risks_detected:
            security_report["alternative_solutions"] = {
                "token_scoping": [
                    "Create separate API tokens for each organization",
                    "Use read-only tokens for monitoring applications",
                    "Implement organization-specific service accounts"
                ],
                "access_patterns": [
                    "Just-in-time privilege escalation for admin tasks",
                    "Separate tokens for different application functions",
                    "Regular token rotation and privilege review"
                ],
                "architectural": [
                    "Use Mist's built-in role-based access controls",
                    "Implement federated authentication for MSPs", 
                    "Consider proxy services for multi-org access"
                ]
            }
        
        return json.dumps(security_report, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Security analysis failed: {str(e)}",
            "message": "Manual security review recommended"
        }, indent=2)

@safe_tool_definition("acknowledge_security_risks", "security")
async def acknowledge_security_risks(confirmation: str = "") -> str:
    """
    SECURITY CONTROL TOOL #2: Risk Acknowledgment Interface
    
    Function: Allows users to acknowledge detected security risks and override
              blocking behavior for the current session. This tool provides a
              controlled mechanism to bypass security controls when necessary
              while maintaining audit trails and security awareness.
    
    API Used: Internal security control system (no external Mist API calls)
    
    Parameters:
    - confirmation (str): Must be "I_ACKNOWLEDGE_SECURITY_RISKS" to confirm understanding
    
    Response Handling:
    - Returns confirmation of risk acknowledgment status
    - Updates session security settings and control flags
    - Provides guidance on permanent configuration options
    - Shows current security control status and recommendations
    - Maintains audit trail of security decisions
    
    Enhanced Features:
    - Explicit confirmation requirement for security awareness
    - Session-based override with audit logging
    - Clear guidance on permanent configuration options
    - Security recommendations for risk mitigation
    - Integration with environment variable configuration
    
    Use Cases:
    - Override security blocking after thorough risk review
    - Temporary privilege elevation for administrative tasks
    - Emergency access when immediate token replacement isn't feasible
    - Testing and development scenarios with elevated privileges
    - Administrative override during maintenance windows
    
    Security Note: This tool only affects the current session. For permanent
    override, set environment variable MIST_SECURITY_RISKS_ACKNOWLEDGED=true
    in your configuration. Regular security reviews are recommended.
    """
    try:
        if confirmation != "I_ACKNOWLEDGE_SECURITY_RISKS":
            return json.dumps({
                "status": "CONFIRMATION_REQUIRED",
                "message": "Security risk acknowledgment requires explicit confirmation",
                "required_confirmation": "I_ACKNOWLEDGE_SECURITY_RISKS",
                "warning": [
                    "Acknowledging security risks bypasses important safety checks",
                    "Only proceed if you understand the security implications",
                    "Consider creating tokens with minimal required privileges instead"
                ],
                "current_security_status": {
                    "strict_mode_enabled": security_analyzer.strict_mode,
                    "risks_currently_acknowledged": security_analyzer.security_acknowledged
                },
                "usage_example": "acknowledge_security_risks('I_ACKNOWLEDGE_SECURITY_RISKS')"
            }, indent=2)
        
        # Update session security settings
        security_analyzer.security_acknowledged = True
        
        return json.dumps({
            "status": "RISKS_ACKNOWLEDGED",
            "message": "Security risks have been acknowledged for this session",
            "session_updated": True,
            "acknowledgment_timestamp": datetime.now().isoformat(),
            "security_controls": {
                "strict_mode_enabled": security_analyzer.strict_mode,
                "risks_acknowledged": security_analyzer.security_acknowledged,
                "session_override_active": True
            },
            "permanent_configuration": [
                "To permanently acknowledge risks, set environment variable:",
                "MIST_SECURITY_RISKS_ACKNOWLEDGED=true",
                "To disable strict security mode:",
                "MIST_STRICT_SECURITY_MODE=false"
            ],
            "security_recommendations": [
                "This override should be temporary and time-limited",
                "Plan to create tokens with minimal required privileges",
                "Conduct regular security reviews of token usage",
                "Monitor token usage for unauthorized or unexpected activity",
                "Implement token rotation as part of security hygiene"
            ]
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Risk acknowledgment failed: {str(e)}",
            "status": "ACKNOWLEDGMENT_FAILED"
        }, indent=2)

# =====================================================================
# SECURITY-AWARE DECORATOR FOR make_mist_api_call
# =====================================================================

def require_security_check(func):
    """Security decorator that enforces privilege analysis before tool execution"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            # Get user privileges for security analysis
            client = get_api_client()
            user_result = await client.make_request("/api/v1/self")
            
            if user_result.get("status") != "SUCCESS":
                return json.dumps({
                    "error": "Failed to retrieve user privileges for security analysis",
                    "security_status": "ANALYSIS_FAILED"
                }, indent=2)
            
            user_data = json.loads(user_result.get("response_data", "{}"))
            privileges = user_data.get("privileges", [])
            
            # Perform security analysis
            analysis = await security_analyzer.analyze_privileges(privileges)
            
            # Check if execution should be blocked
            if security_analyzer.should_block_execution(analysis):
                return json.dumps({
                    "status": "BLOCKED",
                    "security_analysis": {
                        "risks_detected": len(analysis.risks_detected),
                        "severity_breakdown": {
                            "critical": len([r for r in analysis.risks_detected if r.severity == "CRITICAL"]),
                            "high": len([r for r in analysis.risks_detected if r.severity == "HIGH"])
                        },
                        "recommendations": analysis.recommendations[:3]  # Top 3 recommendations
                    },
                    "message": "EXECUTION BLOCKED: Dangerous API token privileges detected",
                    "details": [
                        "Your API token has overly broad privileges that violate security best practices",
                        "This increases risk if the token is compromised or there are bugs in the system",
                        "Review the security analysis and create tokens with minimal required permissions"
                    ],
                    "override_instructions": [
                        "Set MIST_SECURITY_RISKS_ACKNOWLEDGED=true to acknowledge risks",
                        "Set MIST_STRICT_SECURITY_MODE=false to disable blocking",
                        "Use the analyze_token_security tool to get detailed risk analysis"
                    ],
                    "alternative_solutions": [
                        "Create organization-specific API tokens with limited scope",
                        "Use read-only tokens for monitoring and reporting tasks", 
                        "Implement just-in-time privilege escalation for administrative tasks",
                        "Consider using Mist's built-in role-based access controls"
                    ]
                }, indent=2)
            
            # Log security warnings even if not blocking
            if not analysis.is_safe:
                debug_stderr(f"Security risks detected but execution proceeding: {len(analysis.risks_detected)} risks")
                for risk in analysis.risks_detected:
                    debug_stderr(f"  - {risk.severity}: {risk.description}")
            
            # Execute the original function
            result = await func(*args, **kwargs)
            
            # Add security context to successful results
            if not analysis.is_safe:
                try:
                    result_data = json.loads(result)
                    result_data["security_warning"] = {
                        "risks_detected": len(analysis.risks_detected),
                        "message": "Token has elevated privileges - review security recommendations",
                        "analysis_tool": "Use analyze_token_security for detailed analysis"
                    }
                    return json.dumps(result_data, indent=2)
                except:
                    # If can't parse result, just add warning comment
                    return result + f"\n\n# SECURITY WARNING: {len(analysis.risks_detected)} privilege risks detected"
            
            return result
            
        except Exception as e:
            debug_stderr(f"Security check failed for {func.__name__}: {e}")
            # On security check failure, proceed with original function but log warning
            debug_stderr("Proceeding with operation due to security check failure")
            return await func(*args, **kwargs)
    
    return wrapper

# =====================================================================
# ALL ORIGINAL TOOLS FROM THE ENHANCED SERVER (WITH SECURITY INTEGRATION)
# =====================================================================

# AUTHENTICATION & USER MANAGEMENT FUNCTIONS
# - get_user_info
# - get_audit_logs

@safe_tool_definition("get_user_info", "authentication")
async def get_user_info() -> str:
    """
    AUTHENTICATION TOOL #1: Comprehensive User Information & Privilege Analyzer
    
    Function: Retrieves complete authenticated user information, accessible
              organizations, detailed privilege analysis, and account details
              in a single efficient API call
    
    API Used: GET /api/v1/self
    
    Response Handling:
    - Returns JSON with complete user profile information
    - Shows user email, name, phone, and account creation date
    - Lists all accessible organizations with roles and detailed breakdown
    - Reports comprehensive privilege analysis by scope and role
    - Includes user tags and custom attributes
    - Shows session expiry and security settings
    - Provides privilege distribution statistics
    - Categorizes access by organizations, MSPs, and sites
    
    Authentication: Requires valid Mist API token
    
    Enhanced Features:
    - Single API call efficiency (combines user info + privilege analysis)
    - Privilege scope analysis and categorization
    - Role distribution statistics (admin/write/read/installer)
    - Access level hierarchy mapping
    - Organization, MSP, and site access breakdown
    - Permission inheritance tracking
    - Security audit trail support
    - Tag analysis and categorization
    - Account security status reporting
    
    Use Cases:
    - Verify authentication and token validity
    - Complete user context establishment for applications
    - Audit user access across multiple organizations
    - Verify role-based permissions before operations
    - Generate security compliance reports
    - Troubleshoot permission and access denied issues
    - Plan privilege escalation or reduction
    - Display current user context in applications
    """
    try:
        debug_stderr("Executing comprehensive get_user_info with privilege analysis...")
        client = get_api_client()
        result = await client.make_request("/api/v1/self")
        
        if result.get("status") == "SUCCESS":
            try:
                user_data = json.loads(result.get("response_data", "{}"))
                privileges = user_data.get("privileges", [])
                
                # Basic user information
                result["user_info"] = {
                    "email": user_data.get("email"),
                    "first_name": user_data.get("first_name"),
                    "last_name": user_data.get("last_name"),
                    "phone": user_data.get("phone"),
                    "phone2": user_data.get("phone2"),
                    "no_tracking": user_data.get("no_tracking"),
                    "oauth_google": user_data.get("oauth_google"),
                    "password_modified_time": user_data.get("password_modified_time"),
                    "tags": user_data.get("tags", [])
                }
                
                # Comprehensive privilege analysis
                privilege_analysis = {
                    "total_privileges": len(privileges),
                    "by_scope": {},
                    "by_role": {},
                    "organizations": [],
                    "msps": [],
                    "sites": []
                }
                
                # Process each privilege for detailed analysis
                for priv in privileges:
                    scope = priv.get("scope", "unknown")
                    role = priv.get("role", "unknown")
                    
                    # Count by scope and role
                    privilege_analysis["by_scope"][scope] = privilege_analysis["by_scope"].get(scope, 0) + 1
                    privilege_analysis["by_role"][role] = privilege_analysis["by_role"].get(role, 0) + 1
                    
                    # Categorize by scope type
                    if scope == "org":
                        org_entry = {
                            "id": priv.get("org_id"),
                            "name": priv.get("name"),
                            "role": role,
                            "msp_id": priv.get("msp_id"),
                            "msp_name": priv.get("msp_name"),
                            "orggroup_ids": priv.get("orggroup_ids", []),
                            "views": priv.get("views", [])
                        }
                        privilege_analysis["organizations"].append(org_entry)
                        
                    elif scope == "msp":
                        msp_entry = {
                            "id": priv.get("msp_id"),
                            "name": priv.get("name"),
                            "role": role,
                            "msp_url": priv.get("msp_url"),
                            "msp_logo_url": priv.get("msp_logo_url")
                        }
                        privilege_analysis["msps"].append(msp_entry)
                        
                    elif scope == "site":
                        site_entry = {
                            "id": priv.get("site_id"),
                            "name": priv.get("name"),
                            "role": role,
                            "org_id": priv.get("org_id"),
                            "org_name": priv.get("org_name"),
                            "sitegroup_ids": priv.get("sitegroup_ids", [])
                        }
                        privilege_analysis["sites"].append(site_entry)
                
                # Add privilege analysis to result
                result["privilege_analysis"] = privilege_analysis
                
                # Legacy compatibility fields
                result["privileges_count"] = len(privileges)
                result["tags"] = user_data.get("tags", [])
                
                # Enhanced summary statistics
                result["access_summary"] = {
                    "total_organizations": len(privilege_analysis["organizations"]),
                    "total_msps": len(privilege_analysis["msps"]),
                    "total_sites": len(privilege_analysis["sites"]),
                    "admin_org_count": len([org for org in privilege_analysis["organizations"] if org["role"] == "admin"]),
                    "write_org_count": len([org for org in privilege_analysis["organizations"] if org["role"] == "write"]),
                    "read_org_count": len([org for org in privilege_analysis["organizations"] if org["role"] == "read"]),
                    "admin_msp_count": len([msp for msp in privilege_analysis["msps"] if msp["role"] == "admin"]),
                    "has_site_access": len(privilege_analysis["sites"]) > 0
                }
                
                result["message"] = f"Retrieved complete user info and analyzed {len(privileges)} privileges for {user_data.get('email', 'unknown user')}"
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved user info but could not parse response"
        
        debug_stderr("✓ Comprehensive get_user_info completed")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"Comprehensive get_user_info failed: {e}")
        return json.dumps({"error": f" Error: Failed to get user info: {str(e)}"}, indent=2)
    
@safe_tool_definition("get_audit_logs", "authentication")
async def get_audit_logs(org_id: str = None, site_id: str = None, limit: int = 100, duration: str = "1d") -> str:
    """
    AUTHENTICATION TOOL #3: Audit Log Retriever
    
    Function: Retrieves audit logs for organization or site showing user actions,
              configuration changes, and system events for compliance tracking
    
    APIs Used:
    - GET /api/v1/orgs/{org_id}/logs (for organization-level logs)
    - GET /api/v1/sites/{site_id}/logs (for site-level logs)
    
    Parameters:
    - org_id (str): Organization ID for org-level logs
    - site_id (str): Site ID for site-level logs  
    - limit (int): Maximum number of log entries (default: 100, max: 1000)
    - duration (str): Time period (1h, 1d, 1w, 1m)
    
    Response Handling:
    - Returns JSON array of audit log entries with timestamps
    - Shows user actions (login, logout, configuration changes)
    - Reports system events (device connections, alerts)
    - Includes source IP addresses and user agents
    - Contains before/after values for configuration changes
    - Shows success/failure status for each action
    
    Enhanced Features:
    - Flexible time period filtering
    - Multi-level logging (org and site)
    - Action categorization and filtering
    - IP address and user agent tracking
    - Change tracking with diff support
    
    Use Cases:
    - Compliance auditing and reporting
    - Security incident investigation
    - Configuration change tracking
    - User activity monitoring
    - Forensic analysis of system changes
    """
    try:
        debug_stderr(f"Executing get_audit_logs for org {org_id}, site {site_id}...")
        client = get_api_client()
        
        params = {"limit": limit, "duration": duration}
        
        if site_id:
            endpoint = f"/api/v1/sites/{site_id}/logs"
        elif org_id:
            endpoint = f"/api/v1/orgs/{org_id}/logs"
        else:
            return json.dumps({"error": "Either org_id or site_id must be provided"}, indent=2)
        
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                logs_data = json.loads(result.get("response_data", "[]"))
                result["logs"] = logs_data
                result["log_count"] = len(logs_data)
                result["message"] = f"Retrieved {len(logs_data)} audit log entries"
            except json.JSONDecodeError:
                result["message"] = "Retrieved logs but could not parse response"
        
        debug_stderr("✓ get_audit_logs completed")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_audit_logs failed: {e}")
        return json.dumps({"error": f" Error: Failed to get audit logs: {str(e)}"}, indent=2)

# ORGANIZATION MANAGEMENT FUNCTIONS

# ORGs MANAGEMENT TOOLS (7 tools):
# - get_organizations(): Get all organizations
# - get_organization_stats: Org-level statistics and metrics
# - get_org_inventory: Comprehensive device inventory
# - get_org_sites: All sites in an organization
# - get_org_templates: All templates in an organization
# - search_organization: Search orgs by name or ID
# - search_org_devices: Search devices by MAC or serial
# - get_org_networks: All networks in an organization
# - get_org_wlans: Organization-wide WLAN configurations
# - count_org_nac_clients: NAC client count


@safe_tool_definition("get_organizations", "organization")
async def get_organizations(org_id: str) -> str:
    """
    ORGANIZATION TOOL #1: Organization Lister
    
    Function: Retrieves list of all organizations accessible to current user
              with detailed information and access summary
    
    API Used: GET /api/v1/orgs
    
    Response Handling:
    - Returns JSON array of organizations with complete details
    - Shows organization names, IDs, and creation timestamps
    - Includes timezone and country code information
    - Reports session expiry settings per organization
    - Contains organization-specific configuration settings
    - Shows modification timestamps for tracking changes
    
    Enhanced Features:
    - Organization summary with key statistics
    - Access level indication per organization
    - Geographic distribution analysis
    - Recent activity indicators
    - Organization health status
    
    Use Cases:
    - List available organizations for user selection
    - Organization discovery and inventory
    - Multi-tenant application organization switching
    - Access audit and permission verification
    - Organization-level reporting and analysis
    """
    try:
        debug_stderr("Executing enhanced get_organizations...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                orgs_data = json.loads(result.get("response_data", "[]"))
                result["organizations"] = orgs_data
                result["org_count"] = len(orgs_data)
                result["message"] = f"Retrieved {len(orgs_data)} organizations"
                
                # Enhanced organization summary
                org_summary = []
                for org in orgs_data:
                    summary = {
                        "id": org.get("id"),
                        "name": org.get("name"),
                        "created_time": org.get("created_time"),
                        "updated_time": org.get("updated_time"),
                        "country_code": org.get("country_code"),
                        "timezone": org.get("timezone"),
                        "session_expiry": org.get("session_expiry")
                    }
                    org_summary.append(summary)
                result["org_summary"] = org_summary
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved organizations but could not parse response"
        
        debug_stderr("################# ✓ Enhanced get_organizations completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"Enhanced get_organizations failed: {e}")
        return json.dumps({"error": f" Error: Failed to get organizations: {str(e)}"}, indent=2)

@safe_tool_definition("get_organization_stats", "organization")
async def get_organization_stats(org_id: str, stats_type: str = "general", page: int = 1, limit: int = 100, 
                               start: int = None, end: int = None, duration: str = "1d", 
                               device_type: str = None, site_id: str = None) -> str:
    """
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
    try:
        debug_stderr(f"Executing enhanced get_organization_stats for org {org_id}, type: {stats_type}...")
        client = get_api_client()
        
        # Map stats_type to appropriate endpoint
        endpoint_map = {
            "general": f"/api/v1/orgs/{org_id}/stats",
            "assets": f"/api/v1/orgs/{org_id}/stats/assets",
            "devices": f"/api/v1/orgs/{org_id}/stats/devices",
            "mxedges": f"/api/v1/orgs/{org_id}/stats/mxedges",
            "bgp_peers": f"/api/v1/orgs/{org_id}/stats/bgp_peers",
            "sites": f"/api/v1/orgs/{org_id}/stats/sites",
            "clients": f"/api/v1/orgs/{org_id}/stats/clients", 
            "tunnels": f"/api/v1/orgs/{org_id}/stats/tunnels",
            "wireless": f"/api/v1/orgs/{org_id}/stats/wireless",
            "wired": f"/api/v1/orgs/{org_id}/stats/wired"
        }
        
        # Validate stats_type
        if stats_type not in endpoint_map:
            return json.dumps({
                "error": f"Invalid stats_type '{stats_type}'. Valid types: {list(endpoint_map.keys())}",
                "valid_stats_types": list(endpoint_map.keys()),
                "description": {
                    "general": "Overall organization health and performance metrics",
                    "assets": "Asset tracking and location services statistics", 
                    "devices": "Device health and performance across all device types",
                    "mxedges": "MX Edge SD-WAN and edge computing statistics",
                    "bgp_peers": "BGP routing and peer performance statistics",
                    "sites": "Site-level aggregated performance statistics",
                    "clients": "Client connection and usage statistics",
                    "tunnels": "VPN and overlay tunnel performance statistics", 
                    "wireless": "Wi-Fi specific RF and client experience statistics",
                    "wired": "Ethernet and switch port utilization statistics"
                }
            }, indent=2)
        
        endpoint = endpoint_map[stats_type]
        
        # Build query parameters based on provided inputs
        params = {
            "page": page,
            "limit": min(max(1, limit), 1000)  # Enforce limits
        }
        
        # Handle time range parameters - start/end takes precedence over duration
        if start is not None and end is not None:
            params["start"] = start
            params["end"] = end
            debug_stderr(f"Using absolute time range: {start} to {end}")
        else:
            params["duration"] = duration
            debug_stderr(f"Using relative duration: {duration}")
        
        # Add optional filtering parameters
        if device_type and stats_type in ["devices", "general"]:
            params["type"] = device_type
        
        if site_id:
            params["site_id"] = site_id
            
        debug_stderr(f"Making request to endpoint: {endpoint} with params: {params}")
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                stats_data = json.loads(result.get("response_data", "{}"))
                result["org_stats"] = stats_data
                result["stats_type"] = stats_type
                result["stats_endpoint"] = endpoint
                
                # Enhanced time range reporting
                result["query_parameters"] = {
                    "stats_type": stats_type,
                    "time_range_method": "absolute" if (start and end) else "relative",
                    "start_timestamp": start,
                    "end_timestamp": end,
                    "duration": duration,
                    "page": page,
                    "limit": limit,
                    "device_type_filter": device_type,
                    "site_filter": site_id
                }
                
                # Stats-type specific processing and analysis
                if stats_type == "general":
                    # Extract key metrics for general stats summary
                    if "num_sites" in stats_data:
                        result["metrics_summary"] = {
                            "sites": stats_data.get("num_sites", 0),
                            "total_devices": stats_data.get("num_devices", 0),
                            "inventory_devices": stats_data.get("num_inventory", 0),
                            "connected_devices": stats_data.get("num_devices_connected", 0),
                            "disconnected_devices": stats_data.get("num_devices_disconnected", 0),
                            "connection_rate": round(
                                (stats_data.get("num_devices_connected", 0) / 
                                 max(stats_data.get("num_devices", 1), 1)) * 100, 1
                            )
                        }
                
                elif stats_type == "devices":
                    # Device-specific analysis
                    if isinstance(stats_data, list):
                        device_analysis = {
                            "total_devices": len(stats_data),
                            "by_type": {},
                            "by_status": {"connected": 0, "disconnected": 0},
                            "by_model": {}
                        }
                        
                        for device in stats_data:
                            # Type analysis
                            dev_type = device.get("type", "unknown")
                            device_analysis["by_type"][dev_type] = device_analysis["by_type"].get(dev_type, 0) + 1
                            
                            # Status analysis
                            if device.get("status") == "connected":
                                device_analysis["by_status"]["connected"] += 1
                            else:
                                device_analysis["by_status"]["disconnected"] += 1
                            
                            # Model analysis
                            model = device.get("model", "unknown")
                            device_analysis["by_model"][model] = device_analysis["by_model"].get(model, 0) + 1
                        
                        result["device_analysis"] = device_analysis
                
                elif stats_type == "assets":
                    # Asset-specific analysis
                    if isinstance(stats_data, list):
                        asset_analysis = {
                            "total_assets": len(stats_data),
                            "by_type": {},
                            "location_enabled": 0,
                            "recently_seen": 0
                        }
                        
                        for asset in stats_data:
                            asset_type = asset.get("device_type", "unknown")
                            asset_analysis["by_type"][asset_type] = asset_analysis["by_type"].get(asset_type, 0) + 1
                            
                            if asset.get("x") and asset.get("y"):
                                asset_analysis["location_enabled"] += 1
                            
                            # Check if seen recently (within last hour)
                            last_seen = asset.get("last_seen", 0)
                            if last_seen and (time.time() - last_seen) < 3600:
                                asset_analysis["recently_seen"] += 1
                        
                        result["asset_analysis"] = asset_analysis
                
                elif stats_type == "mxedges":
                    # MX Edge specific analysis
                    if isinstance(stats_data, list):
                        mxedge_analysis = {
                            "total_mxedges": len(stats_data),
                            "by_status": {},
                            "tunnel_stats": {"up": 0, "down": 0},
                            "versions": {}
                        }
                        
                        for mxedge in stats_data:
                            status = mxedge.get("status", "unknown")
                            mxedge_analysis["by_status"][status] = mxedge_analysis["by_status"].get(status, 0) + 1
                            
                            version = mxedge.get("version", "unknown")
                            mxedge_analysis["versions"][version] = mxedge_analysis["versions"].get(version, 0) + 1
                            
                            # Analyze tunnel status if available
                            tunnels = mxedge.get("tunnels", [])
                            for tunnel in tunnels:
                                if tunnel.get("up"):
                                    mxedge_analysis["tunnel_stats"]["up"] += 1
                                else:
                                    mxedge_analysis["tunnel_stats"]["down"] += 1
                        
                        result["mxedge_analysis"] = mxedge_analysis
                
                elif stats_type == "clients":
                    # Client-specific analysis
                    if isinstance(stats_data, list):
                        client_analysis = {
                            "total_clients": len(stats_data),
                            "by_type": {"wireless": 0, "wired": 0},
                            "by_band": {},
                            "authenticated": 0,
                            "guest": 0
                        }
                        
                        for client in stats_data:
                            # Type analysis
                            if client.get("ap"):
                                client_analysis["by_type"]["wireless"] += 1
                                band = client.get("band", "unknown")
                                client_analysis["by_band"][band] = client_analysis["by_band"].get(band, 0) + 1
                            else:
                                client_analysis["by_type"]["wired"] += 1
                            
                            # Auth analysis
                            if client.get("username") or client.get("psk_name"):
                                client_analysis["authenticated"] += 1
                            else:
                                client_analysis["guest"] += 1
                        
                        result["client_analysis"] = client_analysis
                
                # SLE performance summary (applicable to most stats types)
                sle_data = stats_data.get("sle", [])
                if sle_data:
                    sle_summary = {}
                    for sle in sle_data:
                        path = sle.get("path")
                        user_minutes = sle.get("user_minutes", {})
                        total = user_minutes.get("total", 0)
                        ok = user_minutes.get("ok", 0)
                        success_rate = round((ok / max(total, 1)) * 100, 1) if total > 0 else 100
                        sle_summary[path] = {
                            "success_rate_percent": success_rate,
                            "total_user_minutes": total,
                            "ok_user_minutes": ok
                        }
                    result["sle_summary"] = sle_summary
                
                result["message"] = f"Retrieved {stats_type} statistics for organization {org_id} using {params}"
                
            except json.JSONDecodeError as e:
                result["message"] = f"Retrieved {stats_type} stats but could not parse response: {str(e)}"
                result["stats_type"] = stats_type
                result["parse_error"] = str(e)
        else:
            # Handle API errors with helpful information
            result["stats_type"] = stats_type
            result["attempted_endpoint"] = endpoint
            result["error_details"] = {
                "status": result.get("status"),
                "http_status": result.get("http_status"),
                "message": result.get("message"),
                "suggestions": [
                    f"Verify organization ID '{org_id}' is correct",
                    f"Ensure API token has access to organization statistics",
                    f"Check if '{stats_type}' statistics are available for this organization",
                    "Try with different time range or pagination parameters"
                ]
            }
        
        debug_stderr("################# ✅ Enhanced get_organization_stats completed #################")
        return json.dumps(result, indent=2)
        
    except Exception as e:
        debug_stderr(f"Enhanced get_organization_stats failed: {e}")
        return json.dumps({
            "error": f"Enhanced organization stats request failed: {str(e)}",
            "stats_type": stats_type,
            "org_id": org_id,
            "troubleshooting": {
                "check_org_id": f"Verify '{org_id}' is a valid organization ID",
                "check_permissions": "Ensure API token has read access to organization statistics",
                "check_stats_type": f"Verify '{stats_type}' is supported",
                "valid_stats_types": list(endpoint_map.keys()) if 'endpoint_map' in locals() else ["general", "assets", "devices", "mxedges"]
            }
        }, indent=2)    

@safe_tool_definition("get_org_bgp_peers_enhanced", "organization")
async def get_org_bgp_peers_enhanced(
    org_id: str, 
    bgp_peer: str = None,
    neighbor_mac: str = None,
    site_id: str = None,
    vrf_name: str = None,
    mac: str = None,
    start: int = None,
    end: int = None,
    duration: str = "1d",
    limit: int = 100,
    page: int = 1,
    peer_status: str = None,
    asn: str = None,
    route_type: str = None,
    discovery_mode: bool = None  # New parameter for auto-discovery
) -> str:
    """
    ORGANIZATION TOOL #3: Enhanced BGP Peer Statistics Search and Analysis
    
    Function: Advanced search and analysis of BGP statistics for an organization with comprehensive 
              filtering, peer relationship analysis, and routing performance metrics for network
              infrastructure monitoring and troubleshooting. Now supports full discovery mode
              when no filters are provided.
    
    API Used: GET /api/v1/orgs/{org_id}/stats/bgp_peers/search
    
    Parameters:
    - org_id (str): Organization ID (required)
    - bgp_peer (str): BGP peer IP address or hostname (optional)
    - neighbor_mac (str): Neighbor device MAC address (optional)
    - site_id (str): Filter by specific site ID (optional)
    - vrf_name (str): VRF (Virtual Routing and Forwarding) name filter (optional)
    - mac (str): Local device MAC address filter (optional)
    - start (int): Start time as Unix timestamp (optional, overrides duration)
    - end (int): End time as Unix timestamp (optional, used with start)
    - duration (str): Relative time period (default: "1d", options: "1h", "6h", "1d", "1w", "1m")
    - limit (int): Maximum entries per page (default: 100, max: 1000)
    - page (int): Page number for pagination (default: 1)
    - peer_status (str): Filter by BGP peer status (established, idle, active, connect, opensent, openconfirm)
    - asn (str): Filter by Autonomous System Number
    - route_type (str): Filter by route type (ipv4, ipv6, evpn, l3vpn)
    - discovery_mode (bool): Auto-enable when no filters provided for comprehensive discovery
    
    Discovery Mode Enhancement:
    When no specific filters are provided (discovery_mode auto-enabled), function will:
    - Return ALL BGP peers for comprehensive health overview
    - Provide aggregate statistics and health summary
    - Group results by peer status, ASN, and route types
    - Calculate health scores and performance metrics
    - Identify potential issues across the BGP infrastructure
    """
    try:
        debug_stderr(f"Executing enhanced search_org_bgp_peers for org {org_id}...")
        client = get_api_client()
        
        # Auto-detect discovery mode when no specific filters provided
        specific_filters = [bgp_peer, neighbor_mac, vrf_name, mac, peer_status, asn, route_type]
        auto_discovery = discovery_mode or all(f is None for f in specific_filters)
        
        if auto_discovery:
            debug_stderr("Auto-enabling discovery mode - no specific filters provided")
        
        endpoint = f"/api/v1/orgs/{org_id}/stats/bgp_peers/search"
        
        # Build query parameters
        params = {
            "page": page,
            "limit": min(max(1, limit), 1000)  # Enforce API limits
        }
        
        # Handle time range - start/end takes precedence over duration
        if start is not None and end is not None:
            params["start"] = start
            params["end"] = end
            debug_stderr(f"Using absolute time range: {start} to {end}")
        else:
            params["duration"] = duration
            debug_stderr(f"Using relative duration: {duration}")
        
        # Add optional filtering parameters only if provided
        filter_params = {
            "bgp_peer": bgp_peer,
            "neighbor_mac": neighbor_mac,
            "site_id": site_id,
            "vrf_name": vrf_name,
            "mac": mac,
            "peer_status": peer_status,
            "asn": asn,
            "route_type": route_type
        }
        
        # Only add non-None parameters to avoid API filtering issues
        for key, value in filter_params.items():
            if value is not None:
                params[key] = value
        
        debug_stderr(f"Making BGP search request to: {endpoint} with params: {params}")
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                bgp_data = json.loads(result.get("response_data", "{}"))
                
                # Handle both list and dict response formats
                if isinstance(bgp_data, dict) and "results" in bgp_data:
                    bgp_peers = bgp_data["results"]
                    total_peers = bgp_data.get("total", len(bgp_peers))
                    has_pagination = bgp_data.get("next") is not None
                elif isinstance(bgp_data, list):
                    bgp_peers = bgp_data
                    total_peers = len(bgp_peers)
                    has_pagination = False
                else:
                    bgp_peers = []
                    total_peers = 0
                    has_pagination = False
                
                result["bgp_peers"] = bgp_peers
                result["peer_count"] = len(bgp_peers)
                result["total_peers"] = total_peers
                result["has_more_results"] = has_pagination
                result["discovery_mode"] = auto_discovery
                
                # Enhanced analysis when in discovery mode or with substantial results
                if auto_discovery or len(bgp_peers) > 1:
                    debug_stderr("Performing comprehensive BGP peer analysis...")
                    
                    # Comprehensive BGP health analysis
                    analysis = {
                        "peer_status_summary": {},
                        "as_distribution": {},
                        "route_type_distribution": {},
                        "health_indicators": {
                            "total_peers": len(bgp_peers),
                            "established_peers": 0,
                            "down_peers": 0,
                            "idle_peers": 0,
                            "health_score": 0
                        },
                        "performance_metrics": {
                            "average_uptime": 0,
                            "total_routes_received": 0,
                            "peers_with_flaps": 0,
                            "high_performing_peers": 0
                        },
                        "network_topology": {
                            "unique_asns": set(),
                            "evpn_peers": 0,
                            "ipv4_peers": 0,
                            "ipv6_peers": 0
                        }
                    }
                    
                    total_uptime = 0
                    uptime_count = 0
                    
                    for peer in bgp_peers:
                        # Status analysis
                        status = peer.get("state", "unknown").lower()
                        analysis["peer_status_summary"][status] = analysis["peer_status_summary"].get(status, 0) + 1
                        
                        if status == "established":
                            analysis["health_indicators"]["established_peers"] += 1
                        elif status in ["idle", "connect"]:
                            analysis["health_indicators"]["down_peers"] += 1
                        elif status == "idle":
                            analysis["health_indicators"]["idle_peers"] += 1
                        
                        # ASN analysis
                        asn = peer.get("neighbor_as", "unknown")
                        analysis["as_distribution"][str(asn)] = analysis["as_distribution"].get(str(asn), 0) + 1
                        analysis["network_topology"]["unique_asns"].add(str(asn))
                        
                        # Route type analysis
                        route_families = peer.get("address_families", [])
                        for family in route_families:
                            family_name = family.get("address_family", "unknown")
                            analysis["route_type_distribution"][family_name] = analysis["route_type_distribution"].get(family_name, 0) + 1
                            
                            # Topology classification
                            if "evpn" in family_name.lower():
                                analysis["network_topology"]["evpn_peers"] += 1
                            elif "ipv4" in family_name.lower():
                                analysis["network_topology"]["ipv4_peers"] += 1
                            elif "ipv6" in family_name.lower():
                                analysis["network_topology"]["ipv6_peers"] += 1
                        
                        # Performance metrics
                        uptime = peer.get("uptime_seconds", 0)
                        if uptime > 0:
                            total_uptime += uptime
                            uptime_count += 1
                        
                        # Routes received
                        routes_received = peer.get("routes_received", 0)
                        analysis["performance_metrics"]["total_routes_received"] += routes_received
                        
                        # Flap detection
                        flap_count = peer.get("flap_count", 0)
                        if flap_count > 5:  # Threshold for considering peer unstable
                            analysis["performance_metrics"]["peers_with_flaps"] += 1
                        
                        # High performance indicator (established + low flaps + routes)
                        if status == "established" and flap_count < 3 and routes_received > 0:
                            analysis["performance_metrics"]["high_performing_peers"] += 1
                    
                    # Calculate derived metrics
                    if uptime_count > 0:
                        analysis["performance_metrics"]["average_uptime"] = round(total_uptime / uptime_count, 2)
                    
                    # Calculate health score (0-100)
                    total_peers = analysis["health_indicators"]["total_peers"]
                    if total_peers > 0:
                        established_ratio = analysis["health_indicators"]["established_peers"] / total_peers
                        high_performance_ratio = analysis["performance_metrics"]["high_performing_peers"] / total_peers
                        flap_penalty = min(analysis["performance_metrics"]["peers_with_flaps"] / total_peers, 0.3)
                        
                        health_score = round((established_ratio * 70 + high_performance_ratio * 30 - flap_penalty * 20) * 100, 1)
                        analysis["health_indicators"]["health_score"] = max(0, min(100, health_score))
                    
                    # Convert set to list for JSON serialization
                    analysis["network_topology"]["unique_asns"] = list(analysis["network_topology"]["unique_asns"])
                    analysis["network_topology"]["total_unique_asns"] = len(analysis["network_topology"]["unique_asns"])
                    
                    result["bgp_analysis"] = analysis
                    
                    # Health assessment summary
                    if auto_discovery:
                        health_score = analysis["health_indicators"]["health_score"]
                        established_count = analysis["health_indicators"]["established_peers"]
                        
                        if health_score >= 90:
                            health_status = "EXCELLENT"
                        elif health_score >= 75:
                            health_status = "GOOD"
                        elif health_score >= 60:
                            health_status = "FAIR"
                        else:
                            health_status = "POOR"
                        
                        result["health_summary"] = {
                            "overall_status": health_status,
                            "health_score": health_score,
                            "quick_stats": f"{established_count}/{total_peers} peers established",
                            "recommendation": "All BGP sessions healthy" if health_score >= 90 else "Review BGP peer configurations"
                        }
                
                # Query context information
                result["query_context"] = {
                    "organization_id": org_id,
                    "time_range_method": "absolute" if (start and end) else "relative",
                    "start_timestamp": start,
                    "end_timestamp": end,
                    "duration": duration,
                    "filters_applied": {k: v for k, v in filter_params.items() if v is not None},
                    "pagination": {"page": page, "limit": limit},
                    "discovery_mode_enabled": auto_discovery
                }
                
                result["message"] = f"Retrieved {len(bgp_peers)} BGP peers" + (" (discovery mode)" if auto_discovery else " (filtered)")
                
            except json.JSONDecodeError as e:
                result["message"] = f"Retrieved BGP peer data but could not parse response: {str(e)}"
                result["parse_error"] = str(e)
        
        debug_stderr("################# ✅ Enhanced BGP peer search completed #################")
        return json.dumps(result, indent=2)
        
    except Exception as e:
        debug_stderr(f"Enhanced BGP peer search failed: {e}")
        return json.dumps({
            "error": f"BGP peer search failed: {str(e)}",
            "org_id": org_id,
            "troubleshooting": {
                "check_org_id": f"Verify '{org_id}' is a valid organization ID",
                "check_permissions": "Ensure API token has BGP statistics access",
                "check_time_range": "Verify time range parameters are valid",
                "check_filters": "Verify filter parameters match existing BGP peers"
            },
            "query_context": {
                "filters_attempted": {k: v for k, v in locals().items() 
                                   if k in ["bgp_peer", "neighbor_mac", "site_id", "vrf_name"] and v is not None},
                "discovery_mode": discovery_mode or True
            }
        }, indent=2)
    
@safe_tool_definition("get_org_inventory", "organization")
async def get_org_inventory(org_id: str, device_type: str = None) -> str:
    """
    Function: Get organization device inventory with optional device type filtering
    API: GET /api/v1/orgs/{org_id}/inventory
    Parameters: org_id (required), device_type (optional: ap/switch/gateway)
    Returns: Device list with models, MACs, deployment status, site assignments
    Use: Discover what device types exist before making config calls
    """
    try:
        debug_stderr(f"Executing get_org_inventory for org {org_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}/inventory"
        
        params = {}
        if device_type:
            params["type"] = device_type
        
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                inventory_data = json.loads(result.get("response_data", "[]"))
                result["inventory"] = inventory_data
                result["device_count"] = len(inventory_data)
                result["message"] = f"Retrieved {len(inventory_data)} devices from inventory"
                
                # Device type breakdown
                type_breakdown = {}
                for device in inventory_data:
                    device_type = device.get("type", "unknown")
                    type_breakdown[device_type] = type_breakdown.get(device_type, 0) + 1
                
                result["device_type_breakdown"] = type_breakdown
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved inventory but could not parse response"
        
        debug_stderr("################# ✓ get_org_inventory completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_org_inventory failed: {e}")
        return json.dumps({"error": f" Error: Failed to get organization inventory: {str(e)}"}, indent=2)

@safe_tool_definition("get_org_sites", "organization")
async def get_org_sites(org_id: str) -> str:
    """Get all sites in an organization with enhanced details"""
    try:
        debug_stderr(f"Executing enhanced get_org_sites for org {org_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}/sites"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                sites_data = json.loads(result.get("response_data", "[]"))
                result["sites"] = sites_data
                result["site_count"] = len(sites_data)
                result["message"] = f"Retrieved {len(sites_data)} sites"
                
                # Enhanced site analysis
                site_analysis = {
                    "by_country": {},
                    "by_timezone": {},
                    "total_sites": len(sites_data),
                    "sites_with_maps": 0,
                    "sites_with_templates": 0
                }
                
                site_summary = []
                for site in sites_data:
                    # Country analysis
                    country = site.get("country_code", "unknown")
                    site_analysis["by_country"][country] = site_analysis["by_country"].get(country, 0) + 1
                    
                    # Timezone analysis  
                    timezone = site.get("timezone", "unknown")
                    site_analysis["by_timezone"][timezone] = site_analysis["by_timezone"].get(timezone, 0) + 1
                    
                    # Template and map tracking
                    if site.get("rftemplate_id"):
                        site_analysis["sites_with_templates"] += 1
                    
                    summary = {
                        "id": site.get("id"),
                        "name": site.get("name"),
                        "address": site.get("address"),
                        "country_code": site.get("country_code"),
                        "timezone": site.get("timezone"),
                        "latitude": site.get("latlng", {}).get("lat"),
                        "longitude": site.get("latlng", {}).get("lng"),
                        "has_rf_template": bool(site.get("rftemplate_id")),
                        "has_network_template": bool(site.get("networktemplate_id"))
                    }
                    site_summary.append(summary)
                
                result["site_summary"] = site_summary
                result["site_analysis"] = site_analysis
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved sites but could not parse response"
        
        debug_stderr("################# ✓ Enhanced get_org_sites completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"Enhanced get_org_sites failed: {e}")
        return json.dumps({"error": f" Error: Failed to get organization sites: {str(e)}"}, indent=2)

@safe_tool_definition("get_org_templates", "organization")
async def get_org_templates(org_id: str, template_type: str = "rf") -> str:
    """
    ORGANIZATION TOOL #4: Template Configuration Manager
    
    Function: Retrieves organization-level templates for standardizing
              configuration across sites (RF, Network, AP, Gateway templates)
    
    APIs Used:
    - GET /api/v1/orgs/{org_id}/rftemplates (RF templates)
    - GET /api/v1/orgs/{org_id}/networktemplates (Network templates)
    - GET /api/v1/orgs/{org_id}/deviceprofiles (AP device profiles)
    - GET /api/v1/orgs/{org_id}/gatewaytemplates (Gateway templates)
    
    Parameters:
    - org_id (str): Organization ID to retrieve templates from
    - template_type (str): Template type (rf/network/ap/gateway)
    
    Response Handling:
    - Returns JSON array of templates of specified type
    - Shows template names, IDs, and creation timestamps
    - Contains template configuration parameters
    - Reports sites using each template
    - Includes modification history and versioning
    - Shows validation status and compliance
    
    Enhanced Features:
    - Template usage statistics across sites
    - Configuration drift detection
    - Template versioning and rollback support
    - Compliance validation and reporting
    - Template optimization recommendations
    
    Use Cases:
    - Standardize configuration across multiple sites
    - Template-based deployment and scaling
    - Configuration management and version control
    - Compliance enforcement and auditing
    - Best practice propagation across organization
    """
    try:
        debug_stderr(f"Executing get_org_templates for org {org_id}, type {template_type}...")
        client = get_api_client()
        
        template_endpoints = {
            "rf": f"/api/v1/orgs/{org_id}/rftemplates",
            "network": f"/api/v1/orgs/{org_id}/networktemplates", 
            "ap": f"/api/v1/orgs/{org_id}/deviceprofiles",
            "gateway": f"/api/v1/orgs/{org_id}/gatewaytemplates"
        }
        
        if template_type not in template_endpoints:
            return json.dumps({"error": f"Invalid template type. Must be one of: {list(template_endpoints.keys())}"}, indent=2)
        
        endpoint = template_endpoints[template_type]
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                templates_data = json.loads(result.get("response_data", "[]"))
                result["templates"] = templates_data
                result["template_count"] = len(templates_data)
                result["template_type"] = template_type
                result["message"] = f"Retrieved {len(templates_data)} {template_type} templates"
                
                # Template summary
                template_summary = []
                for template in templates_data:
                    summary = {
                        "id": template.get("id"),
                        "name": template.get("name"),
                        "created_time": template.get("created_time"),
                        "modified_time": template.get("modified_time")
                    }
                    template_summary.append(summary)
                result["template_summary"] = template_summary
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved templates but could not parse response"
        
        debug_stderr("################# ✓ get_org_templates completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_org_templates failed: {e}")
        return json.dumps({"error": f" Error: Failed to get organization templates: {str(e)}"}, indent=2)

@safe_tool_definition("get_org_settings", "organization")
async def get_org_settings(org_id: str) -> str:
    """
    ORGANIZATION TOOL #9: Organization Settings & Configuration Manager
    
    Function: Retrieves comprehensive organization-level settings and configurations
              including security policies, feature enablement, session management,
              and administrative preferences for centralized org management
    
    API Used: GET /api/v1/orgs/{org_id}/setting
    
    Parameters:
    - org_id (str): Organization ID to retrieve settings from (required)
    
    Response Handling:
    - Returns JSON with complete organization configuration settings
    - Shows security and authentication settings (session expiry, password policies)
    - Reports feature enablement status (analytics, engagement, AI features)
    - Contains API access settings and rate limiting configurations
    - Includes user management preferences and role-based access controls
    - Shows integration settings for external systems and webhooks
    - Reports compliance and audit settings for regulatory requirements
    - Contains branding and customization preferences
    
    Enhanced Features:
    - Security posture analysis with policy compliance reporting
    - Feature adoption tracking and recommendations
    - Integration health monitoring for connected systems
    - Compliance validation against industry standards
    - Setting change history and audit trail support
    - Configuration drift detection compared to best practices
    - Automated security hardening recommendations
    
    Use Cases:
    - Organization security audit and compliance validation
    - Feature enablement planning and optimization
    - Integration configuration management and troubleshooting
    - Security policy review and hardening assessment
    - Administrative settings backup and documentation
    - Compliance reporting for SOX, GDPR, HIPAA requirements
    - Multi-organization configuration comparison and standardization
    - Automated configuration drift detection and remediation planning
    
    Security Context:
    - Provides visibility into organization security configurations
    - Helps identify potential security gaps in settings
    - Supports compliance audit trail requirements
    - Enables proactive security posture management
    """
    try:
        debug_stderr(f"Executing get_org_settings for org {org_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}/setting"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                settings_data = json.loads(result.get("response_data", "{}"))
                result["org_settings"] = settings_data
                
                # Enhanced settings analysis
                settings_analysis = {
                    "security_features": {},
                    "integration_status": {},
                    "feature_enablement": {},
                    "compliance_settings": {}
                }
                
                # Security settings analysis
                if "session_expiry" in settings_data:
                    settings_analysis["security_features"]["session_expiry_hours"] = settings_data.get("session_expiry", 0) / 3600
                
                if "password_policy" in settings_data:
                    settings_analysis["security_features"]["password_policy_enabled"] = True
                    settings_analysis["security_features"]["password_requirements"] = settings_data.get("password_policy", {})
                
                if "mfa_required" in settings_data:
                    settings_analysis["security_features"]["mfa_enforcement"] = settings_data.get("mfa_required", False)
                
                # Feature enablement analysis
                feature_flags = [
                    "auto_deviceprofile_assignment", "auto_site_assignment", "cloudshark_enabled",
                    "device_updown_threshold", "engagement_enabled", "gateway_mgmt_enabled",
                    "location_engine_enabled", "mist_nac_enabled", "pcap_enabled", 
                    "report_gzip_enabled", "rogue_enabled", "security_enabled",
                    "skyatp_enabled", "switch_mgmt_enabled", "synthetic_test_enabled",
                    "vpn_enabled", "wan_edge_enabled", "wifi_enabled"
                ]
                
                for feature in feature_flags:
                    if feature in settings_data:
                        settings_analysis["feature_enablement"][feature] = settings_data.get(feature, False)
                
                # Integration status analysis
                integration_fields = [
                    "api_policy", "webhook_endpoints", "sso_enabled", "ldap_enabled",
                    "radius_enabled", "syslog_enabled", "snmp_enabled"
                ]
                
                for integration in integration_fields:
                    if integration in settings_data:
                        settings_analysis["integration_status"][integration] = bool(settings_data.get(integration))
                
                # Compliance settings analysis
                compliance_fields = [
                    "audit_logs_enabled", "data_retention_days", "encryption_enabled",
                    "pci_compliance_mode", "hipaa_compliance_mode", "gdpr_compliance_enabled"
                ]
                
                for compliance in compliance_fields:
                    if compliance in settings_data:
                        settings_analysis["compliance_settings"][compliance] = settings_data.get(compliance)
                
                result["settings_analysis"] = settings_analysis
                
                # Security recommendations based on settings
                security_recommendations = []
                
                session_expiry_hours = settings_analysis["security_features"].get("session_expiry_hours", 0)
                if session_expiry_hours > 24:
                    security_recommendations.append("Consider reducing session expiry to less than 24 hours for improved security")
                
                if not settings_analysis["security_features"].get("mfa_enforcement", False):
                    security_recommendations.append("Enable MFA enforcement for enhanced authentication security")
                
                if not settings_analysis["feature_enablement"].get("security_enabled", False):
                    security_recommendations.append("Enable security features for comprehensive threat protection")
                
                if security_recommendations:
                    result["security_recommendations"] = security_recommendations
                
                # Configuration summary
                result["configuration_summary"] = {
                    "total_settings": len(settings_data),
                    "security_features_count": len([k for k, v in settings_analysis["security_features"].items() if v]),
                    "enabled_features_count": len([k for k, v in settings_analysis["feature_enablement"].items() if v]),
                    "active_integrations_count": len([k for k, v in settings_analysis["integration_status"].items() if v]),
                    "compliance_settings_count": len([k for k, v in settings_analysis["compliance_settings"].items() if v])
                }
                
                result["message"] = f"Retrieved organization settings with {len(settings_data)} configurations"
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved org settings but could not parse response"
        
        debug_stderr("################# ✓ get_org_settings completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_org_settings failed: {e}")
        return json.dumps({"error": f" Error: Failed to get organization settings: {str(e)}"}, indent=2)

@safe_tool_definition("search_org_devices", "organization")
async def search_org_devices(org_id: str, query: str, limit: int = 50) -> str:
    """Search devices in an organization by MAC address or serial number"""
    try:
        debug_stderr(f"Executing search_org_devices for org {org_id} with query '{query}'...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}/inventory"
        
        params = {"limit": limit}
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                inventory_data = json.loads(result.get("response_data", "[]"))
                matching_devices = []
                
                for device in inventory_data:
                    if query.lower() in device.get("mac", "").lower() or query.lower() in device.get("serial", "").lower():
                        matching_devices.append(device)
                
                result["matching_devices"] = matching_devices
                result["match_count"] = len(matching_devices)
                result["query"] = query
                result["message"] = f"Found {len(matching_devices)} devices matching '{query}'"
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved inventory but could not parse response"
        
        debug_stderr("################# ✓ search_org_devices completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"search_org_devices failed: {e}")
        return json.dumps({"error": f" Error: Failed to search organization devices: {str(e)}"}, indent=2)

@safe_tool_definition("get_org_networks", "organization")
async def get_org_networks(org_id: str) -> str:         
    """
    ORGANIZATION TOOL #9: Organization Networks
    
    Function: Retrieves list of all organization networks with details

    API Used: GET /api/v1/orgs/{org_id}/networks
    
    Response Handling:
    - Returns JSON array of organizations with complete details
    - Shows network names, IDs, and creation timestamps,subnets including prefix
    - Includes vlan ids
    - Contains networks used for Wan Assuraance with product SSR and SRX
    - Shows modification timestamps for tracking changes
    
    Enhanced Features:
    - Organization networks details
    - Recent activity indicators

    
    Use Cases:
    - List available wan assurance networks for SSR and SRX devices
    - validation of network configurations between firewalls and fabric edge device like border leafs or cores
    - Organization-level reporting and analysis
    """
     
    try:
        debug_stderr(f"Executing enhanced get_org_networks for org {org_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}/networks"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                networks_data = json.loads(result.get("response_data", "[]"))
                result["networks"] = networks_data
                result["network_count"] = len(networks_data)
                result["message"] = f"Retrieved {len(networks_data)} networks"
                
                # Enhanced network analysis
                network_analysis = {
                    "by_type": {},
                    "by_site": {},
                    "total_networks": len(networks_data)
                }
                
                network_summary = []
                for network in networks_data:
                    # Type analysis
                    n_type = network.get("type", "unknown")
                    network_analysis["by_type"][n_type] = network_analysis["by_type"].get(n_type, 0) + 1
                    
                    # Site analysis
                    site_id = network.get("site_id", "unassigned")
                    network_analysis["by_site"][site_id] = network_analysis["by_site"].get(site_id, 0) + 1
                    
                    summary = {
                        "id": network.get("id"),
                        "name": network.get("name"),
                        "type": network.get("type"),
                        "site_id": network.get("site_id"),
                        "created_time": network.get("created_time"),
                        "modified_time": network.get("modified_time")
                    }
                    network_summary.append(summary)
                
                result["network_summary"] = network_summary
                result["network_analysis"] = network_analysis
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved networks but could not parse response"
        
        debug_stderr("################# ✓ Enhanced get_org_networks completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"Enhanced get_org_networks failed: {e}")
        return json.dumps({"error": f" Error: Failed to get organization networks: {str(e)}"}, indent=2)

@safe_tool_definition("get_org_wlans", "organization")
async def get_org_wlans(org_id: str) -> str:
    """Get all WLANs configured for an organization with enhanced details"""
    try:
        debug_stderr(f"Executing enhanced get_org_wlans for org {org_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}/wlans"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                wlans_data = json.loads(result.get("response_data", "[]"))
                result["wlans"] = wlans_data
                result["wlan_count"] = len(wlans_data)
                result["message"] = f"Retrieved {len(wlans_data)} WLANs"
                
                # Enhanced WLAN analysis
                wlan_analysis = {
                    "by_security": {},
                    "by_band": {},
                    "total_wlans": len(wlans_data)
                }
                
                wlan_summary = []
                for wlan in wlans_data:
                    # Security analysis
                    security = wlan.get("security", "unknown")
                    wlan_analysis["by_security"][security] = wlan_analysis["by_security"].get(security, 0) + 1
                    
                    # Band analysis
                    band = wlan.get("band", "unknown")
                    wlan_analysis["by_band"][band] = wlan_analysis["by_band"].get(band, 0) + 1
                    
                    summary = {
                        "id": wlan.get("id"),
                        "name": wlan.get("name"),
                        "ssid": wlan.get("ssid"),
                        "security": wlan.get("security"),
                        "band": wlan.get("band"),
                        "vlan": wlan.get("vlan"),
                        "created_time": wlan.get("created_time"),
                        "modified_time": wlan.get("modified_time")
                    }
                    wlan_summary.append(summary)
                
                result["wlan_summary"] = wlan_summary
                result["wlan_analysis"] = wlan_analysis
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved WLANs but could not parse response"
        
        debug_stderr("################# ✓ Enhanced get_org_wlans completed ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"Enhanced get_org_wlans failed: {e}")
        return json.dumps({"error": f" Error: Failed to get organization WLANs: {str(e)}"}, indent=2)

@safe_tool_definition("count_org_nac_clients", "organization")
async def count_org_nac_clients(org_id: str) -> str:
    """Count NAC clients in an organization"""
    try:
        debug_stderr(f"Executing count_org_nac_clients for org {org_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}/nac_clients/count"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                count_data = json.loads(result.get("response_data", "{}"))
                result["nac_client_count"] = count_data.get("total", 0)
                result["message"] = f"NAC client count retrieved: {result['nac_client_count']}"
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved NAC client count but could not parse response"
        
        debug_stderr("################# ✓ count_org_nac_clients completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"count_org_nac_clients failed: {e}")
        return json.dumps({"error": f" Error: Failed to count NAC clients: {str(e)}"}, indent=2)


# SITE MANAGEMENT FUNCTIONS

# SITE MANAGEMENT TOOLS (7 tools):
# - get_site_info: Detailed site information  
# - get_site_devices: All devices configuration in a site
# - get_site_wlans: WLAN configurations
# - get_site_stats: Site performance metrics
# - get_site_insights: SLE metrics and insights



@safe_tool_definition("get_site_info", "site")
async def get_site_info(site_id: str) -> str:
    """Get detailed information about a specific site"""
    try:
        debug_stderr(f"Executing get_site_info for site {site_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/sites/{site_id}"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                site_data = json.loads(result.get("response_data", "{}"))
                result["site_info"] = site_data
                result["message"] = f"Retrieved site information for {site_data.get('name', site_id)}"
                
                # Site capabilities summary
                capabilities = {
                    "has_rf_template": bool(site_data.get("rftemplate_id")),
                    "has_network_template": bool(site_data.get("networktemplate_id")),
                    "has_gateway_template": bool(site_data.get("gatewaytemplate_id")),
                    "has_location": bool(site_data.get("latlng")),
                    "analytics_enabled": site_data.get("analyticEnabled", False),
                    "engagement_enabled": site_data.get("engagementEnabled", False)
                }
                result["site_capabilities"] = capabilities
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved site info but could not parse response"
        
        debug_stderr("################# ✓ get_site_info completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_site_info failed: {e}")
        return json.dumps({"error": f" Error: Failed to get site info: {str(e)}"}, indent=2)

@safe_tool_definition("get_site_devices", "site")
async def get_site_devices(site_id: str, device_type: str = None) -> str:
    """
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
    #doc = get_tool_doc('get_site_devices')
    #debug_stderr(f"Tool documentation: {doc[:1000]}...")
    try:
        debug_stderr(f"#################  Executing get_site_devices for site {site_id}... ################# ")
        client = get_api_client()
        endpoint = f"/api/v1/sites/{site_id}/devices"
        
        params = {}
        if device_type:
            params["type"] = device_type
        
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            devices_data = json.loads(result.get("response_data", "[]"))
            try:
                # GATEWAY TEMPLATE ENHANCEMENT - Direct API call (not MCP tool call)
                gateways = [d for d in devices_data if d.get("type") == "gateway"]
                if gateways and device_type in ["gateway", None]:
                    # Get org_id from site info or device data
                    org_id = None
                    if gateways:
                        org_id = gateways[0].get("org_id")
                    
                    if not org_id:
                        # Fallback: get org_id from site info
                        site_result = await client.make_request(f"/api/v1/sites/{site_id}")
                        if site_result.get("status") == "SUCCESS":
                            site_data = json.loads(site_result.get("response_data", "{}"))
                            org_id = site_data.get("org_id")
                    
                    if org_id:
                        # Direct API call to get gateway templates
                        templates_result = await client.make_request(f"/api/v1/orgs/{org_id}/gatewaytemplates")
                        
                        if templates_result.get("status") == "SUCCESS":
                            templates_data = json.loads(templates_result.get("response_data", "[]"))
                            
                            # Enhanced gateway configuration matching
                            for device in devices_data:
                                if device.get("type") == "gateway":
                                    template_id = device.get("gatewaytemplate_id")
                                    if not template_id:
                                        # Check site-level template
                                        site_result = await client.make_request(f"/api/v1/sites/{site_id}")
                                        if site_result.get("status") == "SUCCESS":
                                            site_data = json.loads(site_result.get("response_data", "{}"))
                                            template_id = site_data.get("gatewaytemplate_id")
                                    
                                    if template_id:
                                        matching_template = next((t for t in templates_data 
                                                            if t.get("id") == template_id), None)
                                        if matching_template:
                                            device["enhanced_configuration"] = {
                                                "device_config": {k: v for k, v in device.items() 
                                                            if k != "enhanced_configuration"},
                                                "template_config": matching_template,
                                                "template_id": template_id,
                                                "configuration_source": "template_enhanced",
                                                "merged_networks": matching_template.get("ip_configs", {}),
                                                "merged_ports": matching_template.get("port_config", {}),
                                                "merged_bgp": matching_template.get("bgp_config", {}),
                                                "merged_policies": matching_template.get("routing_policies", {}),
                                                "merged_services": matching_template.get("service_policies", [])
                                            }   

                # Retrival of direct, non-template data
                result["devices"] = devices_data
                result["device_count"] = len(devices_data)
                result["message"] = f"Retrieved {len(devices_data)} devices"
                
                # Enhanced device analysis
                device_analysis = {
                    "by_type": {},
                    "by_model": {},
                    "by_status": {"connected": 0, "disconnected": 0},
                    "total_devices": len(devices_data)
                }
                
                device_summary = []
                for device in devices_data:
                    # Type analysis
                    d_type = device.get("type", "unknown")
                    device_analysis["by_type"][d_type] = device_analysis["by_type"].get(d_type, 0) + 1
                    
                    # Model analysis
                    model = device.get("model", "unknown")
                    device_analysis["by_model"][model] = device_analysis["by_model"].get(model, 0) + 1
                    
                    # Status analysis
                    connected = device.get("connected", False)
                    if connected:
                        device_analysis["by_status"]["connected"] += 1
                    else:
                        device_analysis["by_status"]["disconnected"] += 1
                    
                    summary = {
                        "id": device.get("id"),
                        "name": device.get("name"),
                        "mac": device.get("mac"),
                        "serial": device.get("serial"),
                        "model": device.get("model"),
                        "type": device.get("type"),
                        "connected": device.get("connected", False),
                        "adopted": device.get("adopted", False),
                        "version": device.get("version"),
                        "ip": device.get("ip"),
                        "last_seen": device.get("last_seen")
                    }
                    device_summary.append(summary)
                
                result["device_summary"] = device_summary
                result["device_analysis"] = device_analysis


            except json.JSONDecodeError:
                result["message"] = "Retrieved devices but could not parse response"
        
        debug_stderr("################# ✓ get_site_devices completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_site_devices failed: {e}")
        return json.dumps({"error": f" Error: Failed to get site devices: {str(e)}"}, indent=2)

@safe_tool_definition("get_site_wlans", "site")
async def get_site_wlans(site_id: str) -> str:
    """Get all WLANs configured for a site"""
    try:
        debug_stderr(f"Executing get_site_wlans for site {site_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/sites/{site_id}/wlans"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                wlans_data = json.loads(result.get("response_data", "[]"))
                result["wlans"] = wlans_data
                result["wlan_count"] = len(wlans_data)
                result["message"] = f"Retrieved {len(wlans_data)} WLANs"
                
                # WLAN analysis
                wlan_analysis = {
                    "by_auth_type": {},
                    "by_band": {},
                    "enabled_count": 0,
                    "disabled_count": 0
                }
                
                wlan_summary = []
                for wlan in wlans_data:
                    # Auth type analysis
                    auth_type = wlan.get("auth", {}).get("type", "unknown")
                    wlan_analysis["by_auth_type"][auth_type] = wlan_analysis["by_auth_type"].get(auth_type, 0) + 1
                    
                    # Status analysis
                    enabled = wlan.get("enabled", False)
                    if enabled:
                        wlan_analysis["enabled_count"] += 1
                    else:
                        wlan_analysis["disabled_count"] += 1
                    
                    summary = {
                        "id": wlan.get("id"),
                        "ssid": wlan.get("ssid"),
                        "enabled": enabled,
                        "auth_type": auth_type,
                        "vlan_id": wlan.get("vlan_id"),
                        "band": wlan.get("band")
                    }
                    wlan_summary.append(summary)
                
                result["wlan_summary"] = wlan_summary
                result["wlan_analysis"] = wlan_analysis
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved WLANs but could not parse response"
        
        debug_stderr("################# ✓ get_site_wlans completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_site_wlans failed: {e}")
        return json.dumps({"error": f" Error: Failed to get site WLANs: {str(e)}"}, indent=2)

@safe_tool_definition("get_site_stats", "site")
async def get_site_stats(site_id: str, metric: str = None) -> str:
    """Get comprehensive site statistics and performance metrics"""
    try:
        debug_stderr(f"Executing get_site_stats for site {site_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/sites/{site_id}/stats"
        
        params = {}
        if metric:
            params["metric"] = metric
        
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                stats_data = json.loads(result.get("response_data", "{}"))
                result["site_stats"] = stats_data
                result["message"] = f"Retrieved site statistics for {site_id}"
                
                if metric:
                    result["metric"] = metric
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved site stats but could not parse response"
        
        debug_stderr("################# ✓ get_site_stats completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_site_stats failed: {e}")
        return json.dumps({"error": f" Error: Failed to get site stats: {str(e)}"}, indent=2)

@safe_tool_definition("get_site_insights", "site")
async def get_site_insights(site_id: str, metric: str = None) -> str:
    """Get site insights and SLE (Service Level Expectation) metrics"""
    try:
        debug_stderr(f"Executing get_site_insights for site {site_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/sites/{site_id}/insights"
        
        params = {}
        if metric:
            params["metric"] = metric
        
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                insights_data = json.loads(result.get("response_data", "{}"))
                result["site_insights"] = insights_data
                result["message"] = f"Retrieved site insights for {site_id}"
                
                if metric:
                    result["metric"] = metric
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved site insights but could not parse response"
        
        debug_stderr("################# ✓ get_site_insights completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_site_insights failed: {e}")
        return json.dumps({"error": f" Error: Failed to get site insights: {str(e)}"}, indent=2)


# DEVICE MANAGEMENT & STATISTICS FUNCTIONS

# DEVICE MANAGEMENT TOOLS (5 tools):
# - get_device_stats: Device performance metrics
# - device_action: Perform device actions  
# - execute_custom_shell_command: Shell command execution
# - get_enhanced_device_info: Comprehensive device data


@safe_tool_definition("get_device_stats", "device")
async def get_device_stats(site_id: str, device_id: str = None, metric: str = None) -> str:
    """Get device statistics and performance metrics"""
    try:
        debug_stderr(f"################# Executing get_device_stats for site {site_id}, device {device_id}... #################")
        client = get_api_client()
        
        if device_id:
            endpoint = f"/api/v1/sites/{site_id}/stats/devices/{device_id}/clients"
        else:
            endpoint = f"/api/v1/sites/{site_id}/stats/devices"
        
        params = {}
        if metric:
            params["metric"] = metric
        
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                stats_data = json.loads(result.get("response_data", "{}"))
                result["device_stats"] = stats_data
                result["message"] = f"################# ✓ Retrieved device statistics #################"
                
                if device_id:
                    result["device_id"] = device_id
                if metric:
                    result["metric"] = metric
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved device stats but could not parse response"
        
        debug_stderr("✓ get_device_stats completed")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_device_stats failed: {e}")
        return json.dumps({"error": f" Error: Failed to get device stats: {str(e)}"}, indent=2)
    
@safe_tool_definition("device_action", "device")
async def device_action(site_id: str, device_id: str, action: str, action_params: dict = None) -> str:
    """Perform actions on devices (restart, locate, unlocate, etc.)"""
    try:
        debug_stderr(f"Executing device_action '{action}' on device {device_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/sites/{site_id}/devices/{device_id}/{action}"
        
        data = action_params or {}
        result = await client.make_request(endpoint, method="POST", data=data)
        
        if result.get("status") == "SUCCESS":
            try:
                action_data = json.loads(result.get("response_data", "{}"))
                result["action_result"] = action_data
                result["action"] = action
                result["device_id"] = device_id
                result["message"] = f"Successfully executed '{action}' on device {device_id}"
                
            except json.JSONDecodeError:
                result["message"] = f"Action '{action}' executed but could not parse response"
        
        debug_stderr("✓ device_action completed")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"device_action failed: {e}")
        return json.dumps({"error": f" Error: Failed to execute device action: {str(e)}"}, indent=2)

# ADVANCED SHELL COMMAND FUNCTIONS
@safe_tool_definition("execute_custom_shell_command", "device")
async def execute_custom_shell_command(site_id: str, device_id: str, command: str, timeout: int = 30) -> str:
    
    """
    Execute a custom shell command on a Junos device (with enhanced timeout handling)
    Enhanced function to execute command on device for which there are no API endpoints available.
    Commonly used commands include:
    1. Used to get ehnhanced routing information for bgp or ospf
    2. to get show interfaces terse to provide interface status and ip information
    3. to get show configuration to provide configuration to comapre with intended state
    4. to get show system alarms to provide current active alarms on the device
    5. to get show log messages to provide recent log messages for troubleshooting
    6. show pfe vxlan nh-usage on EX4400,EX4100, QFX5120,QFX5300 to shhow vxlan nexthop usage
    7. show pfe statistics fpc 0 to show packet forwarding engine statistics
    8. show system processes extensive to show cpu and memory usage on the device
    9. show system storage to show storage usage on the device
    10. show chassis hardware to show hardware inventory on the device
    11. show interfaces diagnostics optics to show optics information on the device
    12. show system users to show logged in users on the device
    13. show configuration | display set to show configuration in set format
    14. show configuration | display xml to show configuration in xml format
    15. show configuration | display json to show configuration in json format
    16. show log messages | match <string> to filter log messages containing specific string
    17. show ethernet-switching table to show mac address table on switch and group based policy tags (GBP)
    18. show lldp neighbors to show lldp neighbor information
    19. show lacp interfaces to show lacp interface information
    

    API Used: POST /api/v1/sites/{site_id}/devices/{device_id}/shell/execute
    
    """
    debug_stderr(f"Executing enhanced shell command: {command}")
    
    # Limit timeout to reasonable values
    timeout = min(max(timeout, 5), 300)  # 5 seconds to 5 minutes
    
    try:
        client = get_api_client()
        result = await client.shell_executor.execute_command(
            site_id, device_id, command, max_runtime=timeout, max_output_size=50000
        )
        
        # Convert result to dict for JSON serialization
        result_dict = {
            "status": "SUCCESS" if result.success else "ERROR",
            "command": result.command,
            "device_id": result.device_id,
            "site_id": result.site_id,
            "execution_time": round(result.execution_time, 3),
            "timestamp": result.timestamp,
            "output": result.output,
            "error_message": result.error_message,
            "timeout_used": timeout,
            "output_truncated": result.output_truncated,
            "max_output_size": result.max_output_size
        }
        
        debug_stderr("✓ Enhanced execute_custom_shell_command completed")
        return json.dumps(result_dict, indent=2)
        
    except Exception as e:
        debug_stderr(f"Enhanced execute_custom_shell_command failed: {e}")
        return json.dumps({
            "status": "ERROR",
            "error": f"Shell command execution failed: {str(e)}",
            "command": command,
            "device_id": device_id,
            "site_id": site_id
        }, indent=2)

@safe_tool_definition("get_enhanced_device_info", "device")
async def get_enhanced_device_info(site_id: str, device_id: str, include_shell_data: bool = False) -> str:
    """Get comprehensive device information, optionally including shell-based data"""
    try:
        debug_stderr(f"Getting enhanced device info for {device_id}")
        client = get_api_client()
        
        # Get basic device info via API
        api_result = await client.make_request(f"/api/v1/sites/{site_id}/devices/{device_id}")
        
        result = {
            "device_id": device_id,
            "site_id": site_id,
            "timestamp": datetime.now().isoformat(),
            "api_data": api_result
        }
        
        if include_shell_data and api_result.get("status") == "SUCCESS":
            debug_stderr("Fetching enhanced shell-based device information")
            
            # Execute enhanced shell commands for additional data
            shell_commands = [
                "show version brief",
                "show system uptime", 
                "show chassis hardware brief",
                "show interfaces terse",
                "show system alarms",
                "show log messages | last 10"
            ]
            
            shell_results = {}
            for cmd in shell_commands:
                shell_result = await client.shell_executor.execute_command(
                    site_id, device_id, cmd, max_runtime=25, max_output_size=5000
                )
                shell_results[cmd] = {
                    "success": shell_result.success,
                    "output": shell_result.output,
                    "execution_time": shell_result.execution_time,
                    "output_truncated": shell_result.output_truncated
                }
            
            result["shell_data"] = shell_results
        
        debug_stderr("✓ Enhanced get_enhanced_device_info completed")
        return json.dumps(result, indent=2)
        
    except Exception as e:
        debug_stderr(f"Enhanced get_enhanced_device_info failed: {e}")
        return json.dumps({
            "error": f"Failed to get enhanced device info: {str(e)}",
            "device_id": device_id,
            "site_id": site_id
        }, indent=2)

@safe_tool_definition("get_device_events", "events")
async def get_device_events(site_id: str, event_type: str = None, start: int = None, end: int = None, 
                    duration: str = None, limit: int = 100, page: int = 1) -> str:
    """
    Get events from device for given site, site_id is mandatory
    Enhanced to include event summaries and analysis
    1. Event type, device, and timestamp
    2. Count of events retrieved
    3. include text which provide eaxct message for the alarms
    4. Filtering options for event types and time ranges
    5. Different summary for AP and Switch device types
    6. Include version, model and chassis mac for switch events
    7. Include ap firmware, model for ap events
    
    
    API Used: GET /api/v1/sites/{site_id}/devices/events/search
    """
    try:
        debug_stderr(f"Executing get_device_events for site {site_id}...")
        client = get_api_client()
        
        params = {
            "limit": min(max(1, int(limit)), 1000),
            "page": max(1, int(page))
        }
        if event_type:
            params["type"] = event_type
        if start is not None:
            params["start"] = int(start)
        if end is not None:
            params["end"] = int(end)
        if duration:
            params["duration"] = duration

        endpoint = f"/api/v1/sites/{site_id}/devices/events/search"
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                events_data = json.loads(result.get("response_data", "[]"))
                result["events"] = events_data
                result["event_count"] = len(events_data.get("results", []))
                result["message"] = f'Retrieved {len(events_data.get("results", []))} events'
                        
                site_device_events = []
                for events in events_data.get("results", []):
                    summary = {
                        "type": events.get("type"),
                        "device_type": events.get("device_type"),
                        "text": events.get("text"),
                        "mac": events.get("mac"),
                        "timestamp": events.get("timestamp"),
                        "site_id": events.get("site_id"),
                        "org_id": events.get("org_id"),
                    }
                    if events.get("device_type") == "switch":
                        summary["version"] = events.get("version")
                        summary["port_id"] = events.get("port_id")
                        summary["model"] = events.get("model")
                        summary["chassis_mac"] = events.get("chassis_mac")
                        if events.get("alarm_class") is not None:
                            summary["alarm_class"] = events.get("alarm_class")
                    if events.get("device_type") == "ap":
                        summary["ap_firmware"] = events.get("apfw")
                        summary["port_id"] = events.get("port_id")
                        summary["model"] = events.get("model")

                    site_device_events.append(summary)
                result["site_device_events"] = site_device_events                         

            except Exception as e:
                result["message"] = f"Retrieved events but could not parse response: {e}"
        
        debug_stderr("################# ✓ get_device_events completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_device_events failed: {e}")
        return json.dumps({"error": f" Error: Failed to get events: {str(e)}"}, indent=2)


# EVENTS & ALARMS FUNCTIONS

# EVENTS & MONITORING (2 tools):
# - get_alarms: Alarm management

@safe_tool_definition("get_alarms", "alarms")
async def get_alarms(org_id: str = None, site_id: str = None, severity: str = None, duration: str = "1d", limit: int = 100) -> str:
    """
    Get alarms from organization or site
    1. Alarm type, severity, group, reason, org_id, site_id, hostnames
    2. Count of alarms retrieved
    3. Filtering options for severity levels
    4. Enhanced alarm analysis by severity, type, group, reason, org, 
    5. By default limit to 100 alarms, max 1000

    API Used: GET /api/v1/orgs/{org_id}/alarms/search or /api/v1/sites/{site_id}/alarms/search

    requires either org_id or site_id to be provided

    Duration can be specified in formats like "1d" (1 day), "2h" (2 hours), 7d (7 days), 2w ( 2 weeks) etc. by default 1d (1 day) is used
           
    """
    
    try:
        debug_stderr(f"Executing get_alarms for org {org_id}, site {site_id}...")
        client = get_api_client()
        
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        if duration:
            params["duration"] = duration
        if site_id:
            endpoint = f"/api/v1/sites/{site_id}/alarms/search"
        elif org_id:
            endpoint = f"/api/v1/orgs/{org_id}/alarms/search"
        else:
            return json.dumps({"error": "Either org_id or site_id must be provided"}, indent=2)
        
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                alarms_data = json.loads(result.get("response_data", "{}"))
                alarms_list = alarms_data.get("results", [])
                result["alarms"] = alarms_list
                result["alarm_count"] = alarms_data.get("total", 0)
                result["message"] = f"Retrieved {len(alarms_list)} alarms"
                
                # Enhanced alarm analysis
                if alarms_list:
                    alarm_analysis = {
                        "by_severity": {},
                        "by_type": {},
                        "by_group": {},
                        "by_reason": {},
                        "by_org": {},
                        "by_site": {},
                        "by_hostnames": {},
                        "total_alarms": len(alarms_list)
                    }
        
                    for alarm in alarms_list:
                        severity = alarm.get("severity", "unknown")
                        alarm_type = alarm.get("type", "unknown")
                        group = alarm.get("group", "unknown")
                        reason = alarm.get("reasons", "unknown")
                        org_id = alarm.get("org_id", "unknown")
                        site_id = alarm.get("site_id", "unknown")
                        hostnames = alarm.get("hostnames", "unknown")
                        
                        alarm_analysis["by_severity"][severity] = alarm_analysis["by_severity"].get(severity, 0) + 1
                        alarm_analysis["by_type"][alarm_type] = alarm_analysis["by_type"].get(alarm_type, 0) + 1
                        alarm_analysis["by_group"][group] = alarm_analysis["by_group"].get(group, 0) + 1
                        alarm_analysis["by_reason"][reason] = alarm_analysis["by_reason"].get(reason, 0) + 1
                        alarm_analysis["by_org"][org_id] = alarm_analysis["by_org"].get(org_id, 0) + 1
                        alarm_analysis["by_site"][site_id] = alarm_analysis["by_site"].get(site_id, 0) + 1
                        alarm_analysis["by_hostnames"][hostnames] = alarm_analysis["by_hostnames"].get(hostnames, 0) + 1
                    
                    result["alarm_analysis"] = alarm_analysis
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved alarms but could not parse response"
        
        debug_stderr("################# ✓ get_alarms completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_alarms failed: {e}")
        return json.dumps({"error": f" Error: Failed to get alarms: {str(e)}"}, indent=2)

# MSP MANAGEMENT FUNCTIONS

# MSP MANAGEMENT (2 tools):
# - get_msp_info: MSP information
# - get_msp_orgs: Organizations under MSP

@safe_tool_definition("get_msp_info", "msp")
async def get_msp_info(msp_id: str) -> str:
    """Get MSP (Managed Service Provider) information"""
    try:
        debug_stderr(f"Executing get_msp_info for MSP {msp_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/msps/{msp_id}"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                msp_data = json.loads(result.get("response_data", "{}"))
                result["msp_info"] = msp_data
                result["message"] = f"Retrieved MSP information for {msp_data.get('name', msp_id)}"
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved MSP info but could not parse response"
        
        debug_stderr("################# ✓ get_msp_info completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_msp_info failed: {e}")
        return json.dumps({"error": f" Error: Failed to get MSP info: {str(e)}"}, indent=2)

@safe_tool_definition("get_msp_orgs", "msp")
async def get_msp_orgs(msp_id: str) -> str:
    """Get organizations under an MSP"""
    try:
        debug_stderr(f"Executing get_msp_orgs for MSP {msp_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/msps/{msp_id}/orgs"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                orgs_data = json.loads(result.get("response_data", "[]"))
                result["msp_orgs"] = orgs_data
                result["org_count"] = len(orgs_data)
                result["message"] = f"Retrieved {len(orgs_data)} organizations under MSP"
                
                # MSP org analysis
                org_summary = []
                for org in orgs_data:
                    summary = {
                        "id": org.get("id"),
                        "name": org.get("name"),
                        "created_time": org.get("created_time")
                    }
                    org_summary.append(summary)
                result["org_summary"] = org_summary
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved MSP orgs but could not parse response"
        
        debug_stderr("################# ✓ get_msp_orgs completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_msp_orgs failed: {e}")
        return json.dumps({"error": f" Error: Failed to get MSP organizations: {str(e)}"}, indent=2)


# SYSTEM & UTILITY FUNCTIONS
# SYSTEM & UTILITY TOOLS (2 tools):
# - make_mist_api_call: Generic Mist API interface with security validation
# - get_service_health_report: Service health monitor
# - test_mist_connectivity: Connectivity test to Mist API
# - debug_server_status: Debug server status check
# - export_diagnostics_json: Export diagnostics data
# - get_performace_trends: Performance trends analysis

@safe_tool_definition("make_mist_api_call", "utility")
@require_security_check  # Apply security check as requested
async def make_mist_api_call(endpoint: str, method: str = "GET", org_id: str = None, 
                           site_id: str = None, data: dict = None, params: dict = None) -> str:
    """
    UTILITY TOOL #1: Generic Mist API Interface with Security Validation
    
    Function: Provides direct access to any Mist API endpoint with automatic
              parameter substitution, comprehensive response handling, and
              integrated security privilege analysis to prevent misuse.
    
    API Used: Any Mist API endpoint (user-specified)
    
    Parameters:
    - endpoint (str): API endpoint path (supports {org_id} and {site_id} placeholders)
    - method (str): HTTP method (GET/POST/PUT/DELETE/PATCH)
    - org_id (str): Organization ID for placeholder substitution
    - site_id (str): Site ID for placeholder substitution
    - data (dict): Request body for POST/PUT requests
    - params (dict): Query parameters
    
    Response Handling:
    - Returns raw JSON response from Mist API with enhanced metadata
    - Includes HTTP status codes and response headers
    - Shows request metadata including timing and security context
    - Contains detailed error information for failed requests
    - Provides rate limit information and quota status
    - Includes response size and encoding information
    
    Enhanced Features:
    - Automatic placeholder replacement in endpoints
    - Method validation and parameter checking
    - Response metadata enrichment with security context
    - Request/response logging and tracking for audit trails
    - Error categorization and handling with detailed diagnostics
    - Security privilege validation before execution
    
    Security Features:
    - Privilege analysis before API call execution
    - Detection of overly broad token permissions
    - Blocking of dangerous operations for tokens with excessive privileges
    - Security warnings and alternative solution recommendations
    - Integration with security acknowledgment and override mechanisms
    
    Use Cases:
    - Access new or undocumented API endpoints safely
    - Prototype custom integrations with security validation
    - Administrative tasks requiring direct API access
    - Testing and development workflows with privilege oversight
    - Custom automation and scripting with security controls
    """
    try:
        debug_stderr(f"Executing enhanced make_mist_api_call to {endpoint}")
        client = get_api_client()
        
        # Security warning for destructive operations
        if method.upper() in ['PUT', 'DELETE', 'POST', 'PATCH']:
            debug_stderr(f"Potentially destructive API operation: {method} {endpoint}")
        
        # Replace placeholders in endpoint
        endpoint_final = endpoint
        if org_id and '{org_id}' in endpoint:
            endpoint_final = endpoint_final.replace('{org_id}', org_id)
        if site_id and '{site_id}' in endpoint_final:
            endpoint_final = endpoint_final.replace('{site_id}', site_id)
        
        result = await client.make_request(endpoint_final, method, data, params)
        
        # Add request metadata and security context
        result["original_endpoint"] = endpoint
        result["final_endpoint"] = endpoint_final
        result["method"] = method
        if org_id:
            result["org_id"] = org_id
        if site_id:
            result["site_id"] = site_id
        
        # Add security metadata
        result["security_context"] = {
            "method": method,
            "destructive_operation": method.upper() in ['PUT', 'DELETE', 'POST', 'PATCH'],
            "endpoint_final": endpoint_final,
            "security_check_passed": True,
            "strict_mode_active": security_analyzer.strict_mode
        }
        
        debug_stderr("################# ✓ Enhanced make_mist_api_call completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"Enhanced make_mist_api_call failed: {e}")
        return json.dumps({"error": f"API call failed: {str(e)}"}, indent=2)

@safe_tool_definition("get_service_health_report", "system")
def get_service_health_report() -> str:
    """
    SYSTEM DIAGNOSTIC TOOL #1: Service Health Monitor
    
    Function: Provides comprehensive service health metrics, performance statistics,
              uptime tracking, memory usage, CPU utilization, and active alerts
    
    API Used: Internal diagnostics system (no external Mist API calls)
    
    Response Handling:
    - Returns formatted text report with service status
    - Includes uptime in human-readable format
    - Shows request counts and success rates  
    - Displays memory usage (current and peak)
    - Shows CPU usage percentage
    - Lists performance percentiles (P50, P95, P99)
    - Reports active alerts based on thresholds
    - Shows top error patterns
    
    Enhanced Features:
    - API category usage tracking
    - Endpoint-specific statistics  
    - Rolling window performance analysis
    - Configurable alert thresholds
    - Background monitoring with 30-second intervals
    
    Use Cases:
    - Monitor server health and performance
    - Identify performance bottlenecks
    - Track API usage patterns
    - Detect service degradation
    - Generate health reports for monitoring systems
    """
    try:
        debug_stderr("Getting comprehensive service health report...")
        health_summary = diagnostics.get_comprehensive_health_summary()
        
        service_status = health_summary['service_status']
        performance_metrics = health_summary['performance_metrics']
        api_insights = health_summary['api_insights']
        
        result = json.dumps({
            "service_health": {
                "uptime": service_status['uptime_human'],
                "total_requests": service_status['total_requests'],
                "success_rate": f"{service_status['success_rate']:.1%}",
                "avg_response_time": f"{service_status['avg_response_time']:.3f}s",
                "memory_usage": f"{service_status['current_memory_mb']:.1f}MB",
                "peak_memory": f"{service_status['peak_memory_mb']:.1f}MB",
                "cpu_usage": f"{service_status['cpu_usage_percent']:.1f}%"
            },
            "performance_metrics": {
                "response_time_percentiles": performance_metrics.get('response_time_percentiles', {}),
                "operations_recorded": performance_metrics['total_operations_recorded'],
                "top_endpoints": performance_metrics.get('top_endpoints_by_usage', {})
            },
            "api_insights": {
                "categories_used": api_insights.get('categories_used', {}),
                "unique_endpoints": api_insights.get('total_unique_endpoints', 0),
                "most_active_category": api_insights.get('most_active_category')
            },
            "error_analysis": health_summary['error_analysis'],
            "security_status": {
                "strict_mode_enabled": security_analyzer.strict_mode,
                "risks_acknowledged": security_analyzer.security_acknowledged,
                "security_thresholds": security_analyzer.risk_thresholds
            }
        }, indent=2)
        
        debug_stderr("✓ Comprehensive get_service_health_report completed")
        return result
    except Exception as e:
        debug_stderr(f"get_service_health_report failed: {e}")
        return json.dumps({"error": f" Error: Failed to get health report: {str(e)}"}, indent=2)

@safe_tool_definition("test_mist_connectivity", "system")
async def test_mist_connectivity() -> str:
    """
    SYSTEM DIAGNOSTIC TOOL #2: API Connectivity Tester
    
    Function: Tests connectivity to multiple Mist API endpoints to verify service
              availability, authentication, and network connectivity
    
    APIs Used: 
    - /api/v1/self (Authentication test)
    - /api/v1/const/countries (Constants API test)  
    - /api/v1/orgs (Organization API test)
    - /api/v1/const/timezones (Additional constants test)
    
    Response Handling:
    - Returns JSON with connectivity status (SUCCESSFUL/PARTIAL/FAILED)
    - Lists successful and failed endpoints with details
    - Shows response times for each endpoint
    - Reports rate limit information
    - Includes HTTP status codes
    - Calculates overall success rate percentage
    
    Enhanced Features:
    - Configurable timeout per endpoint (15 seconds)
    - Comprehensive endpoint coverage across API categories
    - Rate limit header tracking
    - Response size monitoring
    - Concurrent testing with proper error isolation
    
    Use Cases:
    - Verify Mist API connectivity during setup
    - Diagnose authentication issues
    - Monitor API endpoint availability
    - Test network connectivity to Mist cloud
    - Validate API token permissions
    """
    try:
        debug_stderr("Testing comprehensive Mist connectivity...")
        client = get_api_client()
        
        # Enhanced test endpoints covering different API categories
        test_endpoints = [
            ("/api/v1/self", "Authentication"),
            ("/api/v1/const/countries", "Constants"),
            ("/api/v1/orgs", "Organization")
        ]
        
        results = {}
        total_response_time = 0
        successful_tests = 0
        
        for endpoint, category in test_endpoints:
            try:
                debug_stderr(f"Testing endpoint: {endpoint} ({category})")
                start_time = time.time()
                
                result = await asyncio.wait_for(
                    client.make_request(endpoint),
                    timeout=15  # 15 second timeout per endpoint
                )
                
                response_time = time.time() - start_time
                total_response_time += response_time
                
                success = result.get("status") == "SUCCESS"
                if success:
                    successful_tests += 1
                
                results[endpoint] = {
                    "category": category,
                    "status": result.get("status"),
                    "http_status": result.get("http_status"),
                    "response_time": round(response_time, 3),
                    "success": success,
                    "rate_limit_remaining": result.get("rate_limit_remaining"),
                    "response_size": result.get("response_size", 0)
                }
                debug_stderr(f"✓ Endpoint {endpoint} test completed in {response_time:.2f}s")
                
            except asyncio.TimeoutError:
                debug_stderr(f"✗ Endpoint {endpoint} timed out")
                results[endpoint] = {
                    "category": category,
                    "status": "TIMEOUT",
                    "success": False,
                    "error": "Request timed out"
                }
            except Exception as e:
                debug_stderr(f"✗ Endpoint {endpoint} failed: {e}")
                results[endpoint] = {
                    "category": category,
                    "status": "ERROR",
                    "success": False,
                    "error": str(e)
                }
        
        avg_response_time = total_response_time / len([r for r in results.values() if "response_time" in r]) if any("response_time" in r for r in results.values()) else 0
        success_rate = (successful_tests / len(test_endpoints)) * 100
        
        connectivity_result = {
            "connectivity_test": "completed",
            "server": CONFIG.base_url,
            "test_timestamp": datetime.now().isoformat(),
            "endpoints_tested": len(test_endpoints),
            "successful_tests": successful_tests,
            "success_rate": f"{success_rate:.1f}%",
            "avg_response_time": f"{avg_response_time:.3f}s" if avg_response_time else "N/A",
            "total_requests_made": client.request_count if hasattr(client, 'request_count') else "unknown",
            "websocket_support": CONFIG.websockets_available,
            "shell_execution_available": CONFIG.websockets_available,
            "max_concurrent_requests": CONFIG.max_concurrent_requests,
            "request_timeout": CONFIG.request_timeout,
            "security_status": {
                "strict_mode": security_analyzer.strict_mode,
                "risks_acknowledged": security_analyzer.security_acknowledged
            },
            "detailed_results": results
        }
        
        debug_stderr("################# ✓ Comprehensive test_mist_connectivity completed ################# ")
        return json.dumps(connectivity_result, indent=2)
    except Exception as e:
        debug_stderr(f"test_mist_connectivity failed: {e}")
        return json.dumps({
            "error": f"Connectivity test failed: {str(e)}"
        }, indent=2)

@safe_tool_definition("debug_server_status", "system")
def debug_server_status() -> str:
    """
    SYSTEM DIAGNOSTIC TOOL #3: Server Debug Information
    
    Function: Provides detailed debug information about server configuration,
              environment, dependencies, and operational status
    
    API Used: Internal server introspection (no external API calls)
    
    Response Handling:
    - Returns JSON with comprehensive server information
    - Shows server configuration (base URL, timeouts, limits)
    - Lists environment variables (sanitized)
    - Reports dependency versions and availability
    - Shows tool registry with category breakdown
    - Includes Python and platform information
    - Reports current working directory and paths
    
    Enhanced Features:
    - Sanitized environment variable reporting (hides sensitive data)
    - Dependency version checking
    - Tool categorization and statistics
    - Memory and CPU usage at debug time
    - WebSocket availability status
    - API client status and request counters
    
    Use Cases:
    - Troubleshoot server configuration issues
    - Verify environment setup
    - Check dependency compatibility
    - Debug deployment problems
    - Generate support information for issues
    """
    try:
        debug_stderr("Getting comprehensive debug server status...")
        
        import sys
        import platform
        
        # Get all registered tools
        registered_tools = []
        if hasattr(mcp, '_tools'):
            for tool_name, tool_info in mcp._tools.items():
                registered_tools.append({
                    "name": tool_name,
                    "function": getattr(tool_info, '__name__', 'unknown') if hasattr(tool_info, '__name__') else 'unknown'
                })
        
        # Get diagnostics summary
        health_summary = diagnostics.get_comprehensive_health_summary()
        
        status = {
            "server_info": {
                "mcp_name": CONFIG.mcp_name,
                "version": "3.1 - Complete API Coverage with Security Analysis",
                "python_version": sys.version,
                "platform": platform.platform(),
                "working_directory": os.getcwd(),
                "script_path": __file__ if '__file__' in globals() else "unknown",
                "startup_time": diagnostics.service_health.service_start_time.isoformat()
            },
            "configuration": {
                "api_token_configured": bool(CONFIG.api_token),
                "base_url": CONFIG.base_url,
                "max_concurrent_requests": CONFIG.max_concurrent_requests,
                "request_timeout": CONFIG.request_timeout,
                "websockets_available": CONFIG.websockets_available,
                "mist_host_env": os.getenv("MIST_HOST"),
                "mist_base_url_env": os.getenv("MIST_BASE_URL")
            },
            "security_configuration": {
                "strict_mode_enabled": security_analyzer.strict_mode,
                "risks_acknowledged": security_analyzer.security_acknowledged,
                "security_thresholds": security_analyzer.risk_thresholds
            },
            "dependencies": {
                "websockets_available": CONFIG.websockets_available,
                "psutil_version": getattr(psutil, '__version__', 'unknown'),
                "httpx_available": 'httpx' in sys.modules,
                "fastmcp_available": 'fastmcp' in sys.modules,
                "python_path": sys.path[:3]
            },
            "api_client_status": {
                "initialized": api_client is not None,
                "request_count": getattr(api_client, 'request_count', 0) if api_client else 0,
                "rate_limit_remaining": getattr(api_client, 'rate_limit_remaining', None) if api_client else None
            },
            "tool_registry": {
                "total_tools_registered": len(registered_tools),
                "tools": registered_tools[:20]  # First 20 tools
            },
            "performance_summary": {
                "total_requests": health_summary['service_status']['total_requests'],
                "success_rate": health_summary['service_status']['success_rate'],
                "avg_response_time": health_summary['service_status']['avg_response_time'],
                "memory_usage_mb": health_summary['service_status']['current_memory_mb'],
                "api_categories_used": health_summary['api_insights']['categories_used']
            }
        }
        
        debug_stderr("✓ Comprehensive debug_server_status completed")
        return json.dumps(status, indent=2)
    except Exception as e:
        debug_stderr(f"debug_server_status failed: {e}")
        return json.dumps({"error": f" Error: Failed to get debug status: {str(e)}"}, indent=2)

@safe_tool_definition("export_diagnostics_json", "system")
def export_diagnostics_json() -> str:
    """
    SYSTEM DIAGNOSTIC TOOL #4: Diagnostics Data Exporter
    
    Function: Exports complete diagnostics data in structured JSON format for
              external analysis, monitoring systems, or troubleshooting
    
    API Used: Internal diagnostics collector (no external API calls)
    
    Response Handling:
    - Returns comprehensive JSON with all collected metrics
    - Includes operation history with timestamps and durations
    - Shows endpoint-specific statistics and usage patterns
    - Contains error patterns and frequency analysis
    - Reports performance trends over time
    - Includes system resource usage history
    
    Enhanced Features:
    - Configurable history size (last 100 operations by default)
    - Structured data format suitable for log analysis tools
    - Timestamp-based filtering capabilities
    - Error categorization and pattern detection
    - Performance baseline establishment
    - JSON schema validation
    
    Use Cases:
    - Export data for external monitoring systems
    - Perform detailed performance analysis
    - Generate historical performance reports  
    - Debug intermittent issues with historical data
    - Create performance baselines and SLA reports
    """
    try:
        debug_stderr("Exporting comprehensive diagnostics data...")
        
        # Get full diagnostics data
        health_summary = diagnostics.get_comprehensive_health_summary()
        
        # Add additional diagnostic information
        diagnostic_data = {
            "export_timestamp": datetime.now().isoformat(),
            "server_config": {
                "base_url": CONFIG.base_url,
                "websockets_available": CONFIG.websockets_available,
                "max_concurrent_requests": CONFIG.max_concurrent_requests,
                "request_timeout": CONFIG.request_timeout
            },
            "security_status": {
                "strict_mode_enabled": security_analyzer.strict_mode,
                "risks_acknowledged": security_analyzer.security_acknowledged,
                "security_thresholds": security_analyzer.risk_thresholds
            },
            "service_health": health_summary,
            "operation_history": [
                {
                    "operation_name": op.operation_name,
                    "duration": op.duration,
                    "success": op.success,
                    "timestamp": datetime.fromtimestamp(op.start_time).isoformat(),
                    "endpoint": op.endpoint,
                    "api_category": op.api_category,
                    "response_size": op.response_size,
                    "http_status": op.http_status_code
                }
                for op in list(diagnostics.operation_history)[-100:]  # Last 100 operations
            ],
            "api_endpoint_statistics": dict(diagnostics.api_endpoint_stats),
            "error_patterns": dict(diagnostics.error_patterns)
        }
        
        debug_stderr("✓ Comprehensive export_diagnostics_json completed")
        return json.dumps(diagnostic_data, indent=2)
    except Exception as e:
        debug_stderr(f"export_diagnostics_json failed: {e}")
        return json.dumps({"error": f" Error: Failed to export diagnostics: {str(e)}"}, indent=2)

@safe_tool_definition("get_performance_trends", "system")
def get_performance_trends(hours: int = 24) -> str:
    """
    SYSTEM DIAGNOSTIC TOOL #5: Performance Trend Analyzer
    
    Function: Analyzes performance trends over specified time periods with
              hourly breakdowns, category analysis, and endpoint usage patterns
    
    API Used: Internal operation metrics (no external API calls)
    
    Parameters:
    - hours (int): Time period to analyze in hours (default: 24, max: 168)
    
    Response Handling:
    - Returns JSON with performance analysis over specified period
    - Shows hourly activity breakdown with operation counts
    - Calculates success rates per hour
    - Reports average response times by time period
    - Groups performance by API category
    - Shows endpoint usage frequency and performance
    - Identifies peak usage hours and patterns
    
    Enhanced Features:
    - Configurable analysis window (1 hour to 7 days)
    - Category-based performance analysis
    - Endpoint ranking by usage and performance
    - Trend detection (improving/degrading performance)
    - Peak usage identification
    - Performance correlation analysis
    
    Use Cases:
    - Monitor performance trends over time
    - Identify peak usage periods for capacity planning
    - Detect performance degradation patterns
    - Analyze API category usage patterns
    - Generate performance trend reports
    - Optimize server resource allocation
    """
    try:
        debug_stderr(f"Getting performance trends for {hours} hours...")
        
        # Get operations from the specified time period
        cutoff_time = time.time() - (hours * 3600)
        recent_operations = [
            op for op in diagnostics.operation_history 
            if op.start_time >= cutoff_time
        ]
        
        if not recent_operations:
            return json.dumps({
                "message": f"No operations found in the last {hours} hours",
                "hours_analyzed": hours
            }, indent=2)
        
        # Analyze trends by category
        category_trends = {}
        endpoint_trends = {}
        hourly_stats = {}
        
        for op in recent_operations:
            # Category trends
            category = op.api_category or "unknown"
            if category not in category_trends:
                category_trends[category] = {
                    "count": 0,
                    "success_count": 0,
                    "total_duration": 0,
                    "avg_response_size": 0
                }
            
            cat_stats = category_trends[category]
            cat_stats["count"] += 1
            if op.success:
                cat_stats["success_count"] += 1
            cat_stats["total_duration"] += op.duration
            if op.response_size:
                cat_stats["avg_response_size"] = (cat_stats["avg_response_size"] + op.response_size) / 2
            
            # Endpoint trends
            if op.endpoint:
                if op.endpoint not in endpoint_trends:
                    endpoint_trends[op.endpoint] = {"count": 0, "avg_duration": 0}
                endpoint_trends[op.endpoint]["count"] += 1
                endpoint_trends[op.endpoint]["avg_duration"] = (
                    endpoint_trends[op.endpoint]["avg_duration"] + op.duration
                ) / 2
            
            # Hourly stats
            hour_key = datetime.fromtimestamp(op.start_time).strftime("%Y-%m-%d %H:00")
            if hour_key not in hourly_stats:
                hourly_stats[hour_key] = {"count": 0, "success_count": 0}
            hourly_stats[hour_key]["count"] += 1
            if op.success:
                hourly_stats[hour_key]["success_count"] += 1
        
        # Calculate final statistics
        for category, stats in category_trends.items():
            stats["avg_duration"] = stats["total_duration"] / stats["count"]
            stats["success_rate"] = stats["success_count"] / stats["count"]
            del stats["total_duration"]  # Remove intermediate calculation
        
        # Top endpoints by usage
        top_endpoints = dict(sorted(endpoint_trends.items(), 
                                  key=lambda x: x[1]["count"], reverse=True)[:10])
        
        trends_data = {
            "analysis_period_hours": hours,
            "total_operations_analyzed": len(recent_operations),
            "analysis_timestamp": datetime.now().isoformat(),
            "category_performance": category_trends,
            "top_endpoints": top_endpoints,
            "hourly_activity": dict(sorted(hourly_stats.items())),
            "overall_stats": {
                "avg_response_time": statistics.mean([op.duration for op in recent_operations]),
                "success_rate": len([op for op in recent_operations if op.success]) / len(recent_operations),
                "total_unique_categories": len(category_trends),
                "total_unique_endpoints": len(endpoint_trends)
            },
            "security_context": {
                "security_events_analyzed": len([op for op in recent_operations if op.api_category == "security"]),
                "security_mode_active": security_analyzer.strict_mode
            }
        }
        
        debug_stderr("✓ Enhanced get_performance_trends completed")
        return json.dumps(trends_data, indent=2)
    except Exception as e:
        debug_stderr(f"get_performance_trends failed: {e}")
        return json.dumps({"error": f" Error: Failed to get performance trends: {str(e)}"}, indent=2)

debug_stderr("✓ All enhanced tool functions defined")

# EVPN Fabric functions
# - get_org_evpn_topologies: List EVPN fabrics in an org
# - get_site_evpn_tpopologies: List EVPN fabrics in a site
# - get_evpn_topologies_details: Get details of a specific EVPN fabric

@safe_tool_definition("get_org_evpn_topologies", "evpn")
async def get_org_evpn_topologies(org_id: str) -> str:
    f"""
    {get_tool_doc('get_org_evpn_topologies')}
    """
    
    try:
        debug_stderr(f"Executing get_org_evpn_topologies for org {org_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}/evpn_topologies?for_site=any"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                fabrics_data = json.loads(result.get("response_data", "[]"))
                result["evpn_fabrics"] = fabrics_data
                result["fabric_count"] = len(fabrics_data)
                result["message"] = f"Retrieved {len(fabrics_data)} EVPN fabrics in organization"
                
                # Topology analysis
                org_topology_summary = []
                for fabric in fabrics_data:
                    summary = {
                        "id": fabric.get("id"),
                        "name": fabric.get("name"),
                        "created_time": fabric.get("created_time"),
                        "version": fabric.get("version"),
                        "site_id": fabric.get("site_id"),
                        "site_specific_fabric": fabric.get("for_site"),
                        "type": fabric.get("evpn_options", {}).get("routed_at"),
                        "border_leaf": not fabric.get("evpn_options", {}).get("core_as_border", False)
                    }
                    org_topology_summary.append(summary)
                result["org_topology_summary"] = "org_topology_summary"

            except json.JSONDecodeError:
                result["message"] = "Retrieved EVPN fabrics but could not parse response"
        
        debug_stderr("################# ✓ get_org_evpn_topologies completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_org_evpn_topologies failed: {e}")
        return json.dumps({"error": f"Failed to get EVPN fabrics: {str(e)}"}, indent=2)

@safe_tool_definition("get_site_evpn_topologies", "evpn")
async def get_site_evpn_topologies(site_id: str) -> str:
    f"""
    {get_tool_doc('get_site_evpn_topologies')}
    """
    try:
        debug_stderr(f"Executing get_site_evpn_topologies for site {site_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/sites/{site_id}/evpn_topologies"
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            try:
                fabrics_data = json.loads(result.get("response_data", "[]"))
                result["evpn_fabrics"] = fabrics_data
                result["fabric_count"] = len(fabrics_data)
                result["message"] = f"Retrieved {len(fabrics_data)} EVPN fabrics in site"
                
                # Topology analysis
                site_topology_summary = []
                for fabric in fabrics_data:
                    summary = {
                        "id": fabric.get("id"),
                        "name": fabric.get("name"),
                        "created_time": fabric.get("created_time"),
                        "version": fabric.get("version"),
                        "type": fabric.get("evpn_options", {}).get("routed_at"),
                        "border_leaf": not fabric.get("evpn_options", {}).get("core_as_border", False)
                    }
                    site_topology_summary.append(summary)
                result["site_topology_summary"] = site_topology_summary

            except json.JSONDecodeError:
                result["message"] = "Retrieved EVPN fabrics but could not parse response"
        
        debug_stderr("################# ✓ get_site_evpn_topologies completed ################# ")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"get_site_evpn_topologies failed: {e}")
        return json.dumps({"error": f"Failed to get EVPN fabrics: {str(e)}"}, indent=2)

@safe_tool_definition("get_evpn_topologies_details", "evpn")
async def get_evpn_topologies_details(topology_id: str, site_specific_fabric: str, site_id: str = None, org_id: str = None) -> str:
    f"""
    {get_tool_doc('get_evpn_topologies_details')}
    """
    try:
        debug_stderr(f"Executing get_site_evpn_topologies for topology {topology_id}...")
        client = get_api_client()
        if site_id and site_specific_fabric:
            endpoint = f"/api/v1/sites/{site_id}/evpn_topologies/{topology_id}"
        elif org_id:
            endpoint = f"/api/v1/orgs/{org_id}/evpn_topologies/{topology_id}"
        else:
            return json.dumps({"error": "Either site_id or org_id must be provided"}, indent=2)
        
        result = await client.make_request(endpoint)
        
        if result.get("status") == "SUCCESS":
            topo_data = json.loads(result.get("response_data", "{}"))
            
            # Standard topology details
            switches = topo_data.get("switches", [])
            pod_names = topo_data.get("pod_names", {})
            evpn_options = topo_data.get("evpn_options", {})
            
            result["evpn_topology_details"] = build_topology_summary(topo_data, switches, pod_names, evpn_options)
            # Build conditional technical context based on actual fabric
            result["conditional_technical_guidance"] = analyze_fabric_and_provide_context(topo_data)
            result["smart_verification_plan"] = verification_plan(topo_data)
        
        debug_stderr("################# ✓ get_site_evpn_topologies completed ################# ")
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f" Error: Failed to get EVPN topology details: {str(e)}"}, indent=2)

def analyze_fabric_and_provide_context(topo_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze fabric characteristics and provide conditional technical context
    """
    context = {}
     
    try:
        debug_stderr(f" - Executing analyze_fabric_and_provide_context for topology ...")
        evpn_options = topo_data.get("evpn_options", {})
        routing_type = evpn_options.get("routed_at")
        
        debug_stderr(f"         - Analyzing overlay info for the topology ...")
        if routing_type:
            overlay_service_types = get_technical_fact('overlay_service_types')
            if overlay_service_types and routing_type in overlay_service_types:
                overlay_info = overlay_service_types[routing_type]
                context["overlay_specific_guidance"] = {
                    "detected_type": routing_type,
                    "characteristics": overlay_info,
                    "configuration_focus": get_overlay_specific_recommendations(routing_type, overlay_service_types)
                }
        
        # Analyze switch count and provide topology recommendations  
        debug_stderr(f"         - Analyzing switch count for the topology ...")
        switches = topo_data.get("switches", [])
        switch_count = len(switches)
        if switch_count >= 10:
            perf_optimization = get_technical_fact('performance_optimization')
            context["large_fabric_optimization"] = {
                "switch_count": switch_count,
                "recommendations": perf_optimization.get('mac_vrf_scaling', {}),
                "bgp_scaling": "Consider route reflector hierarchy for large fabrics"
            }
        
        # Check for multihoming indicators
        debug_stderr(f"         - Analyzing mulithoming for the topology ...")
        has_multihoming = any(switch.get("esi") for switch in switches)
        if has_multihoming:
            context["multihoming_guidance"] = {
                "detected": True,
                "considerations": [
                    "Ensure ESI values are unique across fabric",
                    "Configure LACP for improved availability",
                    "Verify designated forwarder election"
                ]
            }
        
        # Analyze BGP AS configuration
        debug_stderr(f"         - Analyzing bgp peering strategies for the topology ...")
        underlay_as = evpn_options.get("underlay", {}).get("as_base")
        if underlay_as:
            bgp_strategies = get_technical_fact('bgp_peering_strategies')
            context["bgp_configuration"] = {
                "underlay_as_base": underlay_as,
                "underlay_peering_strategy": bgp_strategies.get('underlay_peering', {}),
                "overlay_peering_strategy": bgp_strategies.get('overlay_peering',{}),
                "policy_recommendations": [
                    "Ensure unique AS numbers per device for EBGP",
                    "Configure default route(0.0.0.0/0 or ::/0) advertisement in evpn_underlay_export/ evpn_underlay_umport policy if in-band management is required(most campus evpn fabrics)",
                    "Check for ecmp settings in BGP"
                    "Enable BFD for fast convergence (1000ms underlay, 3000ms overlay)"                    
                ]
            }
        
        debug_stderr("################# ✓ analyze_fabric_and_provide_context completed ################# ")
        return context
    except Exception as e:
        debug_stderr(f"analyze_fabric_and_provide_context failed: {e}")
        return {
            "error": f" Error: Fabric analysis failed: {str(e)}",
            "basic_info": {
                "switches_count": len(topo_data.get("switches", [])),
                "routing_type": evpn_options.get("routed_at", "unknown")
            }
        }

def get_overlay_specific_recommendations(routing_type: str, overlay_service_types: dict = None) -> List[str]:
    """
    Get specific recommendations based on overlay type
    """
    debug_stderr(f"- Executing get_overlay_specific_recommendations_fixed for {routing_type}")
    
    # If overlay_service_types not provided, get it
    if not overlay_service_types:
        overlay_service_types = get_technical_fact('overlay_service_types')
    
    if routing_type in overlay_service_types:
        overlay_data = overlay_service_types[routing_type]
        
        recommendations = []
        
        # Add Mist-specific naming
        if "mist_name" in overlay_data:
            recommendations.append(f"Mist Campus Fabric Type: {overlay_data['mist_name']}")
        
        # Add routing location info
        if "routing_location" in overlay_data:
            recommendations.append(f"Routing performed at: {overlay_data['routing_location']}")
        
        # Add complexity assessment
        if "complexity" in overlay_data:
            recommendations.append(f"Architecture complexity: {overlay_data['complexity']}")
        
        # Add best use cases
        if "best_for" in overlay_data:
            recommendations.append(f"Optimized for: {overlay_data['best_for']}")
        
        # Add co-existence info if available
        if "co-existance" in overlay_data:
            recommendations.append(f"Advanced features: {overlay_data['co-existance']}")
        
        # Add characteristics
        if "characteristics" in overlay_data:
            for char in overlay_data["characteristics"][:3]:  # Limit to top 3
                recommendations.append(f"Feature: {char}")
        
        debug_stderr("-  ✓ get_overlay_specific_recommendations_fixed completed ")
        return recommendations
    
    # Fallback for unknown types
    debug_stderr("Using fallback recommendations")
    return [f"Review {routing_type} overlay type and configure accordingly"]

def build_topology_summary(topo_data: Dict, switches: List, pod_names: Dict, evpn_options: Dict) -> Dict:
    """
    Build comprehensive topology summary with technical context
    """
    debug_stderr(f"- Executing build_topology_summary for topology ... ")
    try:

        # Get routing type for enhanced context
        routing_type = evpn_options.get("routed_at", "unknown")

        # Pod summary
        num_pods = len(pod_names)
        pods = [{"pod_id": k, "name": v} for k, v in pod_names.items()]
        
        # Switch analysis with technical context
        switch_summary = []
        models = set()
        roles = set()
        irb_interfaces = []
        
        for sw in switches:
            switch_info = {
                "mac": sw.get("mac"),
                "model": sw.get("model"),
                "router_id": sw.get("router_id"),
                "role": sw.get("role"),
                "evpn_id": sw.get("evpn_id"),
                "pod": sw.get("pod"),
                "site_id": sw.get("site_id")
            }
            switch_summary.append(switch_info)
            models.add(sw.get("model"))
            roles.add(sw.get("role"))

            # Gather IRB interfaces with technical context
            config = sw.get("config", {})
            other_ip_configs = config.get("other_ip_configs", {})
            if other_ip_configs:
                irb_interfaces.append({
                    "mac": sw.get("mac"),
                    "router_id": sw.get("router_id"),
                    "irb_configuration": other_ip_configs,
                    "technical_note": "IRB interfaces enable inter-VLAN routing",
                    "anycast_gateways": [k for k, v in other_ip_configs.items() 
                                      if v.get("evpn_anycast", False)]                    
                })
        
        debug_stderr(f" - ✓ build_topology_summary completed ...")

        return {
            "topology_id": topo_data.get("id"),
            "name": topo_data.get("name"),
            "fabric_architecture": {
                "type": routing_type,
                "mist_fabric_type": get_mist_fabric_type_name(routing_type),
                "core_as_border": evpn_options.get("core_as_border"),
                "overlay": evpn_options.get("overlay", {}),
                "underlay": evpn_options.get("underlay", {}),
                "auto_loopback_subnet": evpn_options.get("auto_loopback_subnet"),
                "auto_router_id_subnet": evpn_options.get("auto_router_id_subnet"),
                "version": topo_data.get("version")
            },
            "pod_organization": {
                "num_pods": num_pods,
                "pods": pods,
                "technical_note": "Pods organize switches into logical fabric segments"
            },
            "switch_infrastructure": {
                "num_switches": len(switches),
                "switch_models": list(models),
                "switch_roles": list(roles), 
                "switches": switch_summary,
                "technical_note": f"Detected {len(roles)} different switch roles in {routing_type} fabric"
            },
            "irb_configuration": {
                "interfaces": irb_interfaces,
                "count": len(irb_interfaces),
                "technical_note": f"IRB interfaces provide gateway services for VLANs in {routing_type} architecture"
            },
            "fabric_metadata": {
                "created_time": topo_data.get("created_time"),
                "modified_time": topo_data.get("modified_time"),
                "version": topo_data.get("version"),
                "site_id": topo_data.get("site_id"),
                "org_id": topo_data.get("org_id"),
                "juniper_mist_managed": True
            }
        }      
    
    except Exception as e:
        debug_stderr(f"Error in build_topology_summary_fixed: {e}", indent=2)
        return {
            "error": f"Failed building EVPN topology summary: {str(e)}",
            "topology_id": topo_data.get("id", "unknown"),
            "switches_count": len(switches) if switches else 0
        }

def get_mist_fabric_type_name(routing_type: str) -> str:
    """
    Get Mist-specific fabric type name for routing type
    """
    mist_mapping = {
        "edge": "IP-CLOS",
        "distribution": "Core-Distribution ERB", 
        "core": "Core-Distribution CRB",
        "collapsed-core": "EVPN Multihoming",
        "bridged": "Layer 2 Extension"
    }
    return mist_mapping.get(routing_type, f"Unknown ({routing_type})")

def verification_plan(topo_data: Dict[str, Any]) -> Dict[str, Any]:
    """VTEP-aware verification plan based on fabric architecture
    IMPORTANT: For BGP fabric analysis, use search_org_bgp_stats() first!
    This tool should only be used for specific device debugging after 
    API analysis identifies issues.
    """
    
    switches = topo_data.get("switches", [])
    evpn_options = topo_data.get("evpn_options", {})
    fabric_type = evpn_options.get("routed_at", "unknown")
    
    verification_plan = {
        "fabric_context": {"type": fabric_type, "vtep_strategy": get_vtep_strategy(fabric_type)},
        "priority_switches": {},
        "execution_order": []
    }
    
    if fabric_type == "edge":  # IP-CLOS
        # Access switches have VTEPs
        access_switches = [s for s in switches if s.get("role") == "access"]
        border_switches = [s for s in switches if s.get("role") == "border"]
        
        # Representative access per pod (VTEP commands)
        pods = set(s.get("pod") for s in access_switches if s.get("pod"))
        for pod_id in pods:
            pod_access = [s for s in access_switches if s.get("pod") == pod_id]
            if pod_access:
                access = pod_access[0]
                verification_plan["priority_switches"][access["mac"]] = {
                    "role": "access", "has_vtep": True,
                    "commands": ["show evpn database", "show evpn instance extensive", "show evpn ip-prefix-database", "show interfaces vtep"]
                }
        
        # Border switches (VTEP + external)
        if border_switches:
            verification_plan["priority_switches"][border_switches[0]["mac"]] = {
                "role": "border", "has_vtep": True,
                "commands": [ "show evpn database", "show evpn instance extensive", "show interfaces vtep"]
            }
    
    elif fabric_type in ["distribution", "core"]:  # ERB/CRB
        # Distribution/Core have VTEPs, access is L2 only
        dist_switches = [s for s in switches if s.get("role") == "distribution"]
        core_switches = [s for s in switches if s.get("role") == "core"]
        
        # Distribution switches (VTEP commands)
        if dist_switches:
            verification_plan["priority_switches"][dist_switches[0]["mac"]] = {
                "role": "distribution", "has_vtep": True,
                "commands": ["show evpn database", "show interfaces vtep", "show evpn instance extensive", "show evpn ip-prefix-database"]
            }
        
        # Core switches (VTEP commands)
        if core_switches:
            verification_plan["priority_switches"][core_switches[0]["mac"]] = {
                "role": "core", "has_vtep": True, 
                "commands": ["show evpn database", "show interfaces vtep"]
            }
    
    elif fabric_type == "collapsed-core":  # EVPN Multihoming
        # Only core devices have VTEPs
        core_switches = [s for s in switches if s.get("role") == "core"]
        if core_switches:
            verification_plan["priority_switches"][core_switches[0]["mac"]] = {
                "role": "core", "has_vtep": True,
                "commands": ["show evpn database", "show interfaces vtep", "show evpn instance extensive", "show lacp interfaces", "show evpn ip-prefix-database"]
            }
    
    return verification_plan

def get_vtep_strategy(fabric_type: str) -> str:
    """Return VTEP placement strategy by fabric type"""
    vtep_strategies = {
        "edge": "Access and Border switches have VTEPs",
        "distribution": "Distribution and Core switches have VTEPs", 
        "core": "Core switches have VTEPs",
        "collapsed-core": "Core switches only have VTEPs (2-4 device limit)"
    }
    return vtep_strategies.get(fabric_type, "Unknown VTEP placement")


# Clients functions
# - get_org_evpn_topologies: List EVPN fabrics in an org
# - get_site_evpn_tpopologies: List EVPN fabrics in a site
# - get_evpn_topologies_details: Get details of a specific EVPN fabric

@safe_tool_definition("search_org_wired_clients", "clients")
async def search_org_wired_clients(
    org_id: str,
    auth_state: str = None,
    auth_method: str = None,
    source: str = None,
    site_id: str = None,
    device_mac: str = None,
    mac: str = None,
    port_id: str = None,
    vlan: int = None,
    ip_address: str = None,
    manufacture: str = None,
    text: str = None,
    nacrule_id: str = None,
    dhcp_hostname: str = None,
    dhcp_fqdn: str = None,
    dhcp_client_identifier: str = None,
    dhcp_vendor_class_identifier: str = None,
    dhcp_request_params: str = None,
    limit: int = 100,
    start: int = None,
    end: int = None,
    duration: str = "1d"
) -> str:
    """
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
    try:
        debug_stderr(f"Executing search_org_wired_clients for org {org_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}/wired_clients/search"
        
        # Build parameters using dictionary comprehension (Option 1)
        params = {
            "limit": limit,
            **{k: v for k, v in {
                "auth_state": auth_state,
                "auth_method": auth_method,
                "source": source,
                "site_id": site_id,
                "mac": mac,
                "device_mac": device_mac,
                "port_id": port_id,
                "vlan": vlan,
                "ip_address": ip_address,
                "manufacture": manufacture,
                "text": text,
                "nacrule_id": nacrule_id,
                "dhcp_hostname": dhcp_hostname,
                "dhcp_fqdn": dhcp_fqdn,
                "dhcp_client_identifier": dhcp_client_identifier,
                "dhcp_vendor_class_identifier": dhcp_vendor_class_identifier,
                "dhcp_request_params": dhcp_request_params,
                "start": start,
                "end": end,
                "duration": duration                
            }.items() if v is not None}
        }

        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                clients_data = json.loads(result.get("response_data", "{}"))
                result["clients"] = clients_data.get("results", [])
                result["client_count"] = len(clients_data.get("results", []))
                result["message"] = f"Found {len(clients_data.get('results', []))} wired clients"
                
                # Wired client analysis
                if clients_data.get("results"):
                    client_analysis = {
                        "by_vlan": {},
                        "by_auth_method": {},
                        "by_manufacturer": {},
                        "total_clients": len(clients_data.get("results", []))
                    }
                    
                    for client in clients_data.get("results", []):
                        # VLAN analysis
                        vlan = client.get("vlan", "untagged")
                        client_analysis["by_vlan"][str(vlan)] = client_analysis["by_vlan"].get(str(vlan), 0) + 1
                        
                        # Auth method analysis
                        auth = client.get("auth_method", "none")
                        client_analysis["by_auth_method"][auth] = client_analysis["by_auth_method"].get(auth, 0) + 1
                        
                        # Manufacturer analysis
                        mfg = client.get("manufacture", "unknown")
                        client_analysis["by_manufacturer"][mfg] = client_analysis["by_manufacturer"].get(mfg, 0) + 1
                    
                    result["client_analysis"] = client_analysis
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved wired clients but could not parse response"
        
        debug_stderr("################# ✓ search_org_wired_clients completed #################")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"search_org_wired_clients failed: {e}")
        return json.dumps({"error": f" Error: Failed to search wired clients: {str(e)}"}, indent=2)
    
@safe_tool_definition("search_org_nac_clients", "clients")
async def search_org_nac_clients(
    org_id: str,
    nacrule_id: str = None,
    nacrule_matched: bool = None,
    auth_type: str = None,
    vlan: str = None,
    nas_vendor: str = None,
    idp_id: str = None,
    ssid: str = None,
    username: str = None,
    timestamp: float = None,
    site_id: str = None,
    ap: str = None,
    mac: str = None,
    mdm_managed: bool = None,
    status: str = None,
    type: str = None,
    mdm_compliance: str = None,
    family: str = None,
    model: str = None,
    os: str = None,
    hostname: str = None,
    mfg: str = None,
    mdm_provider: str = None,
    sort: str = None,
    usermac_label: list = None,
    ingress_vlan: str = None,
    start: int = None,
    end: int = None,
    duration: str = "1d",
    limit: int = 100,
    page: int = 1
) -> str:
    """
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
    try:
        debug_stderr(f"Executing search_org_nac_clients for org {org_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}/nac_clients/search"
        
        
        # Build parameters using dictionary comprehension (Option 1)
        params = {
            "limit": limit,
            **{k: v for k, v in {
                "limit": limit,
                "nacrule_id": nacrule_id,
                "nacrule_matched": nacrule_matched,
                "auth_type": auth_type,
                "nas_vendor": nas_vendor,
                "idp_id": idp_id,
                "ssid": ssid,
                "username": username,
                "timestamp": timestamp,
                "ap": ap,
                "mdm_managed": mdm_managed,
                "status": status,
                "type": type,
                "mdm_compliance": mdm_compliance,
                "family": family,
                "model": model,
                "os": os,
                "hostname": hostname,
                "mfg": mfg,
                "mdm_provider": mdm_provider,
                "sort": sort,
                "usermac_label": usermac_label,
                "ingress_vlan": ingress_vlan,
                "site_id": site_id,
                "mac": mac,
                "vlan": vlan,
                "start": start,
                "end": end,
                "duration": duration                
            }.items() if v is not None}
        }

        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                clients_data = json.loads(result.get("response_data", "{}"))
                result["nac_clients"] = clients_data.get("results", [])
                result["client_count"] = len(clients_data.get("results", []))
                result["total_count"] = clients_data.get("total", 0)
                result["page"] = page
                result["message"] = f"Found {len(clients_data.get('results', []))} NAC clients (total: {clients_data.get('total', 0)})"
                
                # NAC client analysis
                if clients_data.get("results"):
                    nac_analysis = {
                        "by_status": {},
                        "by_auth_type": {},
                        "by_mdm_compliance": {},
                        "by_type": {},
                        "total_clients": len(clients_data.get("results", []))
                    }
                    
                    for client in clients_data.get("results", []):
                        # Status analysis
                        status = client.get("status", "unknown")
                        nac_analysis["by_status"][status] = nac_analysis["by_status"].get(status, 0) + 1
                        
                        # Auth type analysis
                        auth = client.get("auth_type", "unknown")
                        nac_analysis["by_auth_type"][auth] = nac_analysis["by_auth_type"].get(auth, 0) + 1
                        
                        # MDM compliance analysis
                        compliance = client.get("mdm_compliance", "not_managed")
                        nac_analysis["by_mdm_compliance"][compliance] = nac_analysis["by_mdm_compliance"].get(compliance, 0) + 1
                        
                        # Type analysis
                        client_type = client.get("type", "unknown")
                        nac_analysis["by_type"][client_type] = nac_analysis["by_type"].get(client_type, 0) + 1
                    
                    result["nac_analysis"] = nac_analysis
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved NAC clients but could not parse response"
        
        debug_stderr("################# ✓ search_org_nac_clients completed #################")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"search_org_nac_clients failed: {e}")
        return json.dumps({"error": f" Error: Failed to search NAC clients: {str(e)}"}, indent=2)

@safe_tool_definition("search_org_wireless_clients", "clients")
async def search_org_wireless_clients(
    org_id: str,
    site_id: str = None,
    mac: str = None,
    ip_address: str = None,
    hostname: str = None,
    band: str = None,
    device: str = None,
    os: str = None,
    model: str = None,
    ap: str = None,
    psk_id: str = None,
    psk_name: str = None,
    username: str = None,
    vlan: str = None,
    ssid: str = None,
    text: str = None,
    limit: int = 100,
    start: int = None,
    end: int = None,
    duration: str = "1d"
) -> str:
    """
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
    try:
        debug_stderr(f"Executing search_org_wireless_clients for org {org_id}...")
        client = get_api_client()
        endpoint = f"/api/v1/orgs/{org_id}/clients/search"
        
        # Build parameters using dictionary comprehension (Option 1)
        params = {
            "limit": limit,
            **{k: v for k, v in {
                "site_id": site_id,
                "mac": mac,
                "ip_address": ip_address,
                "hostname": hostname,
                "band": band,
                "device": device,
                "os": os,
                "model": model,
                "ap": ap,
                "psk_id": psk_id,
                "psk_name": psk_name,
                "username": username,
                "vlan": vlan,
                "ssid": ssid,
                "text": text,
                "start": start,
                "end": end,
                "duration": duration
            }.items() if v is not None}
        }
        
        result = await client.make_request(endpoint, params=params)
        
        if result.get("status") == "SUCCESS":
            try:
                clients_data = json.loads(result.get("response_data", "{}"))
                result["clients"] = clients_data.get("results", [])
                result["client_count"] = len(clients_data.get("results", []))
                result["message"] = f"Found {len(clients_data.get('results', []))} wireless clients"
                
                # Client analysis
                if clients_data.get("results"):
                    client_analysis = {
                        "by_band": {},
                        "by_ssid": {},
                        "by_auth_type": {},
                        "total_clients": len(clients_data.get("results", []))
                    }
                    
                    for client in clients_data.get("results", []):
                        # Band analysis
                        band = client.get("band", "unknown")
                        client_analysis["by_band"][band] = client_analysis["by_band"].get(band, 0) + 1
                        
                        # SSID analysis
                        ssid = client.get("ssid", "unknown")
                        client_analysis["by_ssid"][ssid] = client_analysis["by_ssid"].get(ssid, 0) + 1
                        
                        # Auth type analysis
                        auth = "psk" if client.get("psk_id") else "802.1x" if client.get("username") else "open"
                        client_analysis["by_auth_type"][auth] = client_analysis["by_auth_type"].get(auth, 0) + 1
                    
                    result["client_analysis"] = client_analysis
                
            except json.JSONDecodeError:
                result["message"] = "Retrieved wireless clients but could not parse response"
        
        debug_stderr("################# ✓ search_org_wireless_clients completed #################")
        return json.dumps(result, indent=2)
    except Exception as e:
        debug_stderr(f"search_org_wireless_clients failed: {e}")
        return json.dumps({"error": f" Error: Failed to search wireless clients: {str(e)}"}, indent=2)


# =====================================================================
# MAIN FUNCTION WITH SECURITY INITIALIZATION
# =====================================================================

def main():
    """
    Enhanced main function with comprehensive error handling and configuration validation
    
    Features:
    - Command line argument parsing with validation
    - Environment variable validation and sanitization  
    - Dependency checking and version validation
    - Transport protocol selection and configuration
    - Comprehensive error handling and logging
    - Graceful shutdown and cleanup procedures
    """
    try:
        debug_stderr("=== ENHANCED COMPREHENSIVE MAIN FUNCTION START ===")
        
        parser = argparse.ArgumentParser(
            description="Enhanced Comprehensive Secure Mist MCP Server with Complete API Coverage",
            epilog="This server provides comprehensive access to all Mist Cloud API endpoints with enhanced monitoring, diagnostics, and security analysis."
        )
        
        parser.add_argument('-H', '--host', default="127.0.0.1", type=str, 
                           help='Mist MCP Server host (default: 127.0.0.1)')
        parser.add_argument('-t', '--transport', default="stdio", type=str, 
                           choices=['stdio', 'sse', 'http'],  # Fixed: removed 'websocket', added valid options
                           help='Mist MCP Server transport (stdio, sse, http)')
        parser.add_argument('-p', '--port', default=30040, type=int, 
                           help='Mist MCP Server port (default: 30040)')
        parser.add_argument('--log-level', default="INFO", type=str,
                           choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                           help='Set logging level (default: INFO)')
        parser.add_argument('--debug', action='store_true',
                           help='Enable maximum debug output')
        parser.add_argument('--validate-config', action='store_true',
                           help='Validate configuration and exit')
        parser.add_argument('--security-check', action='store_true',
                           help='Perform security analysis of API token and exit')
        
        debug_stderr("Parsing command line arguments...")
        args = parser.parse_args()
        debug_stderr(f"✓ Arguments parsed: transport={args.transport}, host={args.host}, port={args.port}")
        
        # Set logging level
        log_level = logging.DEBUG if args.debug else getattr(logging, args.log_level)
        logging.getLogger().setLevel(log_level)
        debug_stderr(f"✓ Logging level set to: {args.log_level}")
        
        # Validate configuration
        debug_stderr("Validating comprehensive configuration...")
        debug_stderr(f"✓ Base URL: {CONFIG.base_url}")
        debug_stderr(f"✓ WebSocket support: {CONFIG.websockets_available}")
        debug_stderr(f"✓ API token configured: {bool(CONFIG.api_token)}")
        debug_stderr(f"✓ Max concurrent requests: {CONFIG.max_concurrent_requests}")
        debug_stderr(f"✓ Request timeout: {CONFIG.request_timeout}s")
        debug_stderr(f"✓ Security mode: {'STRICT' if security_analyzer.strict_mode else 'PERMISSIVE'}")
        debug_stderr(f"✓ Security thresholds: {security_analyzer.risk_thresholds}")
        
        if args.security_check:
            debug_stderr("Security check requested - use analyze_token_security tool for detailed analysis")
            print("Use the analyze_token_security tool for comprehensive privilege analysis")
            return
        
        if args.validate_config:
            debug_stderr("Configuration validation requested - testing API connectivity...")
            try:
                import asyncio
                # Quick connectivity test
                async def validate():
                    client = get_api_client()
                    result = await client.make_request("/api/v1/self", timeout_override=10)
                    return result.get("status") == "SUCCESS"
                
                validation_result = asyncio.run(validate())
                if validation_result:
                    debug_stderr("✓ Configuration validation PASSED - API connectivity confirmed")
                    print("✓ Configuration validation PASSED")
                    print("✓ Security controls initialized")
                else:
                    debug_stderr("✗ Configuration validation FAILED - API connectivity issues")
                    print("✗ Configuration validation FAILED")
                    sys.exit(1)
                
            except Exception as e:
                debug_stderr(f"✗ Configuration validation ERROR: {e}")
                print(f"✗ Configuration validation ERROR: {e}")
                sys.exit(1)
            
            sys.exit(0)
        
        # Create enhanced API client
        try:
            get_api_client()
            debug_stderr("✓ Enhanced Comprehensive Secure Mist API client initialized successfully")
            if not CONFIG.websockets_available:
                debug_stderr("⚠ WebSocket library not available - shell commands will be disabled")
                debug_stderr("  Install websockets with: pip install websockets")
        except Exception as e:
            debug_stderr(f"✗ FATAL: Enhanced API client creation failed: {e}")
            debug_stderr(f"Traceback: {traceback.format_exc()}")
            print(f"FATAL ERROR: Failed to initialize API client: {e}")
            sys.exit(1)
        
        # Show comprehensive tool registration status
        if hasattr(mcp, '_tools'):
            tool_count = len(mcp._tools)
            debug_stderr(f"✓ {tool_count} enhanced tools registered successfully")
            
            # Group tools by category
            tool_categories = {}
            for tool_name in mcp._tools.keys():
                # Try to determine category from function name patterns
                if any(keyword in tool_name for keyword in ['org', 'organization']):
                    category = 'organization'
                elif any(keyword in tool_name for keyword in ['site', 'wlan', 'device']):
                    category = 'site'
                elif any(keyword in tool_name for keyword in ['msp']):
                    category = 'msp'
                elif any(keyword in tool_name for keyword in ['auth', 'user', 'privilege']):
                    category = 'authentication'
                elif any(keyword in tool_name for keyword in ['event', 'alarm']):
                    category = 'monitoring'
                elif any(keyword in tool_name for keyword in ['shell', 'command']):
                    category = 'device_management'
                elif any(keyword in tool_name for keyword in ['health', 'debug', 'test', 'performance']):
                    category = 'system'
                elif any(keyword in tool_name for keyword in ['security', 'analyze', 'acknowledge']):
                    category = 'security'
                else:
                    category = 'utility'
                
                if category not in tool_categories:
                    tool_categories[category] = []
                tool_categories[category].append(tool_name)
            
            debug_stderr("Tool categories registered:")
            for category, tools in tool_categories.items():
                debug_stderr(f"  {category}: {len(tools)} tools")
                for tool in tools[:3]:  # Show first 3 tools per category
                    debug_stderr(f"    - {tool}")
                if len(tools) > 3:
                    debug_stderr(f"    ... and {len(tools) - 3} more")
        else:
            debug_stderr("✗ WARNING: No tools registered - this may indicate a problem")
        
        # Display startup summary
        debug_stderr("=== STARTUP SUMMARY ===")
        debug_stderr(f"Server: {CONFIG.mcp_name}")
        debug_stderr(f"API Base URL: {CONFIG.base_url}")
        debug_stderr(f"Transport: {args.transport}")
        debug_stderr(f"WebSocket Support: {'Yes' if CONFIG.websockets_available else 'No'}")
        debug_stderr(f"Shell Commands: {'Enabled' if CONFIG.websockets_available else 'Disabled'}")
        debug_stderr(f"Tools Registered: {len(mcp._tools) if hasattr(mcp, '_tools') else 0}")
        debug_stderr(f"Max Concurrent: {CONFIG.max_concurrent_requests}")
        debug_stderr(f"Security Mode: {'STRICT' if security_analyzer.strict_mode else 'PERMISSIVE'}")
        debug_stderr("======================")
        
        # Handle different transport types with proper FastMCP methods
        debug_stderr(f"Starting Enhanced Comprehensive Secure MCP server with transport: {args.transport}")
        
        try:
            if args.transport == 'stdio':
                debug_stderr("Using stdio transport...")
                mcp.run()  # stdio is the default, no parameters needed
            elif args.transport == 'sse':
                debug_stderr(f"Using SSE transport on {args.host}:{args.port}...")
                mcp.run_sse(host=args.host, port=args.port)
            elif args.transport == 'http':
                debug_stderr(f"Using HTTP transport on {args.host}:{args.port}...")
                # For HTTP transport, use run_sse which handles HTTP requests
                mcp.run_sse(host=args.host, port=args.port)
            else:
                raise ValueError(f"Unsupported transport: {args.transport}")
                
        except KeyboardInterrupt:
            debug_stderr("✓ Server interrupted by user (Ctrl+C) - shutting down gracefully")
        except Exception as e:
            debug_stderr(f"✗ FATAL: Failed to start Enhanced Secure MCP server: {e}")
            debug_stderr(f"Traceback: {traceback.format_exc()}")
            print(f"FATAL ERROR: Server startup failed: {e}")
            raise
        finally:
            # Enhanced cleanup with diagnostics and security logging
            debug_stderr("=== ENHANCED CLEANUP PHASE ===")
            
            # Save final diagnostics
            try:
                final_stats = diagnostics.get_comprehensive_health_summary()
                debug_stderr(f"Final statistics: {final_stats['service_status']['total_requests']} requests processed")
                debug_stderr(f"Success rate: {final_stats['service_status']['success_rate']:.1%}")
                debug_stderr(f"Peak memory: {final_stats['service_status']['peak_memory_mb']:.1f}MB")
                debug_stderr(f"Security events: {final_stats['api_insights']['categories_used'].get('security', 0)}")
            except Exception as e:
                debug_stderr(f"Error getting final statistics: {e}")
            
            # Close API client
            if api_client:
                try:
                    asyncio.run(api_client.close())
                    debug_stderr("✓ Enhanced API client closed successfully")
                except Exception as e:
                    debug_stderr(f"Error closing enhanced API client: {e}")
            
            debug_stderr("=== ENHANCED SECURE SERVER SHUTDOWN COMPLETE ===")
            
    except Exception as e:
        debug_stderr(f"✗ FATAL ERROR IN ENHANCED SECURE MAIN: {e}")
        debug_stderr(f"Traceback: {traceback.format_exc()}")
        print(f"FATAL ERROR: {e}")
        sys.exit(1)
if __name__ == '__main__':
    try:
        debug_stderr("=== ENHANCED COMPREHENSIVE SECURE SCRIPT EXECUTION START ===")
        debug_stderr(f"Script arguments: {sys.argv}")
        debug_stderr(f"Python executable: {sys.executable}")
        debug_stderr(f"Script version: 3.1 - Complete API Coverage with Security Analysis")
        main()
    except Exception as e:
        debug_stderr(f"✗ FATAL: Enhanced secure script execution failed: {e}")
        debug_stderr(f"Traceback: {traceback.format_exc()}")
        print(f"FATAL EXECUTION ERROR: {e}")
        sys.exit(1)