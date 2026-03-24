/**
 * arp-guard — Agent Runtime Protection
 *
 * Thin re-export package. All implementation lives in hackmyagent/arp.
 * Install this package to use ARP as a standalone dependency without
 * importing hackmyagent directly.
 *
 * @example
 *   import { AgentRuntimeProtection, scanText, ALL_PATTERNS } from 'arp-guard';
 *
 *   const arp = new AgentRuntimeProtection({ agentName: 'my-agent' });
 *   await arp.start();
 */
export {
  // Version
  VERSION,

  // Core
  AgentRuntimeProtection,

  // Engine
  EventEngine,

  // Intelligence
  IntelligenceCoordinator,
  BudgetController,
  AnomalyDetector,
  AnthropicAdapter,
  OpenAIAdapter,
  OllamaAdapter,
  createAdapter,
  autoDetectAdapter,

  // Monitors
  ProcessMonitor,
  NetworkMonitor,
  FilesystemMonitor,
  SkillCapabilityMonitor,
  createCapabilityMonitor,
  parseDeclaredCapabilities,

  // Interceptors
  ProcessInterceptor,
  NetworkInterceptor,
  FilesystemInterceptor,
  PromptInterceptor,
  MCPProtocolInterceptor,
  A2AProtocolInterceptor,

  // Enforcement
  EnforcementEngine,

  // Logging
  LocalLogger,

  // Config
  loadConfig,
  defaultConfig,

  // AI-layer patterns
  scanText,
  PATTERN_SETS,
  ALL_PATTERNS,

  // Proxy
  ARPProxy,

  // Telemetry
  GTINForwarder,
  generateSensorToken,
  buildGTINPayload,
  submitGTINEvent,
  isAnomalousEvent,
  mapEventType,

  // License
  checkLicense,
  hasFeature,
  registerLicenseValidator,
  PREMIUM_FEATURES,
} from 'hackmyagent/arp';

export type {
  // Types
  ARPConfig,
  ARPEvent,
  MonitorType,
  EventCategory,
  EventSeverity,
  LLMAdapter,
  LLMAdapterType,
  LLMAssessment,
  LLMResponse,
  IntelligenceConfig,
  BudgetState,
  AlertRule,
  AlertCondition,
  MonitorConfig,
  InterceptorConfig,
  AILayerConfig,
  ProxyConfig,
  ProxyUpstream,
  EnforcementAction,
  EnforcementResult,
  Monitor,
  GTINConfig,
  AlertCallback,
  ARPProxyDeps,
  ThreatPattern,
  ScanResult,
  DeclaredCapabilities,
  ObservedBehavior,
  CapabilityViolation,
  LicenseTier,
  LicenseInfo,
  GTINForwarderConfig,
  GTINEventType,
  GTINRuntimeEnv,
  GTINPayload,
  GTINSubmitResult,
} from 'hackmyagent/arp';
