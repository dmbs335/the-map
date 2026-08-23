import type {
  AnalysisConfidence,
  AnalysisSeverity,
  EvidenceBoundary,
  JadxLearningReport,
} from '../types';

const SEVERITIES: AnalysisSeverity[] = [
  'info',
  'low',
  'medium',
  'high',
  'critical',
];
const CONFIDENCES: AnalysisConfidence[] = ['low', 'medium', 'high'];
const BOUNDARIES: EvidenceBoundary[] = [
  'modelOnly',
  'symbolicWitness',
  'syntheticHarness',
  'implementationHarness',
  'checkedFinding',
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasString(record: Record<string, unknown>, key: string): boolean {
  return typeof record[key] === 'string' && record[key] !== '';
}

function hasNumber(record: Record<string, unknown>, key: string): boolean {
  return typeof record[key] === 'number' && Number.isFinite(record[key]);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function fail(message: string): never {
  throw new Error(`JADX report validation failed: ${message}`);
}

export function validateJadxLearningReport(value: unknown): JadxLearningReport {
  if (!isRecord(value)) {
    fail('root must be an object');
  }
  if (value.schema !== 'jadx-learning-report.v1') {
    fail('schema must be jadx-learning-report.v1');
  }
  if (!hasString(value, 'generatedAt') || !hasString(value, 'generator')) {
    fail('generatedAt and generator are required');
  }
  if (!isRecord(value.app)) {
    fail('app identity is required');
  }
  for (const key of ['packageName', 'versionName'] as const) {
    if (!hasString(value.app, key)) {
      fail(`app.${key} is required`);
    }
  }
  for (const key of ['versionCode', 'minSdk', 'targetSdk'] as const) {
    if (!hasNumber(value.app, key)) {
      fail(`app.${key} must be a number`);
    }
  }
  if (!isRecord(value.summary)) {
    fail('summary is required');
  }
  for (const key of [
    'classCount',
    'methodCount',
    'permissionCount',
    'exportedComponentCount',
    'nativeLibraryCount',
    'findingCount',
    'behaviorSignalCount',
  ] as const) {
    if (!hasNumber(value.summary, key)) {
      fail(`summary.${key} must be a number`);
    }
  }
  if (!isStringArray(value.permissions) || !isStringArray(value.nativeLibraries)) {
    fail('permissions and nativeLibraries must be string arrays');
  }
  if (!Array.isArray(value.components)) {
    fail('components must be an array');
  }
  for (const [index, component] of value.components.entries()) {
    if (!isRecord(component) || !hasString(component, 'name')) {
      fail(`components[${index}] must have a name`);
    }
    if (!['activity', 'service', 'receiver', 'provider', 'application'].includes(String(component.type))) {
      fail(`components[${index}].type is invalid`);
    }
    if (typeof component.exported !== 'boolean') {
      fail(`components[${index}].exported must be boolean`);
    }
    if (!isStringArray(component.intentActions) || !isStringArray(component.authorities) || !isStringArray(component.evidence)) {
      fail(`components[${index}] arrays are invalid`);
    }
  }
  if (!Array.isArray(value.findings)) {
    fail('findings must be an array');
  }
  for (const [index, finding] of value.findings.entries()) {
    if (!isRecord(finding)) {
      fail(`findings[${index}] must be an object`);
    }
    for (const key of ['id', 'title', 'category', 'description'] as const) {
      if (!hasString(finding, key)) {
        fail(`findings[${index}].${key} is required`);
      }
    }
    if (!SEVERITIES.includes(finding.severity as AnalysisSeverity)) {
      fail(`findings[${index}].severity is invalid`);
    }
    if (!CONFIDENCES.includes(finding.confidence as AnalysisConfidence)) {
      fail(`findings[${index}].confidence is invalid`);
    }
    if (!BOUNDARIES.includes(finding.evidenceBoundary as EvidenceBoundary)) {
      fail(`findings[${index}].evidenceBoundary is invalid`);
    }
    for (const key of [
      'evidence',
      'locations',
      'assumptions',
      'negativeControls',
      'learningObjectives',
    ] as const) {
      if (!isStringArray(finding[key])) {
        fail(`findings[${index}].${key} must be a string array`);
      }
    }
  }
  if (!Array.isArray(value.behaviorSignals) || !Array.isArray(value.dataFlows)) {
    fail('behaviorSignals and dataFlows must be arrays');
  }
  if (!isStringArray(value.analysisLimits)) {
    fail('analysisLimits must be a string array');
  }
  if (!isRecord(value.safety)) {
    fail('safety block is required');
  }
  if (value.safety.syntheticOrAuthorizedOnly !== true) {
    fail('safety.syntheticOrAuthorizedOnly must be true');
  }
  if (value.safety.executablePayloadsIncluded !== false) {
    fail('executable payloads are not accepted by the learning app');
  }
  if (!hasString(value.safety, 'notes')) {
    fail('safety.notes is required');
  }

  const report = value as unknown as JadxLearningReport;
  if (report.summary.findingCount !== report.findings.length) {
    fail('summary.findingCount does not match findings.length');
  }
  if (report.summary.behaviorSignalCount !== report.behaviorSignals.length) {
    fail('summary.behaviorSignalCount does not match behaviorSignals.length');
  }
  return report;
}

export function parseJadxLearningReport(text: string): JadxLearningReport {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid JSON: ${detail}`);
  }
  return validateJadxLearningReport(value);
}

const severityWeight: Record<AnalysisSeverity, number> = {
  info: 0,
  low: 1,
  medium: 3,
  high: 6,
  critical: 10,
};
const confidenceWeight: Record<AnalysisConfidence, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

export function findingPriorityScore(
  severity: AnalysisSeverity,
  confidence: AnalysisConfidence,
  evidenceCount: number,
): number {
  return severityWeight[severity] * 10 + confidenceWeight[confidence] * 4 + Math.min(evidenceCount, 8);
}

export function reportCoverage(report: JadxLearningReport): {
  attackSurface: number;
  dataFlow: number;
  behavior: number;
  limits: number;
} {
  return {
    attackSurface: report.components.length + report.permissions.length,
    dataFlow: report.dataFlows.length,
    behavior: report.behaviorSignals.length,
    limits: report.analysisLimits.length,
  };
}
