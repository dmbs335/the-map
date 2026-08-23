export type Level = 'foundation' | 'practitioner' | 'advanced' | 'research';

export type EvidenceBoundary =
  | 'modelOnly'
  | 'symbolicWitness'
  | 'syntheticHarness'
  | 'implementationHarness'
  | 'checkedFinding';

export interface CurriculumTrack {
  id: string;
  title: string;
  description: string;
  level: Level;
  color: string;
}

export interface Lesson {
  id: string;
  trackId: string;
  order: number;
  title: string;
  level: Level;
  minutes: number;
  summary: string;
  objectives: string[];
  concepts: string[];
  relatedCategories: string[];
  prerequisiteIds: string[];
  practiceType: string;
  evidenceBoundary: EvidenceBoundary;
  safetyNote: string;
  keyQuestions: string[];
  sourceRefs: string[];
}

export interface CurriculumData {
  schema: string;
  tracks: CurriculumTrack[];
  lessons: Lesson[];
}

export interface QuizQuestion {
  id: string;
  lessonId: string;
  kind: 'multipleChoice' | 'scenario';
  prompt: string;
  options: string[];
  answerIndex: number;
  explanation: string;
  tags: string[];
}

export interface QuizData {
  schema: string;
  questions: QuizQuestion[];
}

export interface CatalogCategory {
  id: string;
  title: string;
  topicCount: number;
}

export interface CatalogTopic {
  id: string;
  title: string;
  categoryId: string;
  categoryTitle: string;
  path: string;
  summary: string;
  tags: string[];
  sourceUrl: string;
  verified: boolean;
}

export interface CatalogData {
  schema: string;
  sourceRevision: string;
  categories: CatalogCategory[];
  topics: CatalogTopic[];
  stats: {
    topicCount: number;
    categoryCount: number;
    verifiedCount: number;
  };
}

export interface QuizReview {
  repetitions: number;
  intervalDays: number;
  ease: number;
  nextReviewAt: string;
  lastReviewedAt: string;
  lastRating: ReviewRating;
}

export type ReviewRating = 0 | 1 | 2 | 3;

export interface LearningProgress {
  version: 3;
  completedLessonIds: string[];
  completedMissionIds: string[];
  bookmarkedTopicIds: string[];
  quizReviews: Record<string, QuizReview>;
  activityDates: string[];
}

export type TabId = 'today' | 'learn' | 'library' | 'lab' | 'research';

export type AnalysisSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type AnalysisConfidence = 'low' | 'medium' | 'high';
export type AndroidComponentType =
  | 'activity'
  | 'service'
  | 'receiver'
  | 'provider'
  | 'application';

export interface JadxAppIdentity {
  packageName: string;
  versionName: string;
  versionCode: number;
  minSdk: number;
  targetSdk: number;
  sha256?: string;
  signerSha256?: string;
}

export interface JadxComponent {
  name: string;
  type: AndroidComponentType;
  exported: boolean;
  permission?: string;
  intentActions: string[];
  authorities: string[];
  evidence: string[];
}

export interface JadxFinding {
  id: string;
  title: string;
  category: string;
  severity: AnalysisSeverity;
  confidence: AnalysisConfidence;
  description: string;
  evidence: string[];
  locations: string[];
  assumptions: string[];
  negativeControls: string[];
  learningObjectives: string[];
  evidenceBoundary: EvidenceBoundary;
}

export interface JadxBehaviorSignal {
  id: string;
  title: string;
  category: string;
  confidence: AnalysisConfidence;
  description: string;
  evidence: string[];
  benignExplanations: string[];
  capabilities: string[];
}

export interface JadxDataFlow {
  id: string;
  source: string;
  sink: string;
  path: string[];
  confidence: AnalysisConfidence;
  notes: string;
}

export interface JadxLearningReport {
  schema: 'jadx-learning-report.v1';
  generatedAt: string;
  generator: string;
  app: JadxAppIdentity;
  summary: {
    classCount: number;
    methodCount: number;
    permissionCount: number;
    exportedComponentCount: number;
    nativeLibraryCount: number;
    findingCount: number;
    behaviorSignalCount: number;
  };
  permissions: string[];
  nativeLibraries: string[];
  components: JadxComponent[];
  findings: JadxFinding[];
  behaviorSignals: JadxBehaviorSignal[];
  dataFlows: JadxDataFlow[];
  analysisLimits: string[];
  safety: {
    syntheticOrAuthorizedOnly: boolean;
    executablePayloadsIncluded: boolean;
    notes: string;
  };
}

export interface LabMission {
  id: string;
  title: string;
  level: Level;
  minutes: number;
  summary: string;
  objectives: string[];
  steps: string[];
  expectedSignals: string[];
  hints: string[];
  prerequisiteLessonIds: string[];
  findingCategories: string[];
  evidenceBoundary: EvidenceBoundary;
  safetyNote: string;
  sourceRefs: string[];
}

export interface LabData {
  schema: string;
  missions: LabMission[];
}
