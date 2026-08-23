export type Level = 'foundation' | 'practitioner' | 'advanced' | 'research';

export type SupportLevel =
  | 'idea'
  | 'sourceBacked'
  | 'reproduced'
  | 'wellSupported';

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
  supportLevel: SupportLevel;
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
  version: 4;
  completedLessonIds: string[];
  completedMissionIds: string[];
  bookmarkedTopicIds: string[];
  quizReviews: Record<string, QuizReview>;
  activityDates: string[];
}

export type TabId = 'today' | 'learn' | 'library' | 'lab' | 'research';

export interface PracticeMission {
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
  focusAreas: string[];
  supportLevel: SupportLevel;
  safetyNote: string;
  sourceRefs: string[];
}

export interface PracticeData {
  schema: string;
  missions: PracticeMission[];
}
