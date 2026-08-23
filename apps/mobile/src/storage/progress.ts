import Storage from 'expo-sqlite/kv-store';

import type { LearningProgress, QuizReview, ReviewRating } from '../types';

const STORAGE_KEY = 'the-map-learning-progress-v4';

export const EMPTY_PROGRESS: LearningProgress = {
  version: 4,
  completedLessonIds: [],
  completedMissionIds: [],
  bookmarkedTopicIds: [],
  quizReviews: {},
  activityDates: [],
};

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isQuizReview(value: unknown): value is QuizReview {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const candidate = value as Partial<QuizReview>;
  return (
    typeof candidate.repetitions === 'number' &&
    typeof candidate.intervalDays === 'number' &&
    typeof candidate.ease === 'number' &&
    typeof candidate.nextReviewAt === 'string' &&
    typeof candidate.lastReviewedAt === 'string' &&
    typeof candidate.lastRating === 'number' &&
    candidate.lastRating >= 0 &&
    candidate.lastRating <= 3
  );
}

function sanitizeProgress(value: unknown): LearningProgress {
  if (!value || typeof value !== 'object') {
    return EMPTY_PROGRESS;
  }

  const candidate = value as Partial<LearningProgress> & {
    version?: number;
  };
  const quizReviews: Record<string, QuizReview> = {};
  if (candidate.quizReviews && typeof candidate.quizReviews === 'object') {
    for (const [id, review] of Object.entries(candidate.quizReviews)) {
      if (isQuizReview(review)) {
        quizReviews[id] = review;
      }
    }
  }

  return {
    version: 4,
    completedLessonIds: unique(
      isStringArray(candidate.completedLessonIds)
        ? candidate.completedLessonIds
        : [],
    ),
    completedMissionIds: unique(
      isStringArray(candidate.completedMissionIds)
        ? candidate.completedMissionIds
        : [],
    ),
    bookmarkedTopicIds: unique(
      isStringArray(candidate.bookmarkedTopicIds)
        ? candidate.bookmarkedTopicIds
        : [],
    ),
    quizReviews,
    activityDates: unique(
      isStringArray(candidate.activityDates) ? candidate.activityDates : [],
    ).sort(),
  };
}

export async function loadProgress(): Promise<LearningProgress> {
  const raw = await Storage.getItem(STORAGE_KEY);
  if (!raw) {
    return EMPTY_PROGRESS;
  }
  try {
    return sanitizeProgress(JSON.parse(raw));
  } catch (error) {
    console.warn('Unable to parse learning progress', error);
    return EMPTY_PROGRESS;
  }
}

export async function saveProgress(progress: LearningProgress): Promise<void> {
  await Storage.setItem(STORAGE_KEY, JSON.stringify(progress));
}

export async function clearProgress(): Promise<void> {
  await Storage.removeItem(STORAGE_KEY);
}

export function isoDay(date: Date = new Date()): string {
  return date.toISOString().slice(0, 10);
}

export function calculateStreak(
  activityDates: string[],
  now: Date = new Date(),
): number {
  const active = new Set(activityDates);
  const cursor = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
  ));
  let streak = 0;
  while (active.has(isoDay(cursor))) {
    streak += 1;
    cursor.setUTCDate(cursor.getUTCDate() - 1);
  }
  return streak;
}

export function isDue(review: QuizReview | undefined, now = new Date()): boolean {
  if (!review) {
    return true;
  }
  return new Date(review.nextReviewAt).getTime() <= now.getTime();
}

function addDays(date: Date, days: number): Date {
  const next = new Date(date);
  next.setUTCDate(next.getUTCDate() + days);
  return next;
}

export function scheduleReview(
  previous: QuizReview | undefined,
  rating: ReviewRating,
  now = new Date(),
): QuizReview {
  const current = previous ?? {
    repetitions: 0,
    intervalDays: 0,
    ease: 2.4,
    nextReviewAt: now.toISOString(),
    lastReviewedAt: now.toISOString(),
    lastRating: 0 as ReviewRating,
  };

  let repetitions = current.repetitions;
  let intervalDays = current.intervalDays;
  let ease = current.ease;

  if (rating === 0) {
    repetitions = 0;
    intervalDays = 1;
    ease = Math.max(1.3, ease - 0.25);
  } else if (rating === 1) {
    repetitions = Math.max(0, repetitions - 1);
    intervalDays = Math.max(1, Math.round(Math.max(1, intervalDays) * 0.7));
    ease = Math.max(1.3, ease - 0.12);
  } else {
    repetitions += 1;
    if (repetitions === 1) {
      intervalDays = rating === 3 ? 3 : 2;
    } else if (repetitions === 2) {
      intervalDays = rating === 3 ? 7 : 5;
    } else {
      const bonus = rating === 3 ? 1.25 : 1;
      intervalDays = Math.max(
        1,
        Math.round(Math.max(1, intervalDays) * ease * bonus),
      );
    }
    ease = Math.min(3.2, ease + (rating === 3 ? 0.08 : 0.02));
  }

  return {
    repetitions,
    intervalDays,
    ease,
    nextReviewAt: addDays(now, intervalDays).toISOString(),
    lastReviewedAt: now.toISOString(),
    lastRating: rating,
  };
}
