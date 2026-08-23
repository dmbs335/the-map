import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import quizDataJson from '../data/quizzes.json';
import {
  calculateStreak,
  clearProgress,
  EMPTY_PROGRESS,
  isDue,
  isoDay,
  loadProgress,
  saveProgress,
  scheduleReview,
} from '../storage/progress';
import type {
  LearningProgress,
  QuizData,
  ReviewRating,
} from '../types';

const quizData = quizDataJson as QuizData;

interface LearningContextValue {
  hydrated: boolean;
  progress: LearningProgress;
  completedCount: number;
  completedMissionCount: number;
  bookmarkedCount: number;
  dueQuizIds: string[];
  streak: number;
  completeLesson: (lessonId: string) => void;
  reopenLesson: (lessonId: string) => void;
  completeMission: (missionId: string) => void;
  reopenMission: (missionId: string) => void;
  toggleBookmark: (topicId: string) => void;
  rateQuiz: (quizId: string, rating: ReviewRating) => void;
  resetProgress: () => Promise<void>;
}

const LearningContext = createContext<LearningContextValue | null>(null);

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

export function LearningProvider({
  children,
}: React.PropsWithChildren): React.ReactElement {
  const [progress, setProgress] = useState<LearningProgress>(EMPTY_PROGRESS);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    let mounted = true;
    loadProgress()
      .then((loaded) => {
        if (mounted) {
          setProgress(loaded);
          setHydrated(true);
        }
      })
      .catch((error) => {
        console.warn('Unable to hydrate progress', error);
        if (mounted) {
          setHydrated(true);
        }
      });
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (!hydrated) {
      return;
    }
    saveProgress(progress).catch((error) => {
      console.warn('Unable to persist progress', error);
    });
  }, [hydrated, progress]);

  const recordActivity = useCallback(
    (current: LearningProgress): LearningProgress => ({
      ...current,
      activityDates: unique([...current.activityDates, isoDay()]).sort(),
    }),
    [],
  );

  const completeLesson = useCallback(
    (lessonId: string) => {
      setProgress((current) =>
        recordActivity({
          ...current,
          completedLessonIds: unique([
            ...current.completedLessonIds,
            lessonId,
          ]),
        }),
      );
    },
    [recordActivity],
  );

  const reopenLesson = useCallback((lessonId: string) => {
    setProgress((current) => ({
      ...current,
      completedLessonIds: current.completedLessonIds.filter(
        (id) => id !== lessonId,
      ),
    }));
  }, []);

  const completeMission = useCallback(
    (missionId: string) => {
      setProgress((current) =>
        recordActivity({
          ...current,
          completedMissionIds: unique([
            ...current.completedMissionIds,
            missionId,
          ]),
        }),
      );
    },
    [recordActivity],
  );

  const reopenMission = useCallback((missionId: string) => {
    setProgress((current) => ({
      ...current,
      completedMissionIds: current.completedMissionIds.filter(
        (id) => id !== missionId,
      ),
    }));
  }, []);

  const toggleBookmark = useCallback((topicId: string) => {
    setProgress((current) => {
      const exists = current.bookmarkedTopicIds.includes(topicId);
      return {
        ...current,
        bookmarkedTopicIds: exists
          ? current.bookmarkedTopicIds.filter((id) => id !== topicId)
          : [...current.bookmarkedTopicIds, topicId],
      };
    });
  }, []);

  const rateQuiz = useCallback(
    (quizId: string, rating: ReviewRating) => {
      setProgress((current) =>
        recordActivity({
          ...current,
          quizReviews: {
            ...current.quizReviews,
            [quizId]: scheduleReview(current.quizReviews[quizId], rating),
          },
        }),
      );
    },
    [recordActivity],
  );

  const resetProgress = useCallback(async () => {
    await clearProgress();
    setProgress(EMPTY_PROGRESS);
  }, []);

  const dueQuizIds = useMemo(
    () =>
      quizData.questions
        .filter((question) => isDue(progress.quizReviews[question.id]))
        .map((question) => question.id),
    [progress.quizReviews],
  );

  const value = useMemo<LearningContextValue>(
    () => ({
      hydrated,
      progress,
      completedCount: progress.completedLessonIds.length,
      completedMissionCount: progress.completedMissionIds.length,
      bookmarkedCount: progress.bookmarkedTopicIds.length,
      dueQuizIds,
      streak: calculateStreak(progress.activityDates),
      completeLesson,
      reopenLesson,
      completeMission,
      reopenMission,
      toggleBookmark,
      rateQuiz,
      resetProgress,
    }),
    [
      hydrated,
      progress,
      dueQuizIds,
      completeLesson,
      reopenLesson,
      completeMission,
      reopenMission,
      toggleBookmark,
      rateQuiz,
      resetProgress,
    ],
  );

  return (
    <LearningContext.Provider value={value}>
      {children}
    </LearningContext.Provider>
  );
}

export function useLearning(): LearningContextValue {
  const value = useContext(LearningContext);
  if (!value) {
    throw new Error('useLearning must be used within LearningProvider');
  }
  return value;
}
