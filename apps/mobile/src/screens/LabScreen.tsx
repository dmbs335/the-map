import React, { useMemo, useState } from 'react';
import {
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import labsJson from '../data/labs.json';
import quizJson from '../data/quizzes.json';
import { useLearning } from '../state/LearningContext';
import { palette, spacing, type AppTheme } from '../theme';
import type {
  PracticeData,
  QuizData,
  ReviewRating,
} from '../types';
import {
  BulletList,
  Card,
  ListItemButton,
  Pill,
  PrimaryButton,
  ScreenHeader,
  SectionTitle,
} from '../components/ui';

const practice = labsJson as PracticeData;
const quizzes = quizJson as QuizData;

export function LabScreen({
  theme,
  onOpenMission,
}: {
  theme: AppTheme;
  onOpenMission: (missionId: string) => void;
}): React.ReactElement {
  const {
    progress,
    dueQuizIds,
    rateQuiz,
  } = useLearning();
  const [quizIndex, setQuizIndex] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);

  const dueQuestions = useMemo(() => {
    const dueSet = new Set(dueQuizIds);
    const due = quizzes.questions.filter((question) => dueSet.has(question.id));
    return due.length > 0 ? due : quizzes.questions.slice(0, 12);
  }, [dueQuizIds]);

  const currentQuestion =
    dueQuestions[quizIndex % Math.max(1, dueQuestions.length)];

  const submitRating = (rating: ReviewRating): void => {
    if (!currentQuestion) {
      return;
    }
    rateQuiz(currentQuestion.id, rating);
    setSelectedAnswer(null);
    setQuizIndex((current) => current + 1);
  };

  return (
    <ScrollView
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      <ScreenHeader
        eyebrow="PRACTICE"
        title="관찰 → 가설 → 대조 → 검증"
        subtitle="공개 자료와 합성 사례로 The Map의 질문을 직접 적용한다. 취약점 이름보다 원인과 반례를 먼저 적는다."
        theme={theme}
      />

      <View style={styles.metrics}>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>
            {progress.completedMissionIds.length}
          </Text>
          <Text style={[styles.small, { color: theme.muted }]}>완료 연습</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>
            {practice.missions.length}
          </Text>
          <Text style={[styles.small, { color: theme.muted }]}>전체 연습</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{dueQuizIds.length}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>복습 대기</Text>
        </Card>
      </View>

      <Card theme={theme} style={{ backgroundColor: theme.primarySoft }}>
        <Text style={[styles.cardTitle, { color: theme.text }]}>연습할 때 지킬 것</Text>
        <BulletList
          items={[
            '직접 관찰한 사실과 추론을 분리한다.',
            '한 번에 하나의 조건만 바꾸는 대조군을 둔다.',
            '반례가 나오면 가설을 버리거나 좁힌다.',
            '결론의 강도는 출처와 재현 수준에 맞춘다.',
            '공개 자료, 합성 예제, 명시적으로 허가된 환경만 사용한다.',
          ]}
          theme={theme}
        />
      </Card>

      <SectionTitle
        title="범주별 분석 연습"
        subtitle={`${progress.completedMissionIds.length}/${practice.missions.length} 완료`}
        theme={theme}
      />
      <View style={styles.list}>
        {practice.missions.map((mission) => {
          const locked = !mission.prerequisiteLessonIds.every((id) =>
            progress.completedLessonIds.includes(id),
          );
          return (
            <ListItemButton
              key={mission.id}
              title={mission.title}
              subtitle={mission.summary}
              meta={`${mission.minutes}분 · ${mission.level} · ${mission.supportLevel}`}
              onPress={() => onOpenMission(mission.id)}
              theme={theme}
              completed={progress.completedMissionIds.includes(mission.id)}
              locked={locked}
            />
          );
        })}
      </View>

      <SectionTitle
        title="회상 복습"
        subtitle={`${dueQuizIds.length}개 due · 답을 고른 뒤 기억 난이도를 평가한다`}
        theme={theme}
      />
      {currentQuestion ? (
        <Card theme={theme}>
          <Pill label={currentQuestion.kind} theme={theme} tone="primary" />
          <Text style={[styles.quizPrompt, { color: theme.text }]}>
            {currentQuestion.prompt}
          </Text>
          <View style={styles.answerList}>
            {currentQuestion.options.map((option, index) => {
              const selected = selectedAnswer === index;
              const correct = currentQuestion.answerIndex === index;
              const showResult = selectedAnswer !== null;
              const borderColor =
                showResult && correct
                  ? palette.success
                  : showResult && selected
                    ? palette.danger
                    : theme.border;
              return (
                <Pressable
                  key={`${index}-${option}`}
                  disabled={showResult}
                  onPress={() => setSelectedAnswer(index)}
                  style={({ pressed }: { pressed: boolean }) => [
                    styles.answer,
                    {
                      backgroundColor: theme.surfaceAlt,
                      borderColor,
                      opacity: pressed ? 0.7 : 1,
                    },
                  ]}
                >
                  <Text style={[styles.answerText, { color: theme.text }]}>
                    {index + 1}. {option}
                  </Text>
                </Pressable>
              );
            })}
          </View>

          {selectedAnswer !== null ? (
            <View style={styles.explanation}>
              <Text
                style={[
                  styles.result,
                  {
                    color:
                      selectedAnswer === currentQuestion.answerIndex
                        ? palette.success
                        : palette.danger,
                  },
                ]}
              >
                {selectedAnswer === currentQuestion.answerIndex
                  ? '정답'
                  : '다시 연결해보자'}
              </Text>
              <Text style={[styles.body, { color: theme.muted }]}>
                {currentQuestion.explanation}
              </Text>
              <Text style={[styles.small, { color: theme.muted }]}>기억 정도</Text>
              <View style={styles.ratingRow}>
                {([0, 1, 2, 3] as ReviewRating[]).map((rating) => (
                  <PrimaryButton
                    key={rating}
                    label={['모름', '어려움', '보통', '확실'][rating] ?? String(rating)}
                    onPress={() => submitRating(rating)}
                    theme={theme}
                    variant={rating >= 2 ? 'primary' : 'secondary'}
                  />
                ))}
              </View>
            </View>
          ) : null}
        </Card>
      ) : null}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  content: { gap: spacing.lg, padding: spacing.lg, paddingBottom: 120 },
  metrics: { flexDirection: 'row', gap: spacing.sm },
  metricCard: { flex: 1, alignItems: 'center' },
  metric: { fontSize: 22, fontWeight: '900' },
  small: { fontSize: 12, lineHeight: 18, textAlign: 'center' },
  cardTitle: { fontSize: 17, fontWeight: '900' },
  body: { fontSize: 14, lineHeight: 21 },
  list: { gap: spacing.sm },
  quizPrompt: { fontSize: 17, fontWeight: '800', lineHeight: 25 },
  answerList: { gap: spacing.sm },
  answer: { borderWidth: 1, borderRadius: 12, padding: spacing.md },
  answerText: { fontSize: 14, lineHeight: 21 },
  explanation: { gap: spacing.md },
  result: { fontSize: 16, fontWeight: '900' },
  ratingRow: { flexDirection: 'row', flexWrap: 'wrap', gap: spacing.sm },
});
