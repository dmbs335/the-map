import React, { useMemo } from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';

import catalogJson from '../data/generated/catalog.json';
import curriculumJson from '../data/curriculum.json';
import labsJson from '../data/labs.json';
import { useLearning } from '../state/LearningContext';
import { palette, spacing, type AppTheme } from '../theme';
import type { CatalogData, CurriculumData, PracticeData, TabId } from '../types';
import {
  Card,
  Pill,
  PrimaryButton,
  ProgressBar,
  ScreenHeader,
  SectionTitle,
} from '../components/ui';

const curriculum = curriculumJson as CurriculumData;
const catalog = catalogJson as CatalogData;
const practice = labsJson as PracticeData;

export function TodayScreen({
  theme,
  onOpenLesson,
  onOpenMission,
  onNavigate,
}: {
  theme: AppTheme;
  onOpenLesson: (lessonId: string) => void;
  onOpenMission: (missionId: string) => void;
  onNavigate: (tab: TabId) => void;
}): React.ReactElement {
  const {
    hydrated,
    progress,
    completedCount,
    completedMissionCount,
    bookmarkedCount,
    dueQuizIds,
    streak,
  } = useLearning();

  const nextLesson = useMemo(
    () =>
      curriculum.lessons.find(
        (lesson) =>
          !progress.completedLessonIds.includes(lesson.id) &&
          lesson.prerequisiteIds.every((id) =>
            progress.completedLessonIds.includes(id),
          ),
      ),
    [progress.completedLessonIds],
  );

  const nextMission = useMemo(
    () =>
      practice.missions.find(
        (mission) =>
          !progress.completedMissionIds.includes(mission.id) &&
          mission.prerequisiteLessonIds.every((id) =>
            progress.completedLessonIds.includes(id),
          ),
      ),
    [progress.completedLessonIds, progress.completedMissionIds],
  );

  const completion =
    curriculum.lessons.length === 0
      ? 0
      : completedCount / curriculum.lessons.length;

  return (
    <ScrollView
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      <ScreenHeader
        eyebrow="THE MAP LEARNING"
        title="오늘은 질문 하나를 더 정교하게"
        subtitle="취약점 이름을 외우기보다 관찰, 가설, 대조, 재현, 일반화의 흐름으로 The Map을 익힌다."
        theme={theme}
      />

      <View style={styles.pillRow}>
        <Pill
          label={hydrated ? `${streak}일 연속` : '진도 불러오는 중'}
          theme={theme}
          tone="success"
        />
        <Pill
          label={`${bookmarkedCount}개 북마크`}
          theme={theme}
          tone="primary"
        />
      </View>

      <Card theme={theme}>
        <View style={styles.rowBetween}>
          <Text style={[styles.cardTitle, { color: theme.text }]}>전체 커리큘럼</Text>
          <Text style={[styles.metric, { color: theme.primary }]}>
            {completedCount}/{curriculum.lessons.length}
          </Text>
        </View>
        <ProgressBar value={completion} theme={theme} />
        <Text style={[styles.body, { color: theme.muted }]}>
          The Map의 13개 최상위 범주를 그대로 따라가며 각 범주를 개념, 사례, 분석법,
          실험 설계 순서로 학습한다.
        </Text>
      </Card>

      <View style={styles.metrics}>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{dueQuizIds.length}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>복습 대기</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>
            {completedMissionCount}/{practice.missions.length}
          </Text>
          <Text style={[styles.small, { color: theme.muted }]}>연습</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{bookmarkedCount}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>북마크</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{catalog.stats.topicCount}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>Map 주제</Text>
        </Card>
      </View>

      <SectionTitle title="다음 레슨" subtitle="선행 학습이 끝난 가장 가까운 단위" theme={theme} />
      {nextLesson ? (
        <Card theme={theme}>
          <View style={styles.pillRow}>
            <Pill label={nextLesson.level} theme={theme} tone="primary" />
            <Pill label={`${nextLesson.minutes}분`} theme={theme} />
            <Pill label={nextLesson.supportLevel} theme={theme} tone="research" />
          </View>
          <Text style={[styles.cardTitle, { color: theme.text }]}>{nextLesson.title}</Text>
          <Text style={[styles.body, { color: theme.muted }]}>{nextLesson.summary}</Text>
          <PrimaryButton label="레슨 열기" onPress={() => onOpenLesson(nextLesson.id)} theme={theme} />
        </Card>
      ) : (
        <Card theme={theme}>
          <Text style={[styles.cardTitle, { color: theme.text }]}>레슨을 모두 완료했어</Text>
          <Text style={[styles.body, { color: theme.muted }]}>
            연습과 탐구 탭에서 범주 간 연결과 새로운 질문 만들기를 반복해봐.
          </Text>
        </Card>
      )}

      <SectionTitle title="다음 분석 연습" subtitle="관찰과 대조군을 실제로 적어보는 단계" theme={theme} />
      {nextMission ? (
        <Card theme={theme}>
          <Text style={[styles.cardTitle, { color: theme.text }]}>{nextMission.title}</Text>
          <Text style={[styles.body, { color: theme.muted }]}>{nextMission.summary}</Text>
          <PrimaryButton label="연습 열기" onPress={() => onOpenMission(nextMission.id)} theme={theme} />
        </Card>
      ) : null}

      <SectionTitle title="오늘의 균형" subtitle="읽기·회상·분석·탐구를 함께 유지한다" theme={theme} />
      <Card theme={theme}>
        <View style={styles.balanceRow}>
          <Balance number="1" label="레슨" color={palette.primary} theme={theme} />
          <Balance number="5" label="회상" color={palette.warning} theme={theme} />
          <Balance number="1" label="연습" color={palette.success} theme={theme} />
          <Balance number="1" label="질문" color={palette.research} theme={theme} />
        </View>
        <View style={styles.buttonStack}>
          <PrimaryButton label="연습 열기" onPress={() => onNavigate('lab')} theme={theme} />
          <PrimaryButton label="탐구 열기" onPress={() => onNavigate('research')} theme={theme} variant="secondary" />
        </View>
      </Card>

      <Card theme={theme} style={{ backgroundColor: theme.primarySoft }}>
        <Text style={[styles.cardTitle, { color: theme.text }]}>학습 원칙</Text>
        <Text style={[styles.body, { color: theme.muted }]}>
          공개 자료, 합성 예제, 또는 명시적으로 허가된 환경에서만 검증한다.
          관찰하지 않은 사실은 추측으로 표시하고, 결론의 강도는 가진 근거보다 세게 잡지 않는다.
        </Text>
      </Card>
    </ScrollView>
  );
}

function Balance({
  number,
  label,
  color,
  theme,
}: {
  number: string;
  label: string;
  color: string;
  theme: AppTheme;
}): React.ReactElement {
  return (
    <View style={styles.balanceItem}>
      <Text style={[styles.balanceNumber, { color }]}>{number}</Text>
      <Text style={[styles.small, { color: theme.muted }]}>{label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  content: { gap: spacing.lg, padding: spacing.lg, paddingBottom: 120 },
  pillRow: { flexDirection: 'row', flexWrap: 'wrap', gap: spacing.sm },
  rowBetween: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start', gap: spacing.md },
  cardTitle: { fontSize: 18, fontWeight: '900' },
  body: { fontSize: 14, lineHeight: 22 },
  small: { fontSize: 11, lineHeight: 17, textAlign: 'center' },
  metric: { fontSize: 20, fontWeight: '900' },
  metrics: { flexDirection: 'row', gap: spacing.xs },
  metricCard: { flex: 1, alignItems: 'center', paddingHorizontal: spacing.xs },
  balanceRow: { flexDirection: 'row', justifyContent: 'space-around' },
  balanceItem: { alignItems: 'center', gap: spacing.xs },
  balanceNumber: { fontSize: 24, fontWeight: '900' },
  buttonStack: { gap: spacing.sm },
});
