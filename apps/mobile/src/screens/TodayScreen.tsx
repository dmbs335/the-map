import React, { useMemo } from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';

import catalogJson from '../data/generated/catalog.json';
import curriculumJson from '../data/curriculum.json';
import labsJson from '../data/labs.json';
import { useAnalysis } from '../state/AnalysisContext';
import { useLearning } from '../state/LearningContext';
import { palette, spacing, type AppTheme } from '../theme';
import type { CatalogData, CurriculumData, LabData, TabId } from '../types';
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
const labs = labsJson as LabData;

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
  const { report, reportSource } = useAnalysis();

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
      labs.missions.find(
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
        eyebrow="ANDROID SECURITY LEARNING LAB"
        title="오늘은 증거 사슬 하나를 닫아보자"
        subtitle="JADX에서 관찰하고, 모바일·웹 경계를 연결하고, semantic 가설을 local control로 검증한다."
        theme={theme}
      />
      <View style={styles.pillRow}>
        <Pill
          label={hydrated ? `${streak}일 연속` : '진도 불러오는 중'}
          theme={theme}
          tone="success"
        />
        <Pill
          label={reportSource === 'sample' ? 'synthetic report' : 'imported report'}
          theme={theme}
          tone="research"
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
        <Text style={[styles.small, { color: theme.muted }]}>
          {curriculum.tracks.length}개 트랙: Android 플랫폼·JADX·공격면·악성행위·동적 분석·웹·formal research
        </Text>
      </Card>

      <View style={styles.metrics}>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{dueQuizIds.length}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>복습 대기</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{completedMissionCount}/{labs.missions.length}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>미션</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{bookmarkedCount}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>북마크</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{catalog.stats.topicCount}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>The Map</Text>
        </Card>
      </View>

      <SectionTitle title="다음 레슨" subtitle="선행 학습이 끝난 가장 가까운 단위" theme={theme} />
      {nextLesson ? (
        <Card theme={theme}>
          <View style={styles.pillRow}>
            <Pill label={nextLesson.level} theme={theme} tone="primary" />
            <Pill label={`${nextLesson.minutes}분`} theme={theme} />
            <Pill label={nextLesson.evidenceBoundary} theme={theme} tone="research" />
          </View>
          <Text style={[styles.cardTitle, { color: theme.text }]}>{nextLesson.title}</Text>
          <Text style={[styles.body, { color: theme.muted }]}>{nextLesson.summary}</Text>
          <PrimaryButton label="레슨 열기" onPress={() => onOpenLesson(nextLesson.id)} theme={theme} />
        </Card>
      ) : (
        <Card theme={theme}>
          <Text style={[styles.cardTitle, { color: theme.text }]}>레슨을 모두 완료했어</Text>
          <Text style={[styles.body, { color: theme.muted }]}>Lab과 연구 가설을 반복해서 검토해봐.</Text>
        </Card>
      )}

      <SectionTitle title="다음 분석 미션" subtitle="실제 evidence chain을 연습하는 단계" theme={theme} />
      {nextMission ? (
        <Card theme={theme}>
          <Text style={[styles.cardTitle, { color: theme.text }]}>{nextMission.title}</Text>
          <Text style={[styles.body, { color: theme.muted }]}>{nextMission.summary}</Text>
          <PrimaryButton label="미션 열기" onPress={() => onOpenMission(nextMission.id)} theme={theme} />
        </Card>
      ) : null}

      <SectionTitle title="현재 JADX Artifact" theme={theme} />
      <Card theme={theme}>
        <View style={styles.rowBetween}>
          <View style={styles.flex}>
            <Text style={[styles.cardTitle, { color: theme.text }]}>{report.app.packageName}</Text>
            <Text style={[styles.body, { color: theme.muted }]}>
              {report.findings.length} finding candidates · {report.behaviorSignals.length} behavior signals · {report.analysisLimits.length} limits
            </Text>
          </View>
          <Pill label={reportSource} theme={theme} tone="warning" />
        </View>
        <PrimaryButton label="Lab에서 분석" onPress={() => onNavigate('lab')} theme={theme} variant="secondary" />
      </Card>

      <SectionTitle title="오늘의 균형" subtitle="읽기·회상·분석·연구를 함께 유지한다" theme={theme} />
      <Card theme={theme}>
        <View style={styles.balanceRow}>
          <Balance number="1" label="레슨" color={palette.primary} theme={theme} />
          <Balance number="5" label="회상" color={palette.warning} theme={theme} />
          <Balance number="1" label="미션" color={palette.success} theme={theme} />
          <Balance number="1" label="가설" color={palette.research} theme={theme} />
        </View>
        <View style={styles.buttonStack}>
          <PrimaryButton label="Lab 열기" onPress={() => onNavigate('lab')} theme={theme} />
          <PrimaryButton label="Research 열기" onPress={() => onNavigate('research')} theme={theme} variant="secondary" />
        </View>
      </Card>

      <Card theme={theme} style={{ backgroundColor: theme.primarySoft }}>
        <Text style={[styles.cardTitle, { color: theme.text }]}>안전 경계</Text>
        <Text style={[styles.body, { color: theme.muted }]}>
          앱은 synthetic/authorized artifact와 교육용 JSON을 다룬다. APK 실행, payload 배포,
          제3자 시스템 테스트를 자동화하지 않으며 model-only 가설을 실제 제품 finding으로 표시하지 않는다.
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
  flex: { flex: 1, gap: spacing.xs },
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
