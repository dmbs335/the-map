import React from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';

import labsJson from '../data/labs.json';
import curriculumJson from '../data/curriculum.json';
import { useLearning } from '../state/LearningContext';
import { spacing, type AppTheme } from '../theme';
import type { CurriculumData, PracticeData } from '../types';
import {
  BulletList,
  Card,
  EmptyState,
  Pill,
  PrimaryButton,
  ScreenHeader,
  SectionTitle,
  TextButton,
} from '../components/ui';

const practice = labsJson as PracticeData;
const curriculum = curriculumJson as CurriculumData;

export function MissionDetailScreen({
  missionId,
  theme,
  onBack,
  onOpenLesson,
}: {
  missionId: string;
  theme: AppTheme;
  onBack: () => void;
  onOpenLesson: (lessonId: string) => void;
}): React.ReactElement {
  const { progress, completeMission, reopenMission } = useLearning();
  const mission = practice.missions.find((candidate) => candidate.id === missionId);

  if (!mission) {
    return (
      <ScrollView contentContainerStyle={styles.content}>
        <TextButton label="‹ 연습" onPress={onBack} theme={theme} />
        <EmptyState title="연습을 찾지 못했어" detail={missionId} theme={theme} />
      </ScrollView>
    );
  }

  const completed = progress.completedMissionIds.includes(mission.id);
  const missing = mission.prerequisiteLessonIds.filter(
    (id) => !progress.completedLessonIds.includes(id),
  );

  return (
    <ScrollView
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      <TextButton label="‹ 연습" onPress={onBack} theme={theme} />
      <ScreenHeader
        eyebrow="SAFE PRACTICE"
        title={mission.title}
        subtitle={mission.summary}
        theme={theme}
      />
      <View style={styles.pills}>
        <Pill label={mission.level} theme={theme} tone="primary" />
        <Pill label={`${mission.minutes}분`} theme={theme} />
        <Pill label={mission.supportLevel} theme={theme} tone="research" />
      </View>

      {missing.length > 0 ? (
        <Card theme={theme}>
          <Text style={[styles.cardTitle, { color: theme.text }]}>먼저 끝낼 레슨</Text>
          {missing.map((id) => {
            const lesson = curriculum.lessons.find((item) => item.id === id);
            return (
              <TextButton
                key={id}
                label={lesson?.title ?? id}
                onPress={() => onOpenLesson(id)}
                theme={theme}
              />
            );
          })}
        </Card>
      ) : null}

      <SectionTitle title="목표" theme={theme} />
      <Card theme={theme}>
        <BulletList items={mission.objectives} theme={theme} />
      </Card>

      <SectionTitle title="진행 순서" theme={theme} />
      <Card theme={theme}>
        {mission.steps.map((step, index) => (
          <View key={`${index}-${step}`} style={styles.stepRow}>
            <View style={[styles.stepNumber, { backgroundColor: theme.primarySoft }]}>
              <Text style={[styles.stepNumberText, { color: theme.primary }]}>{index + 1}</Text>
            </View>
            <Text style={[styles.stepText, { color: theme.text }]}>{step}</Text>
          </View>
        ))}
      </Card>

      <SectionTitle title="확인할 결과" theme={theme} />
      <Card theme={theme}>
        <BulletList items={mission.expectedSignals} theme={theme} />
      </Card>

      <SectionTitle title="힌트" theme={theme} />
      <Card theme={theme}>
        <BulletList items={mission.hints} theme={theme} tone="warning" />
      </Card>

      <Card theme={theme} style={{ backgroundColor: theme.primarySoft }}>
        <Text style={[styles.cardTitle, { color: theme.text }]}>안전 범위</Text>
        <Text style={[styles.body, { color: theme.muted }]}>{mission.safetyNote}</Text>
      </Card>

      <PrimaryButton
        label={completed ? '완료 취소' : '연습 완료'}
        onPress={() =>
          completed ? reopenMission(mission.id) : completeMission(mission.id)
        }
        theme={theme}
        variant={completed ? 'secondary' : 'primary'}
        disabled={missing.length > 0}
      />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  content: { gap: spacing.lg, padding: spacing.lg, paddingBottom: 80 },
  pills: { flexDirection: 'row', flexWrap: 'wrap', gap: spacing.sm },
  cardTitle: { fontSize: 17, fontWeight: '900' },
  body: { fontSize: 14, lineHeight: 22 },
  stepRow: { flexDirection: 'row', alignItems: 'flex-start', gap: spacing.md },
  stepNumber: { width: 28, height: 28, borderRadius: 14, alignItems: 'center', justifyContent: 'center' },
  stepNumberText: { fontSize: 13, fontWeight: '900' },
  stepText: { flex: 1, fontSize: 14, lineHeight: 22 },
});
