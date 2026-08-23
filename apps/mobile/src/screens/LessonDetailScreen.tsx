import React from 'react';
import {
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import curriculumJson from '../data/curriculum.json';
import { useLearning } from '../state/LearningContext';
import { spacing, type AppTheme } from '../theme';
import type { CurriculumData } from '../types';
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

const curriculum = curriculumJson as CurriculumData;

export function LessonDetailScreen({
  lessonId,
  theme,
  onBack,
  onOpenLesson,
}: {
  lessonId: string;
  theme: AppTheme;
  onBack: () => void;
  onOpenLesson: (lessonId: string) => void;
}): React.ReactElement {
  const { progress, completeLesson, reopenLesson } = useLearning();
  const lesson = curriculum.lessons.find((candidate) => candidate.id === lessonId);

  if (!lesson) {
    return (
      <ScrollView contentContainerStyle={styles.content}>
        <TextButton label="‹ 돌아가기" onPress={onBack} theme={theme} />
        <EmptyState
          title="레슨을 찾지 못했어"
          detail={lessonId}
          theme={theme}
        />
      </ScrollView>
    );
  }

  const track = curriculum.tracks.find((candidate) => candidate.id === lesson.trackId);
  const completed = progress.completedLessonIds.includes(lesson.id);
  const missingPrerequisites = lesson.prerequisiteIds.filter(
    (id) => !progress.completedLessonIds.includes(id),
  );

  return (
    <ScrollView
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      <TextButton label="‹ 커리큘럼" onPress={onBack} theme={theme} />
      <ScreenHeader
        eyebrow={track?.title ?? lesson.trackId}
        title={lesson.title}
        subtitle={lesson.summary}
        theme={theme}
      />

      <View style={styles.pills}>
        <Pill label={lesson.level} theme={theme} tone="primary" />
        <Pill label={`${lesson.minutes}분`} theme={theme} />
        <Pill label={lesson.supportLevel} theme={theme} tone="research" />
        <Pill label={lesson.practiceType} theme={theme} tone="success" />
      </View>

      {missingPrerequisites.length > 0 ? (
        <Card theme={theme} style={{ backgroundColor: theme.surfaceAlt }}>
          <Text style={[styles.cardTitle, { color: theme.text }]}>선행 레슨</Text>
          {missingPrerequisites.map((id) => {
            const prerequisite = curriculum.lessons.find((item) => item.id === id);
            return (
              <TextButton
                key={id}
                label={prerequisite?.title ?? id}
                onPress={() => onOpenLesson(id)}
                theme={theme}
              />
            );
          })}
        </Card>
      ) : null}

      <SectionTitle title="학습 목표" theme={theme} />
      <Card theme={theme}>
        <BulletList items={lesson.objectives} theme={theme} />
      </Card>

      <SectionTitle title="핵심 개념" theme={theme} />
      <View style={styles.wrap}>
        {lesson.concepts.map((concept) => (
          <Pill key={concept} label={concept} theme={theme} tone="neutral" />
        ))}
      </View>

      <SectionTitle
        title="스스로 확인할 질문"
        subtitle="답을 외우기보다 원문과 사례에서 근거를 찾아본다"
        theme={theme}
      />
      <Card theme={theme}>
        <BulletList items={lesson.keyQuestions} theme={theme} />
      </Card>

      <SectionTitle title="관련 범주와 소스" theme={theme} />
      <Card theme={theme}>
        {lesson.relatedCategories.length > 0 ? (
          <BulletList
            items={lesson.relatedCategories.map((item) => `범주: ${item}`)}
            theme={theme}
          />
        ) : null}
        {lesson.sourceRefs.length > 0 ? (
          <BulletList
            items={lesson.sourceRefs.map((item) => `참조: ${item}`)}
            theme={theme}
          />
        ) : (
          <Text style={[styles.body, { color: theme.muted }]}>별도 소스 참조 없음</Text>
        )}
      </Card>

      <Card theme={theme} style={{ backgroundColor: theme.primarySoft }}>
        <Text style={[styles.cardTitle, { color: theme.text }]}>근거 수준과 안전 범위</Text>
        <Text style={[styles.body, { color: theme.muted }]}>
          현재 레슨의 근거 수준은 {lesson.supportLevel}이다. {lesson.safetyNote}
        </Text>
      </Card>

      <PrimaryButton
        label={completed ? '완료 취소' : '레슨 완료'}
        onPress={() =>
          completed ? reopenLesson(lesson.id) : completeLesson(lesson.id)
        }
        theme={theme}
        variant={completed ? 'secondary' : 'primary'}
        disabled={missingPrerequisites.length > 0}
      />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  content: { gap: spacing.lg, padding: spacing.lg, paddingBottom: 80 },
  pills: { flexDirection: 'row', flexWrap: 'wrap', gap: spacing.sm },
  wrap: { flexDirection: 'row', flexWrap: 'wrap', gap: spacing.sm },
  cardTitle: { fontSize: 17, fontWeight: '900' },
  body: { fontSize: 14, lineHeight: 22 },
});
