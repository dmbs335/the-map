import React, { useMemo, useState } from 'react';
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
  Card,
  ChipButton,
  ListItemButton,
  ProgressBar,
  ScreenHeader,
  SearchInput,
  SectionTitle,
} from '../components/ui';

const curriculum = curriculumJson as CurriculumData;

export function LearnScreen({
  theme,
  onOpenLesson,
}: {
  theme: AppTheme;
  onOpenLesson: (lessonId: string) => void;
}): React.ReactElement {
  const { progress } = useLearning();
  const [selectedTrack, setSelectedTrack] = useState<string>('all');
  const [query, setQuery] = useState('');

  const normalizedQuery = query.trim().toLocaleLowerCase();
  const visibleTracks = useMemo(
    () =>
      curriculum.tracks.filter(
        (track) => selectedTrack === 'all' || track.id === selectedTrack,
      ),
    [selectedTrack],
  );

  return (
    <ScrollView
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      <ScreenHeader
        eyebrow="CURRICULUM"
        title="Android 보안 분석 로드맵"
        subtitle="APK 구조와 JADX부터 악성행위·동적 검증·웹 백엔드·semantic/formal 연구까지 끊김 없이 연결한다."
        theme={theme}
      />

      <SearchInput
        value={query}
        onChangeText={setQuery}
        placeholder="레슨·개념 검색"
        theme={theme}
      />

      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        contentContainerStyle={styles.chips}
      >
        <ChipButton
          label="전체"
          selected={selectedTrack === 'all'}
          onPress={() => setSelectedTrack('all')}
          theme={theme}
        />
        {curriculum.tracks.map((track) => (
          <ChipButton
            key={track.id}
            label={track.title}
            selected={selectedTrack === track.id}
            onPress={() => setSelectedTrack(track.id)}
            theme={theme}
          />
        ))}
      </ScrollView>

      {visibleTracks.map((track) => {
        const trackLessons = curriculum.lessons
          .filter((lesson) => lesson.trackId === track.id)
          .filter((lesson) => {
            if (!normalizedQuery) {
              return true;
            }
            const haystack = [
              lesson.title,
              lesson.summary,
              ...lesson.concepts,
            ]
              .join(' ')
              .toLocaleLowerCase();
            return haystack.includes(normalizedQuery);
          })
          .sort((left, right) => left.order - right.order);

        if (trackLessons.length === 0) {
          return null;
        }
        const allTrackLessons = curriculum.lessons.filter(
          (lesson) => lesson.trackId === track.id,
        );
        const completed = allTrackLessons.filter((lesson) =>
          progress.completedLessonIds.includes(lesson.id),
        ).length;
        const completion =
          allTrackLessons.length === 0 ? 0 : completed / allTrackLessons.length;

        return (
          <View key={track.id} style={styles.trackBlock}>
            <Card theme={theme} style={{ borderLeftColor: track.color, borderLeftWidth: 5 }}>
              <View style={styles.rowBetween}>
                <View style={styles.trackTitleBlock}>
                  <Text style={[styles.trackTitle, { color: theme.text }]}>
                    {track.title}
                  </Text>
                  <Text style={[styles.trackDescription, { color: theme.muted }]}>
                    {track.description}
                  </Text>
                </View>
                <Text style={[styles.trackMetric, { color: track.color }]}>
                  {completed}/{allTrackLessons.length}
                </Text>
              </View>
              <ProgressBar value={completion} theme={theme} />
            </Card>

            <View style={styles.lessonList}>
              {trackLessons.map((lesson) => {
                const completedLesson = progress.completedLessonIds.includes(
                  lesson.id,
                );
                const locked = !lesson.prerequisiteIds.every((id) =>
                  progress.completedLessonIds.includes(id),
                );
                return (
                  <ListItemButton
                    key={lesson.id}
                    title={`${lesson.order}. ${lesson.title}`}
                    subtitle={lesson.summary}
                    meta={`${lesson.minutes}분 · ${lesson.level} · ${lesson.evidenceBoundary}`}
                    onPress={() => onOpenLesson(lesson.id)}
                    theme={theme}
                    completed={completedLesson}
                    locked={locked}
                  />
                );
              })}
            </View>
          </View>
        );
      })}

      <SectionTitle
        title="학습 범위"
        subtitle={`${curriculum.tracks.length}개 트랙 · ${curriculum.lessons.length}개 레슨`}
        theme={theme}
      />
      <Card theme={theme}>
        <Text style={[styles.scopeText, { color: theme.muted }]}>
          Android 플랫폼, JADX 정적 분석, 컴포넌트/IPC, WebView, 데이터·TLS·Native,
          악성행위, 동적 검증, The Map 웹 보안, semantic differential,
          분산 권한, 자동 연구 발굴, 형식적 탐색 기반과 방어 엔지니어링을
          모두 포함한다.
        </Text>
      </Card>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  content: {
    gap: spacing.lg,
    padding: spacing.lg,
    paddingBottom: 120,
  },
  chips: { gap: spacing.sm, paddingRight: spacing.lg },
  trackBlock: { gap: spacing.md },
  rowBetween: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: spacing.md,
  },
  trackTitleBlock: { flex: 1, gap: spacing.xs },
  trackTitle: { fontSize: 19, fontWeight: '900' },
  trackDescription: { fontSize: 13, lineHeight: 19 },
  trackMetric: { fontSize: 17, fontWeight: '900' },
  lessonList: { gap: spacing.sm },
  scopeText: { fontSize: 14, lineHeight: 22 },
});
