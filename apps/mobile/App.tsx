import React, { useState } from 'react';
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  View,
  useColorScheme,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';

import { AnalysisProvider, useAnalysis } from './src/state/AnalysisContext';
import { LearningProvider, useLearning } from './src/state/LearningContext';
import { themeFor, spacing, type AppTheme } from './src/theme';
import type { TabId } from './src/types';
import { TodayScreen } from './src/screens/TodayScreen';
import { LearnScreen } from './src/screens/LearnScreen';
import { LibraryScreen } from './src/screens/LibraryScreen';
import { LabScreen } from './src/screens/LabScreen';
import { ResearchScreen } from './src/screens/ResearchScreen';
import { LessonDetailScreen } from './src/screens/LessonDetailScreen';
import { TopicDetailScreen } from './src/screens/TopicDetailScreen';
import { MissionDetailScreen } from './src/screens/MissionDetailScreen';

const tabs: Array<{ id: TabId; label: string; icon: string }> = [
  { id: 'today', label: '오늘', icon: '⌂' },
  { id: 'learn', label: '학습', icon: '◫' },
  { id: 'library', label: 'Map', icon: '◇' },
  { id: 'lab', label: 'Lab', icon: '⌁' },
  { id: 'research', label: '연구', icon: '△' },
];

export default function App(): React.ReactElement {
  const scheme = useColorScheme();
  const theme = themeFor(scheme);

  return (
    <SafeAreaProvider>
      <LearningProvider>
        <AnalysisProvider>
          <StatusBar style={theme.isDark ? 'light' : 'dark'} />
          <AppShell theme={theme} />
        </AnalysisProvider>
      </LearningProvider>
    </SafeAreaProvider>
  );
}

function AppShell({ theme }: { theme: AppTheme }): React.ReactElement {
  const learning = useLearning();
  const analysis = useAnalysis();
  const [tab, setTab] = useState<TabId>('today');
  const [lessonId, setLessonId] = useState<string | null>(null);
  const [topicId, setTopicId] = useState<string | null>(null);
  const [missionId, setMissionId] = useState<string | null>(null);

  const clearDetail = (): void => {
    setLessonId(null);
    setTopicId(null);
    setMissionId(null);
  };
  const navigate = (next: TabId): void => {
    clearDetail();
    setTab(next);
  };
  const openLesson = (id: string): void => {
    setTopicId(null);
    setMissionId(null);
    setLessonId(id);
  };
  const openTopic = (id: string): void => {
    setLessonId(null);
    setMissionId(null);
    setTopicId(id);
  };
  const openMission = (id: string): void => {
    setLessonId(null);
    setTopicId(null);
    setMissionId(id);
  };

  if (!learning.hydrated || !analysis.hydrated) {
    return (
      <SafeAreaView style={[styles.safe, { backgroundColor: theme.background }]}>
        <View style={styles.loading}>
          <ActivityIndicator size="large" color={theme.primary} />
          <Text style={[styles.loadingText, { color: theme.muted }]}>
            오프라인 학습 상태와 분석 artifact를 불러오는 중
          </Text>
        </View>
      </SafeAreaView>
    );
  }

  let content: React.ReactElement;
  if (lessonId) {
    content = (
      <LessonDetailScreen
        lessonId={lessonId}
        theme={theme}
        onBack={() => setLessonId(null)}
        onOpenLesson={openLesson}
      />
    );
  } else if (topicId) {
    content = (
      <TopicDetailScreen
        topicId={topicId}
        theme={theme}
        onBack={() => setTopicId(null)}
      />
    );
  } else if (missionId) {
    content = (
      <MissionDetailScreen
        missionId={missionId}
        theme={theme}
        onBack={() => setMissionId(null)}
        onOpenLesson={openLesson}
      />
    );
  } else {
    switch (tab) {
      case 'learn':
        content = <LearnScreen theme={theme} onOpenLesson={openLesson} />;
        break;
      case 'library':
        content = <LibraryScreen theme={theme} onOpenTopic={openTopic} />;
        break;
      case 'lab':
        content = (
          <LabScreen
            theme={theme}
            onOpenMission={openMission}
            onOpenLesson={openLesson}
          />
        );
        break;
      case 'research':
        content = <ResearchScreen theme={theme} onOpenLesson={openLesson} />;
        break;
      case 'today':
      default:
        content = (
          <TodayScreen
            theme={theme}
            onOpenLesson={openLesson}
            onOpenMission={openMission}
            onNavigate={navigate}
          />
        );
        break;
    }
  }

  const detailOpen = Boolean(lessonId || topicId || missionId);
  return (
    <SafeAreaView
      edges={['top', 'left', 'right']}
      style={[styles.safe, { backgroundColor: theme.background }]}
    >
      <View style={styles.content}>{content}</View>
      {detailOpen ? null : (
        <SafeAreaView
          edges={['bottom']}
          style={[
            styles.navSafe,
            {
              backgroundColor: theme.surface,
              borderTopColor: theme.border,
            },
          ]}
        >
          <View style={styles.nav}>
            {tabs.map((item) => {
              const selected = tab === item.id;
              return (
                <Pressable
                  key={item.id}
                  accessibilityRole="tab"
                  accessibilityState={{ selected }}
                  onPress={() => navigate(item.id)}
                  style={({ pressed }: { pressed: boolean }) => [
                    styles.navItem,
                    {
                      backgroundColor: selected ? theme.primarySoft : 'transparent',
                      opacity: pressed ? 0.65 : 1,
                    },
                  ]}
                >
                  <Text style={[styles.navIcon, { color: selected ? theme.primary : theme.muted }]}>
                    {item.icon}
                  </Text>
                  <Text style={[styles.navLabel, { color: selected ? theme.primary : theme.muted }]}>
                    {item.label}
                  </Text>
                </Pressable>
              );
            })}
          </View>
        </SafeAreaView>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1 },
  content: { flex: 1 },
  loading: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: spacing.lg, padding: spacing.xl },
  loadingText: { fontSize: 14, lineHeight: 20, textAlign: 'center' },
  navSafe: { borderTopWidth: StyleSheet.hairlineWidth },
  nav: { minHeight: 64, flexDirection: 'row', paddingHorizontal: spacing.sm, paddingTop: spacing.xs },
  navItem: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 2, borderRadius: 12, marginHorizontal: 2, paddingVertical: spacing.xs },
  navIcon: { fontSize: 20, fontWeight: '900' },
  navLabel: { fontSize: 11, fontWeight: '800' },
});
