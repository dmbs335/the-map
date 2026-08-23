import React from 'react';
import {
  Linking,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import catalogJson from '../data/generated/catalog.json';
import { useLearning } from '../state/LearningContext';
import { spacing, type AppTheme } from '../theme';
import type { CatalogData } from '../types';
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

const catalog = catalogJson as CatalogData;

export function TopicDetailScreen({
  topicId,
  theme,
  onBack,
}: {
  topicId: string;
  theme: AppTheme;
  onBack: () => void;
}): React.ReactElement {
  const { progress, toggleBookmark } = useLearning();
  const topic = catalog.topics.find((candidate) => candidate.id === topicId);

  if (!topic) {
    return (
      <ScrollView contentContainerStyle={styles.content}>
        <TextButton label="‹ 지식 지도" onPress={onBack} theme={theme} />
        <EmptyState title="문서를 찾지 못했어" detail={topicId} theme={theme} />
      </ScrollView>
    );
  }

  const bookmarked = progress.bookmarkedTopicIds.includes(topic.id);

  return (
    <ScrollView
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      <TextButton label="‹ 지식 지도" onPress={onBack} theme={theme} />
      <ScreenHeader
        eyebrow={topic.categoryTitle}
        title={topic.title}
        subtitle={topic.summary}
        theme={theme}
      />
      <View style={styles.pills}>
        {topic.verified ? (
          <Pill label="VERIFIED_ONLY 포함" theme={theme} tone="success" />
        ) : (
          <Pill label="reference" theme={theme} tone="neutral" />
        )}
        <Pill label={topic.path} theme={theme} tone="primary" />
      </View>

      <SectionTitle title="검색 태그" theme={theme} />
      <View style={styles.pills}>
        {topic.tags.length > 0 ? (
          topic.tags.map((tag) => <Pill key={tag} label={tag} theme={theme} />)
        ) : (
          <Text style={[styles.body, { color: theme.muted }]}>자동 태그 없음</Text>
        )}
      </View>

      <SectionTitle title="학습할 때 확인할 것" theme={theme} />
      <Card theme={theme}>
        <BulletList
          items={[
            '어떤 mutation target이 바뀌는가?',
            'validator와 consumer 사이에 어떤 discrepancy가 생기는가?',
            '공격자가 실제로 얻는 capability는 무엇인가?',
            '어떤 evidence boundary까지 확인됐는가?',
            '모바일 앱·WebView·백엔드와 연결되는 지점이 있는가?',
          ]}
          theme={theme}
        />
      </Card>

      <Card theme={theme} style={{ backgroundColor: theme.primarySoft }}>
        <Text style={[styles.cardTitle, { color: theme.text }]}>문서 해석 경계</Text>
        <Text style={[styles.body, { color: theme.muted }]}>
          이 앱의 catalog는 제목·요약·태그를 offline index로 제공한다. 전체 원문과
          최신 수정 내용은 저장소 문서에서 확인하며, 문서 존재만으로 실제 제품
          취약점을 주장하지 않는다.
        </Text>
      </Card>

      <PrimaryButton
        label={bookmarked ? '북마크 해제' : '북마크 추가'}
        onPress={() => toggleBookmark(topic.id)}
        theme={theme}
        variant={bookmarked ? 'secondary' : 'primary'}
      />
      <PrimaryButton
        label="GitHub 원문 열기"
        onPress={() => {
          Linking.openURL(topic.sourceUrl).catch((error) => {
            console.warn('Unable to open source URL', error);
          });
        }}
        theme={theme}
        variant="secondary"
      />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  content: { gap: spacing.lg, padding: spacing.lg, paddingBottom: 80 },
  pills: { flexDirection: 'row', flexWrap: 'wrap', gap: spacing.sm },
  cardTitle: { fontSize: 17, fontWeight: '900' },
  body: { fontSize: 14, lineHeight: 22 },
});
