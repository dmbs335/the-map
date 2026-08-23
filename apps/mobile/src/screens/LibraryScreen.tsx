import React, { useMemo, useState } from 'react';
import {
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
  Card,
  ChipButton,
  EmptyState,
  ListItemButton,
  ScreenHeader,
  SearchInput,
} from '../components/ui';

const catalog = catalogJson as CatalogData;

type Scope = 'all' | 'bookmarked' | 'verified';

export function LibraryScreen({
  theme,
  onOpenTopic,
}: {
  theme: AppTheme;
  onOpenTopic: (topicId: string) => void;
}): React.ReactElement {
  const { progress } = useLearning();
  const [query, setQuery] = useState('');
  const [categoryId, setCategoryId] = useState('all');
  const [scope, setScope] = useState<Scope>('all');

  const topics = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase();
    return catalog.topics.filter((topic) => {
      if (categoryId !== 'all' && topic.categoryId !== categoryId) {
        return false;
      }
      if (scope === 'bookmarked' && !progress.bookmarkedTopicIds.includes(topic.id)) {
        return false;
      }
      if (scope === 'verified' && !topic.verified) {
        return false;
      }
      if (!normalized) {
        return true;
      }
      return [
        topic.title,
        topic.summary,
        topic.categoryTitle,
        topic.path,
        ...topic.tags,
      ]
        .join(' ')
        .toLocaleLowerCase()
        .includes(normalized);
    });
  }, [query, categoryId, scope, progress.bookmarkedTopicIds]);

  return (
    <ScrollView
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      <ScreenHeader
        eyebrow="THE MAP"
        title="웹 보안 지식 지도"
        subtitle="13개 범주의 원문을 검색하고, 북마크하고, 커리큘럼과 함께 교차해서 읽는다."
        theme={theme}
      />

      <View style={styles.metrics}>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{catalog.stats.topicCount}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>전체 문서</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{catalog.stats.categoryCount}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>범주</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{catalog.stats.verifiedCount}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>검증 표시</Text>
        </Card>
      </View>

      <SearchInput
        value={query}
        onChangeText={setQuery}
        placeholder="취약점, parser, framework, researcher 검색"
        theme={theme}
      />

      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={styles.chips}>
        {(['all', 'bookmarked', 'verified'] as Scope[]).map((item) => (
          <ChipButton
            key={item}
            label={item === 'all' ? '전체' : item === 'bookmarked' ? '북마크' : '검증 표시'}
            selected={scope === item}
            onPress={() => setScope(item)}
            theme={theme}
          />
        ))}
      </ScrollView>

      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={styles.chips}>
        <ChipButton
          label="모든 범주"
          selected={categoryId === 'all'}
          onPress={() => setCategoryId('all')}
          theme={theme}
        />
        {catalog.categories.map((category) => (
          <ChipButton
            key={category.id}
            label={`${category.title} ${category.topicCount}`}
            selected={categoryId === category.id}
            onPress={() => setCategoryId(category.id)}
            theme={theme}
          />
        ))}
      </ScrollView>

      <Text style={[styles.resultCount, { color: theme.muted }]}>{topics.length}개 결과</Text>
      <View style={styles.list}>
        {topics.map((topic) => (
          <ListItemButton
            key={topic.id}
            title={topic.title}
            subtitle={topic.summary}
            meta={`${topic.categoryTitle}${topic.verified ? ' · verified list' : ''}`}
            onPress={() => onOpenTopic(topic.id)}
            theme={theme}
            completed={progress.bookmarkedTopicIds.includes(topic.id)}
          />
        ))}
      </View>
      {topics.length === 0 ? (
        <EmptyState
          title="조건에 맞는 문서가 없어"
          detail="검색어 또는 필터를 줄여봐."
          theme={theme}
        />
      ) : null}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  content: { gap: spacing.lg, padding: spacing.lg, paddingBottom: 120 },
  metrics: { flexDirection: 'row', gap: spacing.sm },
  metricCard: { flex: 1, alignItems: 'center', paddingHorizontal: spacing.sm },
  metric: { fontSize: 20, fontWeight: '900' },
  small: { fontSize: 11, textAlign: 'center' },
  chips: { gap: spacing.sm, paddingRight: spacing.lg },
  resultCount: { fontSize: 13, fontWeight: '700' },
  list: { gap: spacing.sm },
});
