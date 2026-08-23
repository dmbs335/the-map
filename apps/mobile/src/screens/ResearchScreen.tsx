import React from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';

import { researchConcepts } from '../content/researchConcepts';
import { palette, spacing, type AppTheme } from '../theme';
import {
  BulletList,
  Card,
  Pill,
  ScreenHeader,
  SectionTitle,
  TextButton,
} from '../components/ui';

export function ResearchScreen({
  theme,
  onOpenLesson,
}: {
  theme: AppTheme;
  onOpenLesson: (lessonId: string) => void;
}): React.ReactElement {
  return (
    <ScrollView
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      <ScreenHeader
        eyebrow="RESEARCH HABITS"
        title="사례 암기에서 질문 만드는 습관으로"
        subtitle="The Map의 사례를 관찰하고, 반박 가능한 가설을 만들고, 대조군과 재현으로 좁힌 뒤 다른 범주에 적용한다."
        theme={theme}
      />

      <View style={styles.statusGrid}>
        <StatusCard label="1. 관찰" value="무엇을 봤나" color={palette.primary} theme={theme} />
        <StatusCard label="2. 가설" value="왜 그랬나" color={palette.warning} theme={theme} />
        <StatusCard label="3. 검증" value="어떻게 틀릴까" color={palette.success} theme={theme} />
        <StatusCard label="4. 일반화" value="어디에 또 있나" color={palette.research} theme={theme} />
      </View>

      <Card theme={theme} style={{ backgroundColor: theme.primarySoft }}>
        <Text style={[styles.cardTitle, { color: theme.text }]}>핵심 원칙</Text>
        <Text style={[styles.body, { color: theme.muted }]}>
          특정 이론이나 도구의 용어를 외우는 것이 목적이 아니다. 서로 다른 사례를
          비교할 때 반복해서 쓸 수 있는 질문—누가 해석하는지, 무엇을 믿는지,
          시간이 흐른 뒤에도 판단이 유효한지, 어떤 증거가 결론을 지지하는지—를
          습관으로 만드는 것이 목적이다.
        </Text>
      </Card>

      <SectionTitle
        title="탐구를 돕는 8가지 질문"
        subtitle="각 카드는 The Map 커리큘럼의 실제 레슨으로 연결된다"
        theme={theme}
      />
      <View style={styles.list}>
        {researchConcepts.map((concept) => (
          <Card key={concept.id} theme={theme}>
            <View style={styles.rowBetween}>
              <Text style={[styles.cardTitle, { color: theme.text }]}>{concept.title}</Text>
              <Pill
                label={concept.status}
                theme={theme}
                tone={
                  concept.status === 'core'
                    ? 'success'
                    : concept.status === 'explore'
                      ? 'warning'
                      : 'research'
                }
              />
            </View>
            <Text style={[styles.body, { color: theme.muted }]}>{concept.summary}</Text>
            <Text style={[styles.why, { color: theme.text }]}>{concept.whyItMatters}</Text>
            <BulletList items={concept.checks} theme={theme} />
            <TextButton
              label="관련 레슨 열기"
              onPress={() => onOpenLesson(concept.lessonId)}
              theme={theme}
            />
          </Card>
        ))}
      </View>

      <SectionTitle title="한 사례를 끝까지 보는 순서" theme={theme} />
      <Card theme={theme}>
        <Text style={[styles.pipeline, { color: theme.text }]}>The Map 사례와 1차 자료</Text>
        <Text style={[styles.arrow, { color: theme.muted }]}>↓</Text>
        <Text style={[styles.pipeline, { color: theme.text }]}>직접 관찰한 사실</Text>
        <Text style={[styles.arrow, { color: theme.muted }]}>↓</Text>
        <Text style={[styles.pipeline, { color: theme.text }]}>반박 가능한 가설</Text>
        <Text style={[styles.arrow, { color: theme.muted }]}>↓</Text>
        <Text style={[styles.pipeline, { color: theme.text }]}>정상 대조군과 최소 변형</Text>
        <Text style={[styles.arrow, { color: theme.muted }]}>↓</Text>
        <Text style={[styles.pipeline, { color: theme.text }]}>재현 결과와 남은 가정</Text>
        <Text style={[styles.arrow, { color: theme.muted }]}>↓</Text>
        <Text style={[styles.pipeline, { color: theme.text }]}>다른 범주에 던질 질문</Text>
      </Card>
    </ScrollView>
  );
}

function StatusCard({
  label,
  value,
  color,
  theme,
}: {
  label: string;
  value: string;
  color: string;
  theme: AppTheme;
}): React.ReactElement {
  return (
    <Card theme={theme} style={styles.statusCard}>
      <Text style={[styles.statusValue, { color }]}>{value}</Text>
      <Text style={[styles.statusLabel, { color: theme.muted }]}>{label}</Text>
    </Card>
  );
}

const styles = StyleSheet.create({
  content: { gap: spacing.lg, padding: spacing.lg, paddingBottom: 120 },
  statusGrid: { flexDirection: 'row', flexWrap: 'wrap', gap: spacing.sm },
  statusCard: { width: '48%', minHeight: 90, justifyContent: 'center' },
  statusValue: { fontSize: 18, fontWeight: '900' },
  statusLabel: { fontSize: 12, lineHeight: 18 },
  list: { gap: spacing.md },
  rowBetween: { flexDirection: 'row', alignItems: 'flex-start', justifyContent: 'space-between', gap: spacing.md },
  cardTitle: { flex: 1, fontSize: 17, fontWeight: '900' },
  body: { fontSize: 14, lineHeight: 22 },
  why: { fontSize: 14, lineHeight: 22, fontWeight: '700' },
  pipeline: { fontSize: 15, fontWeight: '800', textAlign: 'center', paddingVertical: spacing.xs },
  arrow: { fontSize: 20, textAlign: 'center' },
});
