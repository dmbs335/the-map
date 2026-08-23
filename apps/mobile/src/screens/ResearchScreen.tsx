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
        eyebrow="FORMAL RESEARCH"
        title="취약점 family를 넘어 연구 공간으로"
        subtitle="semantic differential에서 proof-carrying harness와 future search environment까지, 현재 구현된 것과 아직 non-goal인 것을 분리한다."
        theme={theme}
      />

      <View style={styles.statusGrid}>
        <StatusCard label="연구 주제 생성" value="운영" color={palette.success} theme={theme} />
        <StatusCard label="Semantic theory" value="형식화" color={palette.research} theme={theme} />
        <StatusCard label="Android/JADX bridge" value="학습 어댑터" color={palette.primary} theme={theme} />
        <StatusCard label="MCTS / RL" value="미구현" color={palette.warning} theme={theme} />
      </View>

      <Card theme={theme} style={{ backgroundColor: theme.primarySoft }}>
        <Text style={[styles.cardTitle, { color: theme.text }]}>현재 경계</Text>
        <Text style={[styles.body, { color: theme.muted }]}>
          앱은 state/action/transition/invariant/refinement/finite closure를 학습한다.
          MCTS, reinforcement learning, policy/value network, learned reward는 구현하지
          않고 future optimizer의 전제 조건으로만 다룬다.
        </Text>
      </Card>

      <SectionTitle
        title="핵심 개념"
        subtitle="각 카드를 열면 연결된 커리큘럼 레슨으로 이동한다"
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
                  concept.status === 'operational'
                    ? 'success'
                    : concept.status === 'future'
                      ? 'warning'
                      : 'research'
                }
              />
            </View>
            <Text style={[styles.body, { color: theme.muted }]}>{concept.summary}</Text>
            <Text style={[styles.why, { color: theme.text }]}>{concept.whyItMatters}</Text>
            <BulletList items={concept.checks} theme={theme} />
            <TextButton
              label="레슨 열기"
              onPress={() => onOpenLesson(concept.lessonId)}
              theme={theme}
            />
          </Card>
        ))}
      </View>

      <SectionTitle title="Android에 적용할 연구 질문" theme={theme} />
      <Card theme={theme}>
        <BulletList
          items={[
            'PendingIntent·background work의 authorization certificate는 어떤 lifecycle transition까지 유효한가?',
            'Binder caller identity가 Intent extra, Bundle, database row로 바뀔 때 provenance가 어디서 사라지는가?',
            'Manifest permission validator와 runtime component consumer가 같은 capability boundary를 보는가?',
            'WebView에서 확인한 origin과 native bridge가 사용한 document authority가 같은가?',
            'JADX call graph가 끊긴 reflection/native/dynamic-loading edge를 어떤 evidence로 안전하게 보완할 수 있는가?',
            '악성행위 분류에서 permission/API signature와 실제 capability trace를 어떻게 분리할 것인가?',
          ]}
          theme={theme}
        />
      </Card>

      <SectionTitle title="연구 결과의 승격 경로" theme={theme} />
      <Card theme={theme}>
        <Text style={[styles.pipeline, { color: theme.text }]}>Research coordinate</Text>
        <Text style={[styles.arrow, { color: theme.muted }]}>↓</Text>
        <Text style={[styles.pipeline, { color: theme.text }]}>Semantic state & mutation trace</Text>
        <Text style={[styles.arrow, { color: theme.muted }]}>↓</Text>
        <Text style={[styles.pipeline, { color: theme.text }]}>JADX/static evidence + assumptions</Text>
        <Text style={[styles.arrow, { color: theme.muted }]}>↓</Text>
        <Text style={[styles.pipeline, { color: theme.text }]}>Local baseline / adversarial / mitigation</Text>
        <Text style={[styles.arrow, { color: theme.muted }]}>↓</Text>
        <Text style={[styles.pipeline, { color: theme.text }]}>Evidence-bound checked finding</Text>
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
