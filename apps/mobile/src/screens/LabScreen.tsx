import React, { useMemo, useState } from 'react';
import {
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import labsJson from '../data/labs.json';
import quizJson from '../data/quizzes.json';
import { findingPriorityScore, reportCoverage } from '../analysis/report';
import { useAnalysis } from '../state/AnalysisContext';
import { useLearning } from '../state/LearningContext';
import { palette, spacing, type AppTheme } from '../theme';
import type {
  AnalysisSeverity,
  JadxFinding,
  LabData,
  QuizData,
  ReviewRating,
} from '../types';
import {
  BulletList,
  Card,
  KeyValueRow,
  ListItemButton,
  Pill,
  PrimaryButton,
  ScreenHeader,
  SectionTitle,
  TextButton,
} from '../components/ui';

const labs = labsJson as LabData;
const quizzes = quizJson as QuizData;

const severityTone: Record<
  AnalysisSeverity,
  'neutral' | 'primary' | 'warning' | 'danger'
> = {
  info: 'neutral',
  low: 'primary',
  medium: 'warning',
  high: 'danger',
  critical: 'danger',
};

export function LabScreen({
  theme,
  onOpenMission,
  onOpenLesson,
}: {
  theme: AppTheme;
  onOpenMission: (missionId: string) => void;
  onOpenLesson: (lessonId: string) => void;
}): React.ReactElement {
  const {
    report,
    reportSource,
    importError,
    importing,
    importReport,
    useSampleReport,
    clearImportError,
  } = useAnalysis();
  const {
    progress,
    dueQuizIds,
    rateQuiz,
  } = useLearning();
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    null,
  );
  const [quizIndex, setQuizIndex] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);

  const coverage = useMemo(() => reportCoverage(report), [report]);
  const findings = useMemo(
    () =>
      [...report.findings].sort(
        (left, right) =>
          findingPriorityScore(
            right.severity,
            right.confidence,
            right.evidence.length,
          ) -
          findingPriorityScore(
            left.severity,
            left.confidence,
            left.evidence.length,
          ),
      ),
    [report.findings],
  );
  const selectedFinding = findings.find(
    (finding) => finding.id === selectedFindingId,
  );

  const dueQuestions = useMemo(() => {
    const dueSet = new Set(dueQuizIds);
    const due = quizzes.questions.filter((question) => dueSet.has(question.id));
    return due.length > 0 ? due : quizzes.questions.slice(0, 12);
  }, [dueQuizIds]);
  const currentQuestion = dueQuestions[quizIndex % Math.max(1, dueQuestions.length)];

  const submitRating = (rating: ReviewRating): void => {
    if (!currentQuestion) {
      return;
    }
    rateQuiz(currentQuestion.id, rating);
    setSelectedAnswer(null);
    setQuizIndex((current) => current + 1);
  };

  return (
    <ScrollView
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      <ScreenHeader
        eyebrow="JADX LEARNING LAB"
        title="관찰 → 가설 → 검증"
        subtitle="JADX export report를 가져오거나 synthetic report로 Android 공격면·악성행위·semantic invariant를 안전하게 연습한다."
        theme={theme}
      />

      <Card theme={theme}>
        <View style={styles.rowBetween}>
          <View style={styles.flex}>
            <Text style={[styles.cardTitle, { color: theme.text }]}>분석 Artifact</Text>
            <Text style={[styles.body, { color: theme.muted }]}>
              {reportSource === 'sample' ? '교육용 synthetic report' : '로컬에서 가져온 report'}
            </Text>
          </View>
          <Pill
            label={reportSource === 'sample' ? 'SAMPLE' : 'IMPORTED'}
            theme={theme}
            tone={reportSource === 'sample' ? 'research' : 'success'}
          />
        </View>
        <KeyValueRow label="Package" value={report.app.packageName} theme={theme} />
        <KeyValueRow label="Version" value={`${report.app.versionName} (${report.app.versionCode})`} theme={theme} />
        <KeyValueRow label="SDK" value={`${report.app.minSdk} → ${report.app.targetSdk}`} theme={theme} />
        <View style={styles.buttonRow}>
          <PrimaryButton
            label={importing ? '가져오는 중' : 'JADX JSON 가져오기'}
            onPress={() => {
              importReport().catch((error) => console.warn(error));
            }}
            theme={theme}
            disabled={importing}
          />
          <PrimaryButton
            label="샘플로 복원"
            onPress={() => {
              useSampleReport().catch((error) => console.warn(error));
            }}
            theme={theme}
            variant="secondary"
          />
        </View>
        {importError ? (
          <Card theme={theme} style={{ backgroundColor: palette.dangerSoft }}>
            <Text style={[styles.body, { color: palette.danger }]}>{importError}</Text>
            <TextButton label="닫기" onPress={clearImportError} theme={theme} />
          </Card>
        ) : null}
      </Card>

      <View style={styles.metrics}>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{report.summary.exportedComponentCount}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>exported</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{report.findings.length}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>후보</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{report.behaviorSignals.length}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>행동 신호</Text>
        </Card>
        <Card theme={theme} style={styles.metricCard}>
          <Text style={[styles.metric, { color: theme.text }]}>{coverage.limits}</Text>
          <Text style={[styles.small, { color: theme.muted }]}>분석 한계</Text>
        </Card>
      </View>

      <SectionTitle
        title="우선 검토 후보"
        subtitle="severity·confidence·evidence 수로 정렬하지만 점수는 finding 확정이 아니다"
        theme={theme}
      />
      <View style={styles.list}>
        {findings.map((finding) => (
          <Pressable
            key={finding.id}
            onPress={() =>
              setSelectedFindingId((current) =>
                current === finding.id ? null : finding.id,
              )
            }
            style={({ pressed }: { pressed: boolean }) => ({ opacity: pressed ? 0.7 : 1 })}
          >
            <Card theme={theme}>
              <View style={styles.rowBetween}>
                <View style={styles.flex}>
                  <Text style={[styles.findingTitle, { color: theme.text }]}>
                    {finding.title}
                  </Text>
                  <Text style={[styles.small, { color: theme.muted }]}>
                    {finding.category} · confidence {finding.confidence}
                  </Text>
                </View>
                <Pill
                  label={finding.severity}
                  theme={theme}
                  tone={severityTone[finding.severity]}
                />
              </View>
              <Text numberOfLines={3} style={[styles.body, { color: theme.muted }]}>
                {finding.description}
              </Text>
              <View style={styles.pills}>
                <Pill label={finding.evidenceBoundary} theme={theme} tone="research" />
                <Pill label={`${finding.evidence.length} evidence`} theme={theme} />
              </View>
            </Card>
          </Pressable>
        ))}
      </View>

      {selectedFinding ? (
        <FindingDetail finding={selectedFinding} theme={theme} onOpenLesson={onOpenLesson} />
      ) : null}

      <SectionTitle
        title="악성행위 가설"
        subtitle="단일 API가 아니라 trigger·behavior·capability 조합으로 읽는다"
        theme={theme}
      />
      <View style={styles.list}>
        {report.behaviorSignals.map((signal) => (
          <Card key={signal.id} theme={theme}>
            <View style={styles.rowBetween}>
              <Text style={[styles.findingTitle, { color: theme.text }]}>{signal.title}</Text>
              <Pill label={signal.confidence} theme={theme} tone="warning" />
            </View>
            <Text style={[styles.body, { color: theme.muted }]}>{signal.description}</Text>
            <BulletList
              items={[
                `capability: ${signal.capabilities.join(', ') || '미정'}`,
                `benign alternative: ${signal.benignExplanations.join(', ') || '없음'}`,
              ]}
              theme={theme}
            />
          </Card>
        ))}
      </View>

      <SectionTitle
        title="분석 미션"
        subtitle={`${progress.completedMissionIds.length}/${labs.missions.length} 완료`}
        theme={theme}
      />
      <View style={styles.list}>
        {labs.missions.map((mission) => {
          const locked = !mission.prerequisiteLessonIds.every((id) =>
            progress.completedLessonIds.includes(id),
          );
          return (
            <ListItemButton
              key={mission.id}
              title={mission.title}
              subtitle={mission.summary}
              meta={`${mission.minutes}분 · ${mission.level} · ${mission.evidenceBoundary}`}
              onPress={() => onOpenMission(mission.id)}
              theme={theme}
              completed={progress.completedMissionIds.includes(mission.id)}
              locked={locked}
            />
          );
        })}
      </View>

      <SectionTitle
        title="회상 복습"
        subtitle={`${dueQuizIds.length}개 due · 답을 고른 뒤 기억 난이도를 평가한다`}
        theme={theme}
      />
      {currentQuestion ? (
        <Card theme={theme}>
          <Pill label={currentQuestion.kind} theme={theme} tone="primary" />
          <Text style={[styles.quizPrompt, { color: theme.text }]}>
            {currentQuestion.prompt}
          </Text>
          <View style={styles.answerList}>
            {currentQuestion.options.map((option, index) => {
              const selected = selectedAnswer === index;
              const correct = currentQuestion.answerIndex === index;
              const showResult = selectedAnswer !== null;
              const borderColor =
                showResult && correct
                  ? palette.success
                  : showResult && selected
                    ? palette.danger
                    : theme.border;
              return (
                <Pressable
                  key={`${index}-${option}`}
                  disabled={showResult}
                  onPress={() => setSelectedAnswer(index)}
                  style={({ pressed }: { pressed: boolean }) => [
                    styles.answer,
                    {
                      backgroundColor: theme.surfaceAlt,
                      borderColor,
                      opacity: pressed ? 0.7 : 1,
                    },
                  ]}
                >
                  <Text style={[styles.answerText, { color: theme.text }]}>
                    {index + 1}. {option}
                  </Text>
                </Pressable>
              );
            })}
          </View>
          {selectedAnswer !== null ? (
            <View style={styles.explanation}>
              <Text
                style={[
                  styles.result,
                  {
                    color:
                      selectedAnswer === currentQuestion.answerIndex
                        ? palette.success
                        : palette.danger,
                  },
                ]}
              >
                {selectedAnswer === currentQuestion.answerIndex ? '정답' : '다시 연결해보자'}
              </Text>
              <Text style={[styles.body, { color: theme.muted }]}>
                {currentQuestion.explanation}
              </Text>
              <Text style={[styles.small, { color: theme.muted }]}>기억 정도</Text>
              <View style={styles.ratingRow}>
                {([0, 1, 2, 3] as ReviewRating[]).map((rating) => (
                  <PrimaryButton
                    key={rating}
                    label={['모름', '어려움', '보통', '확실'][rating] ?? String(rating)}
                    onPress={() => submitRating(rating)}
                    theme={theme}
                    variant={rating >= 2 ? 'primary' : 'secondary'}
                  />
                ))}
              </View>
            </View>
          ) : null}
        </Card>
      ) : null}

      <Card theme={theme} style={{ backgroundColor: theme.primarySoft }}>
        <Text style={[styles.cardTitle, { color: theme.text }]}>실험 안전 경계</Text>
        <Text style={[styles.body, { color: theme.muted }]}>
          앱은 JSON report와 교육용 미션을 다룬다. APK 실행·payload 전달·외부 target
          테스트 기능은 포함하지 않는다. 동적 검증은 별도 로컬 격리 lab에서만 수행한다.
        </Text>
      </Card>
    </ScrollView>
  );
}

function FindingDetail({
  finding,
  theme,
  onOpenLesson,
}: {
  finding: JadxFinding;
  theme: AppTheme;
  onOpenLesson: (lessonId: string) => void;
}): React.ReactElement {
  return (
    <Card theme={theme} style={{ backgroundColor: theme.primarySoft }}>
      <Text style={[styles.cardTitle, { color: theme.text }]}>선택한 후보의 Evidence Boundary</Text>
      <KeyValueRow label="ID" value={finding.id} theme={theme} />
      <KeyValueRow label="Evidence" value={finding.evidenceBoundary} theme={theme} />
      <SectionTitle title="관찰 증거" theme={theme} />
      <BulletList items={finding.evidence} theme={theme} />
      <SectionTitle title="Locator" theme={theme} />
      <BulletList items={finding.locations} theme={theme} />
      <SectionTitle title="아직 필요한 가정" theme={theme} />
      <BulletList items={finding.assumptions} theme={theme} tone="warning" />
      <SectionTitle title="Negative Control" theme={theme} />
      <BulletList items={finding.negativeControls} theme={theme} />
      <SectionTitle title="학습 목표" theme={theme} />
      <BulletList items={finding.learningObjectives} theme={theme} />
      <TextButton
        label="증거 중심 리포트 레슨 열기"
        onPress={() => onOpenLesson('jadx-evidence-report')}
        theme={theme}
      />
    </Card>
  );
}

const styles = StyleSheet.create({
  content: { gap: spacing.lg, padding: spacing.lg, paddingBottom: 120 },
  rowBetween: { flexDirection: 'row', alignItems: 'flex-start', justifyContent: 'space-between', gap: spacing.md },
  flex: { flex: 1, gap: spacing.xs },
  cardTitle: { fontSize: 17, fontWeight: '900' },
  body: { fontSize: 14, lineHeight: 21 },
  small: { fontSize: 12, lineHeight: 18 },
  buttonRow: { gap: spacing.sm, marginTop: spacing.sm },
  metrics: { flexDirection: 'row', gap: spacing.xs },
  metricCard: { flex: 1, alignItems: 'center', paddingHorizontal: spacing.xs },
  metric: { fontSize: 19, fontWeight: '900' },
  list: { gap: spacing.sm },
  findingTitle: { fontSize: 15, lineHeight: 20, fontWeight: '900', flex: 1 },
  pills: { flexDirection: 'row', flexWrap: 'wrap', gap: spacing.sm },
  quizPrompt: { fontSize: 17, lineHeight: 25, fontWeight: '800' },
  answerList: { gap: spacing.sm },
  answer: { borderWidth: 1.5, borderRadius: 12, padding: spacing.md },
  answerText: { fontSize: 14, lineHeight: 20, fontWeight: '700' },
  explanation: { gap: spacing.md, marginTop: spacing.sm },
  result: { fontSize: 18, fontWeight: '900' },
  ratingRow: { gap: spacing.sm },
});
