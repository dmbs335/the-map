import React from 'react';
import {
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
  type StyleProp,
  type ViewStyle,
} from 'react-native';

import { palette, radius, spacing, type AppTheme } from '../theme';

export function Card({
  children,
  theme,
  style,
  accessibilityLabel,
}: React.PropsWithChildren<{
  theme: AppTheme;
  style?: StyleProp<ViewStyle>;
  accessibilityLabel?: string;
}>): React.ReactElement {
  return (
    <View
      accessibilityLabel={accessibilityLabel}
      style={[
        styles.card,
        { backgroundColor: theme.surface, borderColor: theme.border },
        style,
      ]}
    >
      {children}
    </View>
  );
}

export function ScreenHeader({
  eyebrow,
  title,
  subtitle,
  theme,
}: {
  eyebrow?: string;
  title: string;
  subtitle?: string;
  theme: AppTheme;
}): React.ReactElement {
  return (
    <View style={styles.screenHeader}>
      {eyebrow ? (
        <Text style={[styles.eyebrow, { color: theme.primary }]}>{eyebrow}</Text>
      ) : null}
      <Text style={[styles.screenTitle, { color: theme.text }]}>{title}</Text>
      {subtitle ? (
        <Text style={[styles.screenSubtitle, { color: theme.muted }]}>
          {subtitle}
        </Text>
      ) : null}
    </View>
  );
}

export function SectionTitle({
  title,
  subtitle,
  theme,
}: {
  title: string;
  subtitle?: string;
  theme: AppTheme;
}): React.ReactElement {
  return (
    <View style={styles.sectionHeader}>
      <Text style={[styles.sectionTitle, { color: theme.text }]}>{title}</Text>
      {subtitle ? (
        <Text style={[styles.sectionSubtitle, { color: theme.muted }]}>
          {subtitle}
        </Text>
      ) : null}
    </View>
  );
}

export function Pill({
  label,
  theme,
  tone = 'neutral',
}: {
  label: string;
  theme: AppTheme;
  tone?: 'neutral' | 'primary' | 'success' | 'warning' | 'danger' | 'research';
}): React.ReactElement {
  const colors = {
    neutral: { background: theme.surfaceAlt, foreground: theme.muted },
    primary: { background: theme.primarySoft, foreground: theme.primary },
    success: { background: palette.successSoft, foreground: palette.success },
    warning: { background: palette.warningSoft, foreground: palette.warning },
    danger: { background: palette.dangerSoft, foreground: palette.danger },
    research: { background: palette.researchSoft, foreground: palette.research },
  }[tone];

  return (
    <View style={[styles.pill, { backgroundColor: colors.background }]}>
      <Text style={[styles.pillText, { color: colors.foreground }]}>
        {label}
      </Text>
    </View>
  );
}

export function ChipButton({
  label,
  selected,
  onPress,
  theme,
}: {
  label: string;
  selected: boolean;
  onPress: () => void;
  theme: AppTheme;
}): React.ReactElement {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ selected }}
      onPress={onPress}
      style={({ pressed }: { pressed: boolean }) => [
        styles.chipButton,
        {
          backgroundColor: selected ? theme.primarySoft : theme.surface,
          borderColor: selected ? theme.primary : theme.border,
          opacity: pressed ? 0.7 : 1,
        },
      ]}
    >
      <Text
        style={[
          styles.chipButtonText,
          { color: selected ? theme.primary : theme.muted },
        ]}
      >
        {label}
      </Text>
    </Pressable>
  );
}

export function ProgressBar({
  value,
  theme,
}: {
  value: number;
  theme: AppTheme;
}): React.ReactElement {
  const clamped = Math.max(0, Math.min(1, value));
  return (
    <View
      accessibilityRole="progressbar"
      accessibilityValue={{ min: 0, max: 100, now: Math.round(clamped * 100) }}
      style={[styles.progressTrack, { backgroundColor: theme.surfaceAlt }]}
    >
      <View
        style={[
          styles.progressValue,
          {
            backgroundColor: theme.primary,
            width: `${Math.round(clamped * 100)}%`,
          },
        ]}
      />
    </View>
  );
}

export function PrimaryButton({
  label,
  onPress,
  theme,
  disabled = false,
  variant = 'primary',
  accessibilityHint,
}: {
  label: string;
  onPress: () => void;
  theme: AppTheme;
  disabled?: boolean;
  variant?: 'primary' | 'secondary' | 'danger';
  accessibilityHint?: string;
}): React.ReactElement {
  const backgroundColor =
    variant === 'primary'
      ? theme.primary
      : variant === 'danger'
        ? palette.danger
        : theme.surfaceAlt;
  const color = variant === 'secondary' ? theme.text : '#FFFFFF';

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      accessibilityHint={accessibilityHint}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }: { pressed: boolean }) => [
        styles.button,
        {
          backgroundColor,
          borderColor: variant === 'secondary' ? theme.border : backgroundColor,
          opacity: disabled ? 0.45 : pressed ? 0.78 : 1,
        },
      ]}
    >
      <Text style={[styles.buttonText, { color }]}>{label}</Text>
    </Pressable>
  );
}

export function TextButton({
  label,
  onPress,
  theme,
  destructive = false,
}: {
  label: string;
  onPress: () => void;
  theme: AppTheme;
  destructive?: boolean;
}): React.ReactElement {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      onPress={onPress}
      hitSlop={8}
      style={({ pressed }: { pressed: boolean }) => ({ opacity: pressed ? 0.55 : 1 })}
    >
      <Text
        style={[
          styles.textButton,
          { color: destructive ? palette.danger : theme.primary },
        ]}
      >
        {label}
      </Text>
    </Pressable>
  );
}

export function SearchInput({
  value,
  onChangeText,
  placeholder,
  theme,
}: {
  value: string;
  onChangeText: (value: string) => void;
  placeholder: string;
  theme: AppTheme;
}): React.ReactElement {
  return (
    <TextInput
      accessibilityLabel={placeholder}
      autoCapitalize="none"
      autoCorrect={false}
      clearButtonMode="while-editing"
      onChangeText={onChangeText}
      placeholder={placeholder}
      placeholderTextColor={theme.muted}
      style={[
        styles.search,
        {
          backgroundColor: theme.surface,
          borderColor: theme.border,
          color: theme.text,
        },
      ]}
      value={value}
    />
  );
}

export function ListItemButton({
  title,
  subtitle,
  meta,
  onPress,
  theme,
  completed = false,
  locked = false,
}: {
  title: string;
  subtitle?: string;
  meta?: string;
  onPress: () => void;
  theme: AppTheme;
  completed?: boolean;
  locked?: boolean;
}): React.ReactElement {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: locked }}
      disabled={locked}
      onPress={onPress}
      style={({ pressed }: { pressed: boolean }) => [
        styles.listItem,
        {
          backgroundColor: theme.surface,
          borderColor: theme.border,
          opacity: locked ? 0.5 : pressed ? 0.72 : 1,
        },
      ]}
    >
      <View style={styles.listItemBody}>
        <Text style={[styles.listItemTitle, { color: theme.text }]}>{title}</Text>
        {subtitle ? (
          <Text
            numberOfLines={2}
            style={[styles.listItemSubtitle, { color: theme.muted }]}
          >
            {subtitle}
          </Text>
        ) : null}
        {meta ? (
          <Text style={[styles.listItemMeta, { color: theme.primary }]}>
            {meta}
          </Text>
        ) : null}
      </View>
      <Text
        style={[
          styles.listItemIcon,
          { color: completed ? palette.success : theme.muted },
        ]}
      >
        {locked ? '🔒' : completed ? '✓' : '›'}
      </Text>
    </Pressable>
  );
}

export function BulletList({
  items,
  theme,
  tone = 'normal',
}: {
  items: string[];
  theme: AppTheme;
  tone?: 'normal' | 'warning';
}): React.ReactElement {
  return (
    <View style={styles.bulletList}>
      {items.map((item, index) => (
        <View key={`${index}-${item}`} style={styles.bulletRow}>
          <Text
            style={[
              styles.bullet,
              { color: tone === 'warning' ? palette.warning : theme.primary },
            ]}
          >
            •
          </Text>
          <Text style={[styles.bulletText, { color: theme.text }]}>{item}</Text>
        </View>
      ))}
    </View>
  );
}

export function KeyValueRow({
  label,
  value,
  theme,
}: {
  label: string;
  value: string | number;
  theme: AppTheme;
}): React.ReactElement {
  return (
    <View style={[styles.keyValueRow, { borderBottomColor: theme.border }]}>
      <Text style={[styles.key, { color: theme.muted }]}>{label}</Text>
      <Text style={[styles.value, { color: theme.text }]}>{String(value)}</Text>
    </View>
  );
}

export function EmptyState({
  title,
  detail,
  theme,
}: {
  title: string;
  detail: string;
  theme: AppTheme;
}): React.ReactElement {
  return (
    <View style={styles.emptyState}>
      <Text style={[styles.emptyTitle, { color: theme.text }]}>{title}</Text>
      <Text style={[styles.emptyDetail, { color: theme.muted }]}>{detail}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    borderWidth: StyleSheet.hairlineWidth,
    borderRadius: radius.lg,
    padding: spacing.lg,
    gap: spacing.sm,
  },
  screenHeader: { gap: spacing.xs, paddingTop: spacing.sm },
  eyebrow: { fontSize: 12, fontWeight: '900', letterSpacing: 1.1, textTransform: 'uppercase' },
  screenTitle: { fontSize: 30, fontWeight: '900', letterSpacing: -0.8, lineHeight: 36 },
  screenSubtitle: { fontSize: 15, lineHeight: 23 },
  sectionHeader: { gap: spacing.xs, marginTop: spacing.sm },
  sectionTitle: { fontSize: 20, fontWeight: '800', letterSpacing: -0.3 },
  sectionSubtitle: { fontSize: 14, lineHeight: 20 },
  pill: { alignSelf: 'flex-start', borderRadius: radius.pill, paddingHorizontal: 10, paddingVertical: 5 },
  pillText: { fontSize: 12, fontWeight: '700' },
  chipButton: { borderWidth: StyleSheet.hairlineWidth, borderRadius: radius.pill, paddingHorizontal: 12, paddingVertical: 8 },
  chipButtonText: { fontSize: 12, fontWeight: '800' },
  progressTrack: { height: 10, borderRadius: radius.pill, overflow: 'hidden' },
  progressValue: { height: '100%', borderRadius: radius.pill },
  button: { minHeight: 46, alignItems: 'center', justifyContent: 'center', borderRadius: radius.md, borderWidth: StyleSheet.hairlineWidth, paddingHorizontal: spacing.lg, paddingVertical: spacing.md },
  buttonText: { fontSize: 15, fontWeight: '800' },
  textButton: { fontSize: 14, fontWeight: '800' },
  search: { minHeight: 48, borderWidth: StyleSheet.hairlineWidth, borderRadius: radius.md, paddingHorizontal: spacing.lg, fontSize: 16 },
  listItem: { borderWidth: StyleSheet.hairlineWidth, borderRadius: radius.md, padding: spacing.md, flexDirection: 'row', alignItems: 'center', gap: spacing.md },
  listItemBody: { flex: 1, gap: spacing.xs },
  listItemTitle: { fontSize: 16, fontWeight: '800' },
  listItemSubtitle: { fontSize: 13, lineHeight: 19 },
  listItemMeta: { fontSize: 12, fontWeight: '700' },
  listItemIcon: { fontSize: 22, fontWeight: '700' },
  bulletList: { gap: spacing.sm },
  bulletRow: { flexDirection: 'row', gap: spacing.sm, alignItems: 'flex-start' },
  bullet: { fontSize: 18, lineHeight: 22, fontWeight: '900' },
  bulletText: { flex: 1, fontSize: 14, lineHeight: 22 },
  keyValueRow: { minHeight: 42, borderBottomWidth: StyleSheet.hairlineWidth, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', gap: spacing.md },
  key: { fontSize: 13, flex: 1 },
  value: { fontSize: 13, fontWeight: '800', textAlign: 'right', flex: 1.2 },
  emptyState: { alignItems: 'center', gap: spacing.sm, paddingVertical: spacing.xxl, paddingHorizontal: spacing.xl },
  emptyTitle: { fontSize: 17, fontWeight: '800' },
  emptyDetail: { textAlign: 'center', fontSize: 14, lineHeight: 20 },
});
