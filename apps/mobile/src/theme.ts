import { ColorSchemeName } from 'react-native';

export const palette = {
  ink: '#0E1726',
  muted: '#667085',
  border: '#D0D5DD',
  surface: '#FFFFFF',
  surfaceAlt: '#F2F4F7',
  primary: '#2563EB',
  primarySoft: '#DBEAFE',
  success: '#059669',
  successSoft: '#D1FAE5',
  warning: '#D97706',
  warningSoft: '#FEF3C7',
  danger: '#DC2626',
  dangerSoft: '#FEE2E2',
  research: '#7C3AED',
  researchSoft: '#EDE9FE',
  darkBackground: '#0B1220',
  darkSurface: '#111B2E',
  darkSurfaceAlt: '#17233A',
  darkText: '#F8FAFC',
  darkMuted: '#A8B3C7',
  darkBorder: '#334155',
};

export interface AppTheme {
  isDark: boolean;
  background: string;
  surface: string;
  surfaceAlt: string;
  text: string;
  muted: string;
  border: string;
  primary: string;
  primarySoft: string;
}

export function themeFor(scheme: ColorSchemeName): AppTheme {
  const isDark = scheme === 'dark';
  return {
    isDark,
    background: isDark ? palette.darkBackground : '#F8FAFC',
    surface: isDark ? palette.darkSurface : palette.surface,
    surfaceAlt: isDark ? palette.darkSurfaceAlt : palette.surfaceAlt,
    text: isDark ? palette.darkText : palette.ink,
    muted: isDark ? palette.darkMuted : palette.muted,
    border: isDark ? palette.darkBorder : palette.border,
    primary: isDark ? '#60A5FA' : palette.primary,
    primarySoft: isDark ? '#172554' : palette.primarySoft,
  };
}

export const spacing = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 24,
  xxl: 32,
};

export const radius = {
  sm: 8,
  md: 12,
  lg: 18,
  pill: 999,
};
