import Storage from 'expo-sqlite/kv-store';
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import sampleReportJson from '../data/samples/jadx-learning-report.json';
import { pickJadxLearningReport } from '../analysis/importReport';
import { validateJadxLearningReport } from '../analysis/report';
import type { JadxLearningReport } from '../types';

const STORAGE_KEY = 'the-map-last-jadx-report-v1';
const sampleReport = validateJadxLearningReport(sampleReportJson);

interface AnalysisContextValue {
  hydrated: boolean;
  report: JadxLearningReport;
  reportSource: 'sample' | 'imported';
  importError: string | null;
  importing: boolean;
  importReport: () => Promise<void>;
  useSampleReport: () => Promise<void>;
  clearImportError: () => void;
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null);

interface PersistedReport {
  source: 'sample' | 'imported';
  report: JadxLearningReport;
}

function parsePersisted(raw: string | null): PersistedReport | null {
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as { source?: unknown; report?: unknown };
    if (parsed.source !== 'sample' && parsed.source !== 'imported') {
      return null;
    }
    return {
      source: parsed.source,
      report: validateJadxLearningReport(parsed.report),
    };
  } catch (error) {
    console.warn('Unable to parse saved JADX report', error);
    return null;
  }
}

async function persist(value: PersistedReport): Promise<void> {
  await Storage.setItem(STORAGE_KEY, JSON.stringify(value));
}

export function AnalysisProvider({
  children,
}: React.PropsWithChildren): React.ReactElement {
  const [hydrated, setHydrated] = useState(false);
  const [report, setReport] = useState<JadxLearningReport>(sampleReport);
  const [reportSource, setReportSource] = useState<'sample' | 'imported'>('sample');
  const [importError, setImportError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);

  useEffect(() => {
    let mounted = true;
    Storage.getItem(STORAGE_KEY)
      .then((raw) => {
        const loaded = parsePersisted(raw);
        if (mounted && loaded) {
          setReport(loaded.report);
          setReportSource(loaded.source);
        }
      })
      .catch((error) => {
        console.warn('Unable to hydrate JADX report', error);
      })
      .finally(() => {
        if (mounted) {
          setHydrated(true);
        }
      });
    return () => {
      mounted = false;
    };
  }, []);

  const importReport = useCallback(async () => {
    setImporting(true);
    setImportError(null);
    try {
      const selected = await pickJadxLearningReport();
      if (!selected) {
        return;
      }
      setReport(selected);
      setReportSource('imported');
      await persist({ source: 'imported', report: selected });
    } catch (error) {
      setImportError(error instanceof Error ? error.message : String(error));
    } finally {
      setImporting(false);
    }
  }, []);

  const useSampleReport = useCallback(async () => {
    setReport(sampleReport);
    setReportSource('sample');
    setImportError(null);
    await persist({ source: 'sample', report: sampleReport });
  }, []);

  const clearImportError = useCallback(() => setImportError(null), []);

  const value = useMemo<AnalysisContextValue>(
    () => ({
      hydrated,
      report,
      reportSource,
      importError,
      importing,
      importReport,
      useSampleReport,
      clearImportError,
    }),
    [
      hydrated,
      report,
      reportSource,
      importError,
      importing,
      importReport,
      useSampleReport,
      clearImportError,
    ],
  );

  return (
    <AnalysisContext.Provider value={value}>
      {children}
    </AnalysisContext.Provider>
  );
}

export function useAnalysis(): AnalysisContextValue {
  const value = useContext(AnalysisContext);
  if (!value) {
    throw new Error('useAnalysis must be used within AnalysisProvider');
  }
  return value;
}
