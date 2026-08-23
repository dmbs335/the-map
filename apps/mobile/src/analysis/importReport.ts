import * as DocumentPicker from 'expo-document-picker';
import { File } from 'expo-file-system';

import { parseJadxLearningReport } from './report';
import type { JadxLearningReport } from '../types';

export async function pickJadxLearningReport(): Promise<JadxLearningReport | null> {
  const result = await DocumentPicker.getDocumentAsync({
    type: 'application/json',
    copyToCacheDirectory: true,
    multiple: false,
  });
  if (result.canceled) {
    return null;
  }
  const asset = result.assets[0];
  if (!asset) {
    throw new Error('The document picker returned no asset.');
  }
  const file = new File(asset.uri);
  const text = await file.text();
  return parseJadxLearningReport(text);
}
