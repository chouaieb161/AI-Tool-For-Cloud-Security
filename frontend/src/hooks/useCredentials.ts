import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import type { CredentialStatus } from '../api';

export function useCredentials() {
  const [status, setStatus] = useState<CredentialStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getCredentialStatus();
      setStatus(data);
    } catch (err) {
      console.error('Failed to load credential status', err);
      setError('Failed to check credentials status.');
    } finally {
      setLoading(false);
    }
  }, []);

  const upload = useCallback(async (file: File) => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.uploadCredentials(file);
      setStatus(data);
      return data;
    } catch (err) {
      console.error('Failed to upload credentials', err);
      setError('Upload failed. Please provide a valid service account JSON file.');
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  return { status, loading, error, reload: loadStatus, upload };
}
