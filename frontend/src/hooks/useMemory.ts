import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import type { MemoryNote } from '../api';

export function useMemory(projectId: number | null) {
  const [notes, setNotes] = useState<MemoryNote[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const sortNotes = useCallback((items: MemoryNote[]) => {
    return [...items].sort((a, b) => {
      if (a.pinned !== b.pinned) {
        return a.pinned ? -1 : 1;
      }
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });
  }, []);

  const loadNotes = useCallback(async () => {
    if (!projectId) return;
    try {
      setLoading(true);
      setError(null);
      const data = await api.getMemoryNotes(projectId);
      setNotes(sortNotes(data));
    } catch (err) {
      console.error('Failed to load memory notes', err);
      setError('Failed to load memory notes.');
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  const togglePin = useCallback(
    async (note: MemoryNote) => {
      if (!projectId) return;
      const updated = await api.updateMemoryNote(projectId, note.id, !note.pinned);
      setNotes((prev) => sortNotes(
        prev.map((item) => (item.id === updated.id ? updated : item))
      ));
    },
    [projectId, sortNotes]
  );

  const removeNote = useCallback(
    async (noteId: number) => {
      if (!projectId) return;
      await api.deleteMemoryNote(projectId, noteId);
      setNotes((prev) => prev.filter((note) => note.id !== noteId));
    },
    [projectId]
  );

  useEffect(() => {
    loadNotes();
  }, [loadNotes]);

  return { notes, loading, error, reload: loadNotes, togglePin, removeNote };
}
