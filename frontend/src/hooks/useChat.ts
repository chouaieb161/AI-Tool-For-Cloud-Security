import { useState, useRef, useEffect } from 'react';
import { api } from '../api';
import type { ChatMessage, ChatSession, Project } from '../api';

export function useChat() {
  const [project, setProject] = useState<Project | null>(null);
  const [session, setSession] = useState<ChatSession | null>(null);
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

    // Load or create session
    const initChat = async () => {
      try {
        let projects = await api.getProjects();
        if (projects.length === 0) {
          const newProj = await api.createProject("Demo GCP Project", "demo-gcp-001");
          projects = [newProj];
        }
        const activeProj = projects[0];
        setProject(activeProj);

        // get existing sessions
        const existingSessions = await api.getChatSessions(activeProj.id) || [];
        let activeSession = existingSessions[0];

        if (!activeSession) {
          activeSession = await api.createChatSession(activeProj.id, "Security Consultation");
          existingSessions.unshift(activeSession);
        }

        setSessions(existingSessions);
        setSession(activeSession);

      } catch (err) {
        console.error("Failed to init chat session", err);
      }
    };

    initChat();
  }, []);

  useEffect(() => {
    if (!session) return;
    const loadHistory = async () => {
      try {
        const history = await api.getChatMessages(session.id);
        setMessages(history);
      } catch (err) {
        console.error("Failed to load chat history", err);
      }
    };
    loadHistory();
  }, [session]);

  const createSession = async (title?: string) => {
    if (!project) return;
    try {
      const created = await api.createChatSession(project.id, title || "New Session");
      setSessions((prev) => [created, ...prev]);
      setSession(created);
      setMessages([]);
    } catch (err) {
      console.error("Failed to create session", err);
    }
  };

  const deleteSession = async (sessionId: number) => {
    try {
      await api.deleteChatSession(sessionId);
      setSessions((prev) => {
        const next = prev.filter((s) => s.id !== sessionId);
        if (session?.id === sessionId) {
          const replacement = next[0] || null;
          setSession(replacement);
          setMessages([]);
        }
        return next;
      });
    } catch (err) {
      console.error("Failed to delete session", err);
    }
  };

  const selectSession = (sessionId: number) => {
    const next = sessions.find((s) => s.id === sessionId) || null;
    if (!next) return;
    setSession(next);
  };

  const updateMessage = async (messageId: number, content: string) => {
    if (!session || !content.trim()) return;
    try {
      const updated = await api.updateChatMessage(session.id, messageId, content.trim());
      setMessages((prev) => prev.map((msg) => (msg.id === messageId ? updated : msg)));
    } catch (err) {
      console.error("Failed to update message", err);
    }
  };

  const deleteMessage = async (messageId: number) => {
    if (!session) return;
    try {
      await api.deleteChatMessage(session.id, messageId);
      setMessages((prev) => prev.filter((msg) => msg.id !== messageId));
    } catch (err) {
      console.error("Failed to delete message", err);
    }
  };

  const sendMessage = async (content: string) => {
    if (!session || !content.trim()) return;

    const userMsg: ChatMessage = {
      id: Date.now(), // temp id
      session_id: session.id,
      role: 'user',
      content,
      created_at: new Date().toISOString()
    };

    setMessages(prev => [...prev, userMsg]);
    setIsLoading(true);
    setIsStreaming(true);

    const assistantMsg: ChatMessage = {
      id: Date.now() + 1,
      session_id: session.id,
      role: 'assistant',
      content: '',
      citations: [],
      steps: [],
      created_at: new Date().toISOString()
    };

    setMessages(prev => [...prev, assistantMsg]);

    try {
      const response = await fetch(`/api/chat/sessions/${session.id}/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      });

      if (!response.body) throw new Error("No response body");

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      
      let done = false;
      let streamedContent = '';
      let streamedSteps: string[] = [];
      let streamedCitations: any[] = [];

      while (!done) {
        const { value, done: readerDone } = await reader.read();
        done = readerDone;
        if (value) {
          const chunk = decoder.decode(value, { stream: true });
          const messages = chunk.split('\n\n').filter(m => m.startsWith('data: '));
          
          for (const msg of messages) {
            const dataStr = msg.replace('data: ', '');
            if (!dataStr) continue;
            
            try {
              const data = JSON.parse(dataStr);
              
              if (data.type === 'token') {
                streamedContent += data.payload.text;
              } else if (data.type === 'step') {
                streamedSteps.push(data.payload.text);
              } else if (data.type === 'citation') {
                streamedCitations.push(data.payload);
              } else if (data.type === 'user_message') {
                setMessages(prev => prev.map((msg) => (
                  msg.id === userMsg.id ? { ...msg, id: data.payload.message_id } : msg
                )));
              } else if (data.type === 'done') {
                // finished
              }

              // Update the assistant message in UI
              setMessages(prev => {
                const newArr = [...prev];
                const lastIdx = newArr.length - 1;
                newArr[lastIdx] = {
                  ...newArr[lastIdx],
                  content: streamedContent,
                  steps: [...streamedSteps],
                  citations: [...streamedCitations],
                  id: data.type === 'done' ? data.payload.message_id : newArr[lastIdx].id
                };
                return newArr;
              });

            } catch (e) {
              console.warn("Parse error for chunk", dataStr, e);
            }
          }
        }
      }
    } catch (err) {
      console.error("Stream failed", err);
    } finally {
      setIsLoading(false);
      setIsStreaming(false);
    }
  };

  return {
    project,
    session,
    sessions,
    messages,
    isLoading,
    isStreaming,
    sendMessage,
    createSession,
    deleteSession,
    selectSession,
    updateMessage,
    deleteMessage
  };
}
