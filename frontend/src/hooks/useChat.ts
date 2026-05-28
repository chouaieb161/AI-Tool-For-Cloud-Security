import { useState, useRef, useEffect } from 'react';
import { api } from '../api';
import type { ChatMessage, ChatSession, Project } from '../api';

export function useChat() {
  const [project, setProject] = useState<Project | null>(null);
  const [session, setSession] = useState<ChatSession | null>(null);
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
        }

        setSession(activeSession);
        
        // load message history
        const history = await api.getChatMessages(activeSession.id);
        setMessages(history);

      } catch (err) {
        console.error("Failed to init chat session", err);
      }
    };

    initChat();
  }, []);

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

  return { project, session, messages, isLoading, isStreaming, sendMessage };
}
