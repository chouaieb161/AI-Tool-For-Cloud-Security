import { useState, useRef, useEffect } from 'react';
import { Send, FileText, CheckCircle2, Pin, PinOff, RefreshCw, Trash2, Plus, Pencil, Check, X } from 'lucide-react';
import { useChat } from '../hooks/useChat';
import { useMemory } from '../hooks/useMemory';

export default function ChatPage() {
  const {
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
  } = useChat();
  const [input, setInput] = useState('');
  const [editingMessageId, setEditingMessageId] = useState<number | null>(null);
  const [editDraft, setEditDraft] = useState('');
  const endRef = useRef<HTMLDivElement>(null);
  const { notes, loading: memoryLoading, error: memoryError, reload, togglePin, removeNote } = useMemory(project?.id ?? null);

  // Auto-scroll to bottom
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isStreaming]);

  useEffect(() => {
    if (!isStreaming && messages.length > 0) {
      reload();
    }
  }, [isStreaming, messages.length, reload]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;
    sendMessage(input);
    setInput('');
  };

  const startEditing = (messageId: number, content: string) => {
    setEditingMessageId(messageId);
    setEditDraft(content);
  };

  const cancelEditing = () => {
    setEditingMessageId(null);
    setEditDraft('');
  };

  const saveEdit = async () => {
    if (editingMessageId === null || !editDraft.trim()) return;
    await updateMessage(editingMessageId, editDraft);
    cancelEditing();
  };

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)]">
      <header className="mb-4">
        <h2 className="text-2xl font-bold text-slate-800">Security Agent</h2>
        <p className="text-slate-500">Ask the GCP CIS agent for compliance and remediation guidance.</p>
      </header>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[240px_minmax(0,1fr)_320px]">
        <aside className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          <div className="border-b border-slate-200 px-4 py-3 bg-slate-50 flex items-center justify-between">
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">Sessions</h3>
              <p className="text-xs text-slate-400">Start a new thread</p>
            </div>
            <button
              onClick={() => createSession()}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 bg-white px-2 py-1 text-xs text-slate-600 hover:text-slate-900"
            >
              <Plus size={14} />
              New
            </button>
          </div>
          <div className="max-h-[70vh] overflow-y-auto p-3 space-y-2">
            {sessions.length === 0 ? (
              <div className="text-xs text-slate-500">No sessions yet.</div>
            ) : (
              sessions.map((item) => (
                <div
                  key={item.id}
                  className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-sm transition ${
                    session?.id === item.id
                      ? 'border-blue-200 bg-blue-50 text-blue-800'
                      : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => selectSession(item.id)}
                    className="min-w-0 flex-1 text-left"
                  >
                    <div className="font-medium truncate">
                      {item.title || `Session ${item.id}`}
                    </div>
                    <div className="text-[11px] text-slate-400">
                      {new Date(item.created_at).toLocaleString()}
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={() => deleteSession(item.id)}
                    disabled={isStreaming}
                    className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-slate-400 hover:bg-red-50 hover:text-red-600 disabled:cursor-not-allowed disabled:opacity-40"
                    title="Delete session"
                    aria-label="Delete session"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              ))
            )}
          </div>
        </aside>
        <div className="flex-1 bg-white rounded-lg border border-slate-200 shadow-sm flex flex-col overflow-hidden">
        {/* Chat Transcript Area */}
        <div className="flex-1 p-4 overflow-y-auto space-y-6">
          {messages.length === 0 ? (
            <div className="text-center text-slate-500 mt-10">Starting session... or say hello!</div>
          ) : null}

          {messages.map((msg, i) => (
            <div key={i} className={`flex gap-4 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
              <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold shrink-0
                ${msg.role === 'user' ? 'bg-slate-800 text-white' : 'bg-blue-100 text-blue-600'}`}>
                {msg.role === 'user' ? 'U' : 'AI'}
              </div>
              
              <div className={`group max-w-[75%] ${msg.role === 'user' ? 'bg-slate-800 text-white p-3 rounded-lg rounded-tr-none' : 'bg-slate-50 p-4 rounded-lg rounded-tl-none border border-slate-200 text-slate-800'}`}>
                {msg.role === 'user' && editingMessageId === msg.id ? (
                  <div className="space-y-2">
                    <textarea
                      value={editDraft}
                      onChange={(event) => setEditDraft(event.target.value)}
                      className="min-h-24 w-full resize-y rounded-md border border-slate-500 bg-white px-3 py-2 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-400"
                    />
                    <div className="flex justify-end gap-2">
                      <button
                        type="button"
                        onClick={cancelEditing}
                        className="inline-flex h-8 w-8 items-center justify-center rounded-md bg-slate-700 text-slate-100 hover:bg-slate-600"
                        title="Cancel edit"
                        aria-label="Cancel edit"
                      >
                        <X size={15} />
                      </button>
                      <button
                        type="button"
                        onClick={saveEdit}
                        disabled={!editDraft.trim()}
                        className="inline-flex h-8 w-8 items-center justify-center rounded-md bg-blue-600 text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
                        title="Save edit"
                        aria-label="Save edit"
                      >
                        <Check size={15} />
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="whitespace-pre-wrap">{msg.content}</div>
                )}

                {msg.role === 'user' && editingMessageId !== msg.id && (
                  <div className="mt-2 flex justify-end gap-1 opacity-100 sm:opacity-0 sm:transition-opacity sm:group-hover:opacity-100">
                    <button
                      type="button"
                      onClick={() => startEditing(msg.id, msg.content)}
                      disabled={isStreaming}
                      className="inline-flex h-7 w-7 items-center justify-center rounded-md bg-slate-700 text-slate-100 hover:bg-slate-600 disabled:cursor-not-allowed disabled:opacity-40"
                      title="Edit prompt"
                      aria-label="Edit prompt"
                    >
                      <Pencil size={14} />
                    </button>
                    <button
                      type="button"
                      onClick={() => deleteMessage(msg.id)}
                      disabled={isStreaming}
                      className="inline-flex h-7 w-7 items-center justify-center rounded-md bg-slate-700 text-slate-100 hover:bg-red-600 disabled:cursor-not-allowed disabled:opacity-40"
                      title="Delete prompt"
                      aria-label="Delete prompt"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                )}

                {/* Citations block */}
                {msg.citations && msg.citations.length > 0 && (
                  <div className="mt-4 pt-3 border-t border-slate-200">
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
                      <FileText size={14} /> CIS References
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {msg.citations.map((c: any, idx: number) => (
                        <span key={idx} className="bg-blue-100 text-blue-800 px-2.5 py-1 rounded text-xs font-medium">
                          CIS {c.cis_id}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Steps block */}
                {msg.steps && msg.steps.length > 0 && (
                  <div className="mt-4 pt-3 border-t border-slate-200">
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
                      <CheckCircle2 size={14} /> Remediation Steps
                    </div>
                    <ul className="space-y-2">
                      {msg.steps.map((step: string, idx: number) => (
                        <li key={idx} className="flex gap-2 text-sm bg-white p-2 rounded border border-slate-100 shadow-sm">
                          <span className="font-semibold text-blue-600">{idx + 1}.</span>
                          <span className="text-slate-600">{step}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          ))}
          {isStreaming && (
            <div className="flex gap-4">
               <div className="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center font-bold shrink-0 text-blue-600">
                AI
              </div>
              <div className="bg-slate-50 p-3 rounded-lg text-slate-500">Typing...</div>
            </div>
          )}
          <div ref={endRef} />
        </div>

        {/* Input Area */}
        <div className="p-4 bg-slate-50 border-t border-slate-200">
          <form 
            className="flex gap-2"
            onSubmit={handleSubmit}
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={isLoading}
              placeholder="E.g., How do I fix public buckets in this project?"
              className="flex-1 px-4 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-slate-100"
            />
            <button 
              type="submit"
              className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md flex items-center gap-2 transition-colors disabled:opacity-50"
              disabled={!input.trim() || isLoading}
            >
              <Send size={18} />
              Send
            </button>
          </form>
        </div>
        </div>

        <aside className="rounded-xl border border-slate-200 bg-gradient-to-br from-white via-slate-50 to-emerald-50 shadow-sm overflow-hidden">
          <div className="border-b border-slate-200 px-4 py-3 bg-white/70 backdrop-blur">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-600">Memory Notes</h3>
                <p className="text-xs text-slate-500">Pinned highlights and session takeaways.</p>
              </div>
              <button
                onClick={reload}
                className="inline-flex items-center gap-1 rounded-md border border-slate-200 bg-white px-2 py-1 text-xs text-slate-600 hover:text-slate-900"
              >
                <RefreshCw size={14} />
                Refresh
              </button>
            </div>
          </div>

          <div className="p-4 space-y-3 max-h-[70vh] overflow-y-auto">
            {memoryLoading && (
              <div className="text-sm text-slate-500 animate-pulse">Loading memory notes...</div>
            )}
            {memoryError && (
              <div className="text-sm text-red-600 bg-red-50 border border-red-100 rounded-md p-3">
                {memoryError}
              </div>
            )}
            {!memoryLoading && !memoryError && notes.length === 0 && (
              <div className="text-sm text-slate-500">No memory notes yet. Ask for guidance and pin the useful ones.</div>
            )}
            {!memoryLoading && !memoryError && notes.map((note) => (
              <div key={note.id} className="rounded-lg border border-slate-200 bg-white/90 p-3 shadow-sm">
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                        {note.kind.replace('_', ' ')}
                      </span>
                      {note.pinned && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold text-amber-800">
                          <Pin size={10} /> Pinned
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-slate-700 whitespace-pre-wrap">{note.content}</p>
                  </div>
                  <div className="flex flex-col gap-2">
                    <button
                      onClick={() => togglePin(note)}
                      className="inline-flex items-center justify-center rounded-md border border-slate-200 bg-white px-2 py-1 text-xs text-slate-600 hover:text-slate-900"
                    >
                      {note.pinned ? <PinOff size={14} /> : <Pin size={14} />}
                    </button>
                    <button
                      onClick={() => removeNote(note.id)}
                      className="inline-flex items-center justify-center rounded-md border border-slate-200 bg-white px-2 py-1 text-xs text-red-500 hover:text-red-700"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </aside>
      </div>
    </div>
  );
}
