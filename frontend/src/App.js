import React, { useEffect, useMemo, useState } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route, Link, useLocation } from "react-router-dom";
import axios from "axios";
import Swipe from "./pages/Swipe";
import Account from "./pages/Account";
import Legal from "./pages/Legal";
import { CORAL } from "./mock";
import { ThemeProvider } from "next-themes";
import { Button } from "./components/ui/button";
import { Input } from "./components/ui/input";
import { Card, CardContent } from "./components/ui/card";
import { Avatar, AvatarImage, AvatarFallback } from "./components/ui/avatar";
import { Sun, Moon, MessageSquare, Home as HomeIcon } from "lucide-react";
import { getMatches, listMessages, sendMessage, getMe as apiGetMe } from "./lib/api";
import { Toaster } from "./components/ui/toaster";
import { SessionsList, SessionFormDialog } from "./components/ui/scheduling";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

function HelloPing() {
  useEffect(() => {
    axios.get(`${API}/`).catch(() => {});
    (async () => { try { const data = await apiGetMe(); if (data?.user?.id) localStorage.setItem("ss_me_id", data.user.id); } catch {} })();
  }, []);
  return null;
}

function Logo() {
  const [ok, setOk] = useState(true);
  return ok ? (<img src="/logo.png" alt="SkillSwap" className="h-6" onError={() => setOk(false)} />) : (<span className="font-semibold" style={{ color: CORAL }}>SkillSwap</span>);
}

function Layout({ children }) {
  const location = useLocation();
  const nav = [ { to: "/", label: "Swipe" }, { to: "/chats", label: "Chats" }, { to: "/account", label: "Account" } ];
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-30 border-b bg-background/80 backdrop-blur hidden md:block">
        <div className="mx-auto max-w-5xl px-4 h-14 flex items-center justify-between">
          <Link to="/" className="font-semibold tracking-tight"><Logo /></Link>
          <div className="flex items-center gap-1">
            {nav.map((n) => (<Link key={n.to} to={n.to} className={"px-3 py-2 rounded-md text-sm " + (location.pathname === n.to ? "bg-muted" : "hover:bg-muted")}>{n.label}</Link>))}
            <ThemeToggle />
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-4 pb-20 md:pb-4">{children}</main>
      <MobileNav />
      <footer className="py-6 text-center text-xs text-muted-foreground">MVP: Auth passwordless, scoring, scheduling + ratings. <Link to="/legal" className="underline">Confidentialité & Conditions</Link></footer>
      <Toaster />
    </div>
  );
}

function MobileNav() {
  const location = useLocation();
  const links = [ { to: "/", label: "Swipe", icon: <HomeIcon size={18} /> }, { to: "/chats", label: "Chats", icon: <MessageSquare size={18} /> }, { to: "/account", label: "Account", icon: <Sun size={18} /> } ];
  return (
    <nav className="md:hidden fixed bottom-0 left-0 right-0 border-t bg-background/95 backdrop-blur">
      <div className="max-w-5xl mx-auto grid grid-cols-3">
        {links.map(l => (<Link key={l.to} to={l.to} className={"flex flex-col items-center py-2 " + (location.pathname === l.to ? "text-foreground" : "text-muted-foreground")}>{l.icon}<span className="text-xs mt-1">{l.label}</span></Link>))}
      </div>
    </nav>
  );
}

function ThemeToggle() {
  const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "light");
  useEffect(() => { const root = document.documentElement; if (theme === "dark") root.classList.add("dark"); else root.classList.remove("dark"); localStorage.setItem("theme", theme); }, [theme]);
  return (<Button variant="ghost" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>{theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}</Button>);
}

function Chats() {
  const [threads, setThreads] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [meId, setMeId] = useState(() => localStorage.getItem("ss_me_id") || null);
  const [openPlan, setOpenPlan] = useState(false);

  useEffect(() => { if (meId) return; (async () => { try { const data = await apiGetMe(); if (data?.user?.id) { localStorage.setItem("ss_me_id", data.user.id); setMeId(data.user.id); } } catch {} })(); }, [meId]);
  useEffect(() => { let mounted = true; (async () => { try { const data = await getMatches(); if (!mounted) return; const items = (data.matches || []).map((m) => ({ id: m.id, userId: m.user.id, name: m.user.name, avatar: m.user.photos?.[0], lastMessage: m.lastMessage?.text || (m.lastMessage?.imageUrl ? "📷 image" : "") })); setThreads(items); setActiveId(items[0]?.id || null); } catch { setThreads([]); } })(); return () => { mounted = false; }; }, []);

  const [messages, setMessages] = useState([]);
  useEffect(() => { let mounted = true; (async () => { if (!activeId) return; try { const data = await listMessages(activeId, 0, 50); if (!mounted) return; setMessages(data.messages || []); } catch { setMessages([]); } })(); return () => { mounted = false; }; }, [activeId]);

  const send = async (text) => { if (!activeId || !text) return; try { const m = await sendMessage(activeId, { text, clientSessionId: String(Date.now()) }); setMessages((prev) => [...prev, { id: m.id, fromUserId: m.fromUserId, text: m.text, ts: new Date(m.ts).getTime() }]); setThreads((prev) => prev.map((t) => t.id === activeId ? { ...t, lastMessage: text } : t)); } catch {} };

  return (
    <div className="grid md:grid-cols-[300px_1fr] gap-4">
      <Card className="h-[70vh] overflow-auto"><CardContent className="p-0">{threads.map((t) => (<button key={t.id} onClick={() => setActiveId(t.id)} className={(activeId === t.id ? "bg-muted " : "") + " w-full flex items-center gap-3 p-3 border-b hover:bg-muted text-left"}><Avatar className="h-10 w-10"><AvatarImage src={t.avatar} /><AvatarFallback>{t.name.slice(0,2).toUpperCase()}</AvatarFallback></Avatar><div><div className="text-sm font-medium">{t.name}</div><div className="text-xs text-muted-foreground line-clamp-1">{t.lastMessage}</div></div></button>))}</CardContent></Card>
      <Card className="h-[70vh] flex flex-col">
        <CardContent className="flex-1 overflow-auto space-y-2 p-3">
          <div className="flex items-center justify-between mb-2"><div className="text-sm text-muted-foreground">Conversation</div><Button className="h-10" style={{ backgroundColor: CORAL }} onClick={() => setOpenPlan(true)}>Planifier</Button></div>
          {messages.map((m) => (<div key={m.id} className={(m.fromUserId === meId ? "justify-end" : "justify-start") + " flex"}><div className={(m.fromUserId === meId ? "bg-[var(--accent)]/20" : "bg-muted") + " rounded-lg px-3 py-2 max-w-[70%]"} style={m.fromUserId === meId ? { border: `1px solid ${CORAL}` } : undefined}><div className="text-sm">{m.text}</div><div className="text-[10px] text-muted-foreground mt-1">{new Date(m.ts || Date.now()).toLocaleTimeString()}</div></div></div>))}
          {activeId && <SessionsList matchId={activeId} meId={meId} />}
        </CardContent>
        <ChatInput onSend={send} />
      </Card>
      {activeId && <SessionFormDialog open={openPlan} onOpenChange={setOpenPlan} matchId={activeId} onCreated={() => {}} />}
    </div>
  );
}

function ChatInput({ onSend }) {
  const [text, setText] = useState("");
  const submit = () => { if (!text.trim()) return; onSend(text.trim()); setText(""); };
  return (
    <div className="p-3 border-t flex items-center gap-2">
      <Input placeholder="Message" value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === "Enter" ? submit() : null} />
      <Button onClick={submit} style={{ backgroundColor: CORAL }}>Send</Button>
    </div>
  );
}

function Home() {
  return (
    <div className="grid md:grid-cols-[380px_auto] gap-6 items-start">
      <div><div className="hidden md:block sticky top-20"><PhoneFrame><Swipe /></PhoneFrame></div><div className="md:hidden"><Swipe /></div></div>
      <div className="space-y-4"><h1 className="text-2xl font-semibold">Find people to swap skills</h1><p className="text-muted-foreground max-w-prose">Swipe to find matches, chat, schedule a session, then rate each other. Passwordless auth included.</p></div>
    </div>
  );
}

function PhoneFrame({ children }) { return (<div className="rounded-[32px] border shadow-2xl overflow-hidden w-[360px] h-[720px] bg-background"><div className="h-6 bg-muted flex items-center justify-center text-[10px]">SkillSwap</div><div className="h-[calc(100%-24px)] overflow-auto">{children}</div></div>); }

function App() {
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <BrowserRouter>
        <HelloPing />
        <Layout>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/chats" element={<Chats />} />
            <Route path="/account" element={<Account />} />
            <Route path="/legal" element={<Legal />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;