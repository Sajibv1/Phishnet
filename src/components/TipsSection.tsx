import { Eye, Link2, Lock, MousePointerClick, ScanSearch, Timer } from "lucide-react";

const TIPS = [
  {
    icon: Lock,
    title: "HTTPS ≠ trustworthy",
    body: "The padlock only means the connection is encrypted. The majority of phishing sites now ship with valid HTTPS too.",
  },
  {
    icon: ScanSearch,
    title: "Read domains right-to-left",
    body: "Start from the right and stop at the first single slash. paypa1.com.secure-login.tk belongs to secure-login.tk — nobody else.",
  },
  {
    icon: Timer,
    title: "Urgency is the tell",
    body: "“Act within 24 hours or lose access.” Pressure short-circuits judgement — real services never rush you like that.",
  },
  {
    icon: Link2,
    title: "Unwrap short links",
    body: "Shorteners conceal their destination. Expand them first before you commit to a click.",
  },
  {
    icon: Eye,
    title: "Watch for look-alikes",
    body: "Cyrillic а, rn standing in for m, 0 posing as O — one swapped glyph is enough to clone a famous brand.",
  },
  {
    icon: MousePointerClick,
    title: "Hover before you click",
    body: "On desktop, hovering reveals the true target in the status bar. If it differs from the label, walk away.",
  },
];

export default function TipsSection() {
  return (
    <div className="grid gap-3.5 sm:grid-cols-2 lg:grid-cols-3">
      {TIPS.map((tip, i) => (
        <article
          key={tip.title}
          className="group animate-fade-up rounded-xl border border-edge bg-panel p-5 transition hover:border-neon/35"
          style={{ animationDelay: `${i * 60}ms` }}
        >
          <div className="grid h-9 w-9 place-items-center rounded-lg border border-edge bg-[#070d10] transition group-hover:border-neon/40">
            <tip.icon className="h-[18px] w-[18px] text-neon" />
          </div>
          <h3 className="mt-3.5 text-sm font-bold text-fog">{tip.title}</h3>
          <p className="mt-1.5 text-xs leading-relaxed text-dim">{tip.body}</p>
        </article>
      ))}
    </div>
  );
}
