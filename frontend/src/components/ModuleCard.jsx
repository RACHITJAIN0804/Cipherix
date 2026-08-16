import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ArrowRight } from 'lucide-react';

const ACCENT_STYLES = {
  cyan: {
    borderHover: 'hover:border-cyan-500/50',
    glow: 'group-hover:shadow-[0_0_25px_rgba(34,211,238,0.18)]',
    iconBg: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
    badge: 'badge-cyan',
    gradient: 'from-cyan-500/10 to-transparent',
  },
  green: {
    borderHover: 'hover:border-emerald-500/50',
    glow: 'group-hover:shadow-[0_0_25px_rgba(16,185,129,0.18)]',
    iconBg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    badge: 'badge-emerald',
    gradient: 'from-emerald-500/10 to-transparent',
  },
  purple: {
    borderHover: 'hover:border-purple-500/50',
    glow: 'group-hover:shadow-[0_0_25px_rgba(168,85,247,0.18)]',
    iconBg: 'bg-purple-500/10 border-purple-500/30 text-purple-400',
    badge: 'badge-purple',
    gradient: 'from-purple-500/10 to-transparent',
  },
  blue: {
    borderHover: 'hover:border-blue-500/50',
    glow: 'group-hover:shadow-[0_0_25px_rgba(59,130,246,0.18)]',
    iconBg: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
    badge: 'badge-blue',
    gradient: 'from-blue-500/10 to-transparent',
  },
  amber: {
    borderHover: 'hover:border-amber-500/50',
    glow: 'group-hover:shadow-[0_0_25px_rgba(245,158,11,0.18)]',
    iconBg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
    badge: 'badge-amber',
    gradient: 'from-amber-500/10 to-transparent',
  },
  rose: {
    borderHover: 'hover:border-rose-500/50',
    glow: 'group-hover:shadow-[0_0_25px_rgba(239,68,68,0.18)]',
    iconBg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
    badge: 'badge-rose',
    gradient: 'from-rose-500/10 to-transparent',
  },
  slate: {
    borderHover: 'hover:border-slate-400/50',
    glow: 'group-hover:shadow-[0_0_25px_rgba(148,163,184,0.15)]',
    iconBg: 'bg-slate-500/10 border-slate-500/30 text-slate-300',
    badge: 'badge-cyan',
    gradient: 'from-slate-500/10 to-transparent',
  },
};

export function ModuleCard({ title, description, icon: Icon, badge, accent = 'cyan', route }) {
  const navigate = useNavigate();
  const accentStyle = ACCENT_STYLES[accent] || ACCENT_STYLES.cyan;

  const handleClick = () => {
    if (route) {
      navigate(route);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleClick();
    }
  };

  return (
    <motion.div
      whileHover={{ scale: 1.02, y: -4 }}
      whileTap={{ scale: 0.98 }}
      transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      tabIndex={0}
      role="button"
      aria-label={`${title} module: ${description}`}
      className={`glass-panel p-6 flex flex-col justify-between cursor-pointer group select-none relative overflow-hidden h-full min-h-[210px] ${accentStyle.borderHover} ${accentStyle.glow}`}
    >
      {/* Background Subtle Ambient Gradient */}
      <div className={`absolute top-0 right-0 w-36 h-36 bg-gradient-to-bl ${accentStyle.gradient} rounded-full blur-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none`} />

      {/* Top Header Row: Icon + Badge */}
      <div className="flex justify-between items-start z-10">
        <div className={`w-12 h-12 rounded-2xl border flex items-center justify-center transition-transform duration-300 group-hover:scale-105 ${accentStyle.iconBg}`}>
          <Icon className="w-6 h-6 stroke-[2]" />
        </div>
        {badge !== undefined && badge !== null && (
          <span className={`badge-tag ${accentStyle.badge} text-[11px] font-semibold py-1 px-2.5 shadow-sm`}>
            {badge}
          </span>
        )}
      </div>

      {/* Body Content: Title & Description */}
      <div className="space-y-1.5 my-3 z-10 flex-1 flex flex-col justify-center">
        <h3 className="text-lg font-bold font-outfit text-[#E5E7EB] tracking-wide group-hover:text-cyan-300 transition-colors">
          {title}
        </h3>
        <p className="text-xs text-[#94A3B8] font-normal leading-relaxed line-clamp-2">
          {description}
        </p>
      </div>

      {/* Footer Navigation Arrow Indicator */}
      <div className="flex items-center justify-end z-10 pt-2 border-t border-slate-800/60">
        <div className="flex items-center gap-1 text-xs font-semibold text-slate-400 group-hover:text-cyan-400 transition-colors">
          <ArrowRight className="w-4 h-4 transition-transform duration-300 group-hover:translate-x-1.5" />
        </div>
      </div>
    </motion.div>
  );
}
