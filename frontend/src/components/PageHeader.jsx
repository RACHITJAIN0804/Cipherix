import React from 'react';

/**
 * PageHeader — Standardized page section header used across all sub-pages.
 *
 * Props:
 *  - icon       : A Lucide icon component (e.g. Shield)
 *  - iconColor  : CSS color string or Tailwind class for the icon (default: '#22D3EE')
 *  - iconBg     : CSS background for icon container (optional)
 *  - iconBorder : CSS border for icon container (optional)
 *  - title      : Main section heading text
 *  - description: Subtitle / description below the title
 *  - children   : Right-side slot — action buttons, selectors, badges, etc.
 */
export function PageHeader({
  icon: Icon,
  iconColor = 'text-cyan-400',
  title,
  description,
  children,
}) {
  return (
    <div className="page-header-bar">
      <div className="page-header-left">
        {Icon && (
          <div className={`page-header-icon ${iconColor}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
        <div className="page-header-text">
          <h2 className="page-header-title">{title}</h2>
          {description && (
            <p className="page-header-desc">{description}</p>
          )}
        </div>
      </div>

      {children && (
        <div className="page-header-actions">
          {children}
        </div>
      )}
    </div>
  );
}
