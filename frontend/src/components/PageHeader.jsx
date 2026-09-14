import React from 'react';


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
