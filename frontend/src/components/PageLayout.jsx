import React from 'react';
import { TopNavBar } from './TopNavBar';
import { PageTransition } from './PageTransition';

/**
 * PageLayout — Shared page wrapper used by every sub-page in Cipherix.
 *
 * Props:
 *  - title      : Page title shown in the TopNavBar
 *  - user       : Current authenticated user object
 *  - onLogout   : Logout handler
 *  - flexContent: When true, makes <main> a flex column so children can fill
 *                 remaining vertical space (used by chat-style pages like AIAssistantView)
 *  - children   : Page body content
 */
export function PageLayout({ title, user, onLogout, flexContent = false, children }) {
  return (
    <PageTransition>
      <div className="page-root">
        <TopNavBar title={title} user={user} onLogout={onLogout} />

        <main className={`page-main${flexContent ? ' page-main--flex' : ''}`}>
          {children}
        </main>
      </div>
    </PageTransition>
  );
}
