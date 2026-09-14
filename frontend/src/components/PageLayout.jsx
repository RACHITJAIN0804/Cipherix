import React from 'react';
import { TopNavBar } from './TopNavBar';
import { PageTransition } from './PageTransition';


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
