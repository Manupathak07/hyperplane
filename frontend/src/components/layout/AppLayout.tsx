import { Outlet } from "react-router-dom";

import Sidebar from "./Sidebar";
import Header from "./Header";
import ActivityPanel from "./ActivityPanel";

/**
 * App shell — wraps every page in a persistent Sidebar + Header + ActivityPanel.
 * All routes declared under <Route element={<AppLayout />}> render via <Outlet />.
 * Layout: [Sidebar | Content | ActivityPanel] — desktop only.
 */
export default function AppLayout() {
  return (
    <div className="flex h-screen w-full bg-background text-foreground">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />
        <div className="flex flex-1 overflow-hidden">
          <main className="flex-1 overflow-auto p-6">
            <Outlet />
          </main>
          <ActivityPanel />
        </div>
      </div>
    </div>
  );
}