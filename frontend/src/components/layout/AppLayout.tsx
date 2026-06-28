import { Outlet } from "react-router-dom";

import Sidebar from "./Sidebar";
import Header from "./Header";

/**
 * App shell — wraps every page in a persistent Sidebar + Header layout.
 * All routes declared under <Route element={<AppLayout />}> render here.
 */
export default function AppLayout() {
  return (
    <div className="flex h-screen w-full bg-background text-foreground">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}