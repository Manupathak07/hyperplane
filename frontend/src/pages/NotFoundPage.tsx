import { Link, useLocation } from "react-router-dom";

interface Props {
  title?: string;
  week?: string;
  message?: string;
}

export default function NotFoundPage({
  title,
  week,
  message,
}: Props) {
  const { pathname } = useLocation();
  return (
    <div className="mx-auto max-w-md text-center">
      <div className="rounded-md border border-dashed border-border bg-card/40 p-8">
        <div className="text-xs uppercase tracking-wider text-muted-foreground">
          {week ? `Available in ${week}` : "Not found"}
        </div>
        <h2 className="mt-2 text-lg font-semibold">
          {title ?? `No page at ${pathname}`}
        </h2>
        <p className="mt-2 text-sm text-muted-foreground">
          {message ??
            "This route is reserved for a future HyperPlane feature. The sidebar is already wired to it."}
        </p>
        <Link
          to="/health"
          className="mt-4 inline-flex rounded-md border border-border bg-card px-3 py-1.5 text-xs font-medium hover:bg-accent"
        >
          Back to Health
        </Link>
      </div>
    </div>
  );
}