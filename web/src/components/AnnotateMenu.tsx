import { Bookmark, BookmarkMinus, Link2, MessageSquareText, PencilLine } from "lucide-react";
import { useEffect, type MouseEvent } from "react";
import { hex } from "../lib/format";
import { promptAnnotation, setState, toggleBookmark, useStore, useT } from "../state/store";
import { Kbd } from "./ui";

/** Open the annotate menu for an instruction (right-click in disassembly / graph / function list). */
export function openAnnotateMenu(e: MouseEvent, address: number, fn: number | null): void {
  e.preventDefault();
  setState({ menu: { x: e.clientX, y: e.clientY, address, fn }, xref: null });
}

/** Floating context menu: rename function, comment, bookmark, xrefs to here. */
export function AnnotateMenu() {
  const t = useT();
  const { menu, bookmarked } = useStore((s) => ({
    menu: s.menu,
    bookmarked: s.menu ? s.annotations.bookmarks[s.menu.address] !== undefined : false,
  }));
  useEffect(() => {
    if (!menu) return;
    const close = () => setState({ menu: null });
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", onKey);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("blur", close);
    };
  }, [menu]);
  if (!menu) return null;

  const items = [
    ...(menu.fn !== null
      ? [{ icon: PencilLine, label: t("annotate.rename"), key: "N", run: () => promptAnnotation("name", menu.address, menu.fn) }]
      : []),
    { icon: MessageSquareText, label: t("annotate.comment"), key: ";", run: () => promptAnnotation("comment", menu.address, menu.fn) },
    {
      icon: bookmarked ? BookmarkMinus : Bookmark,
      label: bookmarked ? t("annotate.unbookmark") : t("annotate.bookmark"),
      key: "B",
      run: () => {
        setState({ menu: null });
        void toggleBookmark(menu.address);
      },
    },
    {
      icon: Link2,
      label: t("xref.to_here"),
      key: "X",
      run: () => setState({ menu: null, xref: { x: menu.x, y: menu.y, rva: menu.address, label: hex(menu.address) } }),
    },
  ];
  const left = Math.min(menu.x, window.innerWidth - 240);
  const top = Math.min(menu.y, window.innerHeight - 180);
  return (
    <div
      role="menu"
      aria-label={hex(menu.address)}
      onMouseDown={(e) => e.stopPropagation()}
      style={{ left, top }}
      className="fixed z-[55] w-[230px] rounded-lg border border-line bg-panel p-1 shadow-2xl"
    >
      <div className="px-2 py-1 font-mono text-[11px] text-faint">{hex(menu.address)}</div>
      {items.map(({ icon: Icon, label, key, run }) => (
        <button
          key={label}
          type="button"
          role="menuitem"
          onClick={run}
          className="flex h-7 w-full cursor-pointer items-center gap-2 rounded px-2 text-left text-[12.5px] hover:bg-raised"
        >
          <Icon size={14} className="text-muted" aria-hidden />
          {label}
          <span className="ml-auto">
            <Kbd>{key}</Kbd>
          </span>
        </button>
      ))}
    </div>
  );
}

