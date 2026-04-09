import { useEffect, useRef } from "react";
import { X } from "lucide-react";

function getFocusable(container) {
  if (!container) {
    return [];
  }

  return [...container.querySelectorAll("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])")]
    .filter((element) => !element.hasAttribute("disabled"));
}

export default function ModalShell({ titleId, onDismiss, tone = "default", children }) {
  const cardRef = useRef(null);

  useEffect(() => {
    const node = cardRef.current;
    const focusable = getFocusable(node);
    const first = focusable[0];
    first?.focus();

    function handleKeyDown(event) {
      if (event.key === "Escape") {
        event.preventDefault();
        onDismiss();
        return;
      }

      if (event.key !== "Tab") {
        return;
      }

      const items = getFocusable(node);
      if (items.length === 0) {
        event.preventDefault();
        return;
      }

      const activeIndex = items.indexOf(document.activeElement);
      const nextIndex = event.shiftKey
        ? (activeIndex <= 0 ? items.length - 1 : activeIndex - 1)
        : (activeIndex === items.length - 1 ? 0 : activeIndex + 1);

      event.preventDefault();
      items[nextIndex]?.focus();
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onDismiss]);

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onDismiss}>
      <div
        ref={cardRef}
        className={`modal-card modal-${tone}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button className="modal-close" type="button" aria-label="Close dialog" onClick={onDismiss}>
          <X size={18} />
        </button>
        {children}
      </div>
    </div>
  );
}
