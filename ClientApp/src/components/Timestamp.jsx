import { formatAbsoluteTime, formatRelativeTime } from "../ui/presentation";

export default function Timestamp({ value, className = "" }) {
  return (
    <time className={className} dateTime={value ?? undefined} title={formatAbsoluteTime(value)}>
      {formatRelativeTime(value)}
    </time>
  );
}
