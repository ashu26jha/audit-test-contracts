import { format, formatDistanceToNow, formatRelative, parseISO } from "date-fns";

/**
 * Format a date in a standard format (e.g., "15 Dec 2023")
 * @param date - Date object or ISO string
 * @param formatStr - Optional custom format string (date-fns format)
 * @returns Formatted date string
 */
export const formatDate = (date: Date | string, formatStr: string = "dd MMM yyyy"): string => {
  try {
    const dateObj = typeof date === "string" ? parseISO(date) : date;
    return format(dateObj, formatStr);
  } catch (error) {
    console.error("Error formatting date:", error);
    return String(date);
  }
};

/**
 * Format a datetime with time in local timezone
 * @param isoString - UTC ISO datetime string
 * @param formatStr - Optional custom format string (date-fns format)
 * @returns Formatted datetime string
 */
export const formatUTCToLocal = (isoString: string, formatStr: string = "dd MMM yyyy, HH:mm"): string => {
  if (!isoString) return "";

  try {
    const date = parseISO(isoString);
    return format(date, formatStr);
  } catch (error) {
    console.error("Error formatting datetime:", error);
    return isoString;
  }
};

/**
 * Format a date relative to now (e.g., "2 hours ago", "in 3 days")
 * @param isoString - UTC ISO datetime string
 * @param addSuffix - Whether to add ago/in prefix/suffix
 * @returns Relative time string
 */
export const formatRelativeTime = (isoString: string, addSuffix: boolean = true): string => {
  if (!isoString) return "";

  try {
    const date = parseISO(isoString);
    return formatDistanceToNow(date, { addSuffix });
  } catch (error) {
    console.error("Error formatting relative time:", error);
    return isoString;
  }
};

/**
 * Format a date relative to another date (e.g., "yesterday at 2:00 PM")
 * @param isoString - UTC ISO datetime string
 * @param baseDate - Date to compare to (defaults to now)
 * @returns Relative date string
 */
export const formatRelativeDate = (isoString: string, baseDate: Date = new Date()): string => {
  if (!isoString) return "";

  try {
    const date = parseISO(isoString);
    return formatRelative(date, baseDate);
  } catch (error) {
    console.error("Error formatting relative date:", error);
    return isoString;
  }
};
