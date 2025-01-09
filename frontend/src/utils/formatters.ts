export const formatScanStatus = (status: string): string => {
  return status
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
};

export const getScanStatusVariant = (status: string) => {
  switch (status) {
    case "in_progress":
      return "primary";
    case "failed":
      return "danger";
    case "completed":
      return "success";
    default:
      return "success";
  }
};
