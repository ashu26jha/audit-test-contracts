export const formatScanStatus = (status: string, isPaid: boolean = false): string => {
  if (!isPaid && status === "completed") {
    return "Unpaid";
  }

  return status
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
};

export const getScanStatusVariant = (status: string, isPaid: boolean = false) => {
  switch (status) {
    case "in_progress":
      return "primary";
    case "failed":
      return "danger";
    case "completed":
      return isPaid ? "success" : "warning";
    default:
      return "success";
  }
};
