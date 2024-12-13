export const formatDate = (dateString: Date) => {
  return new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short", year: "numeric" }).format(
    new Date(dateString),
  );
};
