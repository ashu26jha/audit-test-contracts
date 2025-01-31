export const sanitizeString = (input: string): string => {
  if (!input) return "";

  // Remove HTML tags using a bounded quantifier
  let sanitized = input.replace(/<[^>]{0,1000}>/g, "");
  // Remove script tags using multiple passes with simpler patterns
  sanitized = sanitized.replace(/<script[^>]*>/gi, "");
  sanitized = sanitized.replace(/<\/script>/gi, "");

  // Allow alphanumeric, spaces, and basic punctuation
  sanitized = sanitized.replace(/[^a-zA-Z0-9\s.,!?-]/g, "");
  return sanitized.trim();
};

export const organizeFilesByFolder = (files: SolidityFile[] | ReadmeFile[]): FolderStructure[] => {
  const root: FolderStructure[] = [];

  files.forEach((file) => {
    const pathParts = file.path.split("/");
    let currentLevel = root;

    pathParts.forEach((part, index) => {
      const isLastPart = index === pathParts.length - 1;
      const currentPath = pathParts.slice(0, index + 1).join("/");

      const existingItem = currentLevel.find((item) => item.name === part);

      if (existingItem) {
        if (!isLastPart) {
          currentLevel = existingItem.children!;
        }
      } else {
        const newItem: FolderStructure = isLastPart
          ? {
              name: part,
              type: "file",
              path: currentPath,
              fileInfo: file,
            }
          : {
              name: part,
              type: "folder",
              path: currentPath,
              children: [],
            };

        currentLevel.push(newItem);
        if (!isLastPart) {
          currentLevel = newItem.children!;
        }
      }
    });
  });

  return root;
};
