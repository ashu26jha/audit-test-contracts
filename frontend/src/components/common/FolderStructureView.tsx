"use client";

import { type FC, useState, useEffect } from "react";

import { Checkbox, cn, Spinner } from "@nextui-org/react";
import { ChevronDown, ChevronRight, Text } from "lucide-react";

import { useAuth } from "@/contexts/AuthContext";
import { formatNumberWithCommas } from "@/utils/formatters";

export interface FolderStructureViewProps {
  items: FolderStructure[];
  level?: number;
  onSelect?: (path: string) => void;
  selectedPaths: string[];
  isDisabled?: boolean;
  isLoading: boolean;
  variant: "contract" | "readme";
}

export const FolderStructureView: FC<FolderStructureViewProps> = ({
  items,
  level = 0,
  onSelect,
  selectedPaths,
  isDisabled = false,
  isLoading,
  variant,
}) => {
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set());
  const { user } = useAuth();

  useEffect(() => {
    const folderPaths = new Set<string>();

    const collectFolderPaths = (items: FolderStructure[]) => {
      items.forEach((item) => {
        if (item.type === "folder") {
          folderPaths.add(item.path);
          if (item.children) {
            collectFolderPaths(item.children);
          }
        }
      });
    };

    collectFolderPaths(items);
    setExpandedFolders(folderPaths);
  }, [items]);

  const toggleFolder = (path: string) => {
    const newExpanded = new Set(expandedFolders);
    if (newExpanded.has(path)) {
      newExpanded.delete(path);
    } else {
      newExpanded.add(path);
    }
    setExpandedFolders(newExpanded);
  };

  if (isLoading) {
    return (
      <div className="w-full h-80 flex items-center justify-center">
        <Spinner color="secondary" size="lg" />
      </div>
    );
  }

  return (
    <div className={`${level === 0 && "h-[18rem] overflow-auto"}`}>
      {items.map((item) => (
        <div key={item.path}>
          <div
            className="flex items-center gap-2 py-1 rounded px-2 cursor-pointer"
            style={{ marginLeft: `${level * 20}px` }}
          >
            {item.type === "folder" ? (
              <button className="flex items-center gap-2 w-full" onClick={() => toggleFolder(item.path)}>
                <span className="select-none">
                  {expandedFolders.has(item.path) ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
                </span>
                <span>{item.name}</span>
              </button>
            ) : (
              <div className="w-[97%]">
                <Checkbox
                  color="secondary"
                  isSelected={selectedPaths.includes(item.path)}
                  onValueChange={() => onSelect?.(item.path)}
                  isDisabled={
                    (variant == "readme" && user?.subscription.type !== "enterprise") ||
                    (isDisabled && !selectedPaths.includes(item.path))
                  }
                  classNames={{
                    base: cn(
                      "ml-4 inline-flex w-full max-w-full",
                      "hover:bg-content2 items-center justify-start",
                      "cursor-pointer rounded-lg",
                    ),
                    label: "w-full flex justify-between",
                  }}
                >
                  <span>{item.name}</span>
                  <span className="ml-auto flex gap-2 items-center">
                    <Text size={16} />
                    <div className="w-12 text-end">
                      {item.fileInfo && variant === "contract"
                        ? formatNumberWithCommas(item.fileInfo?.lineCount || 0)
                        : formatNumberWithCommas(item.fileInfo?.character_count || 0)}
                    </div>
                  </span>
                </Checkbox>
              </div>
            )}
          </div>
          {item.type === "folder" && expandedFolders.has(item.path) && item.children && (
            <FolderStructureView
              items={item.children}
              level={level + 1}
              onSelect={onSelect}
              selectedPaths={selectedPaths}
              isDisabled={isDisabled}
              isLoading={false}
              variant={variant}
            />
          )}
        </div>
      ))}
    </div>
  );
};
