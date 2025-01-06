"use client";

import { useState, type FC } from "react";

import {
  Button,
  Chip,
  DateRangePicker,
  Popover,
  PopoverContent,
  PopoverTrigger,
  type DateValue,
  type RangeValue,
} from "@nextui-org/react";
import { Calendar, Check, ListFilter } from "lucide-react";

import { formatDate } from "@/utils/datetime";

const filters = [
  { filter: "Newest to Oldest Scans", key: "newest" },
  { filter: "Oldest to Newest Scans", key: "oldest" },
  { filter: "Highest to Lowest Vulnerabilities", key: "most_vulnerabilities" },
  { filter: "Lowest to Highest Vulnerabilities", key: "least_vulnerabilities" },
] as const;

interface ScanFiltersProps {
  selectedFilter: FilterKey | null;
  onFilterSelect: (filter: FilterKey) => void;
  onClearFilter: () => void;
  selectedDateRange: RangeValue<DateValue> | null;
  setSelectedDateRange: (range: RangeValue<DateValue> | null) => void;
}

const ScanFilters: FC<ScanFiltersProps> = ({
  selectedDateRange,
  setSelectedDateRange,
  selectedFilter,
  onFilterSelect,
  onClearFilter,
}) => {
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const [isDateFilterOpen, setisDateFilterOpen] = useState(false);

  const handleClearFilter = () => {
    onClearFilter();
    setIsFilterOpen(false);
  };

  const handleClearDateRangeFilter = () => {
    setSelectedDateRange(null);
  };

  const handleFilterSelect = (filter: FilterKey) => {
    onFilterSelect(filter);
  };

  const handleDateFilter = (v: RangeValue<DateValue> | null) => {
    setSelectedDateRange(v);
  };

  return (
    <div className="flex items-center gap-x-4">
      {/* Date Range Button */}
      <Button
        className="bg-content-1 border border-default-100"
        radius="sm"
        size="md"
        onPress={() => setisDateFilterOpen(true)}
        startContent={<Calendar size={16} />}
      >
        <DateRangePicker
          value={selectedDateRange}
          onChange={handleDateFilter}
          isOpen={isDateFilterOpen}
          color="secondary"
          onOpenChange={setisDateFilterOpen}
          classNames={{
            base: "w-0",
            inputWrapper: "bg-transparent hover:bg-transparent",
            input: "hidden hover:hidden",
            separator: "hidden",
            selectorButton: "hidden",
            selectorIcon: "text-white hidden",
            calendar: "bg-content-1",
          }}
          CalendarBottomContent={
            <div className="p-3">
              <Button
                fullWidth
                variant="bordered"
                radius="sm"
                onPress={handleClearDateRangeFilter}
                isDisabled={!selectedDateRange}
              >
                Clear Filter
              </Button>
            </div>
          }
        />
        {selectedDateRange
          ? `${formatDate(new Date(selectedDateRange.start.toString()), "dd MMM yy")} - ${formatDate(
              new Date(selectedDateRange.end.toString()),
              "dd MMM yy",
            )}`
          : "Sort by Date"}
      </Button>

      {/* Filters Button */}
      <Popover
        classNames={{
          base: "p-0",
        }}
        placement="bottom"
        isOpen={isFilterOpen}
        onOpenChange={setIsFilterOpen}
      >
        <PopoverTrigger>
          <Button
            className="bg-content-1 border border-default-100"
            radius="sm"
            size="md"
            startContent={<ListFilter size={20} />}
          >
            Filters
            {selectedFilter && (
              <Chip radius="sm" size="sm">
                <p className="text-sm">1</p>
              </Chip>
            )}
          </Button>
        </PopoverTrigger>

        <PopoverContent className="w-[280px] bg-content-2 p-0">
          <div className="w-full flex flex-col gap-y-1">
            <h2 className="text-xs mt-2 text-foreground-500 px-4 py-2">FILTERS</h2>

            {filters.map((filter) => (
              <button
                onClick={() => handleFilterSelect(filter.key)}
                key={filter.key}
                className="flex justify-between items-center h-10 mx-2 px-2 py-[10px] font-light text-foreground hover:bg-default-flat rounded-lg cursor-pointer"
              >
                {filter.filter}
                {selectedFilter === filter.key && <Check size={14} />}
              </button>
            ))}
          </div>
          <div className="flex my-3 px-4 justify-between gap-x-2 w-full">
            <Button fullWidth variant="bordered" radius="sm" onPress={handleClearFilter} isDisabled={!selectedFilter}>
              Clear Filter
            </Button>
          </div>
        </PopoverContent>
      </Popover>
    </div>
  );
};

export default ScanFilters;
