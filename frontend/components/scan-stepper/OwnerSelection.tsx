import React from "react";
import { Select, SelectItem } from "@nextui-org/react";
import { useScanStepperStore } from "../../store/scanStepperStore";

export const OwnerSelection: React.FC = () => {
  const { owners, setSelectedOwner } = useScanStepperStore();

  return (
    <div className="mb-6 text-color-red">
      <Select
        variant="bordered"
        label={
          <>
            Git Organization
            <span style={{ color: "red", marginLeft: "4px" }}>*</span>
          </>
        }
        placeholder="Select one"
        labelPlacement="outside"
        className="w-full"
        onSelectionChange={(keys) => {
          const selected = Array.from(keys)[0] as string;
          setSelectedOwner(owners.find((owner) => owner.login === selected) || null);
        }}
      >
        {owners.map((org) => (
          <SelectItem key={org.login} value={org.login} className="hover:bg-[#4F46E5] transition-colors duration-300">
            {org.login}
          </SelectItem>
        ))}
      </Select>
    </div>
  );
};
