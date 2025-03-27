import { useMemo } from "react";

import {
  Card,
  CardBody,
  CardHeader,
  Checkbox,
  Divider,
  Chip,
  Accordion,
  AccordionItem,
  Tooltip,
} from "@nextui-org/react";
import { Info, InfoIcon } from "lucide-react";

import { useScanStepperStore } from "@/store/scanStepperStore";

import { MarkdownWithCode } from "../layout";

const InvariantsSelection = () => {
  const { invariants, selectedInvariants, selectedContracts, setSelectedInvariants } = useScanStepperStore();

  const handleInvariantToggle = (invariant: Invariant) => {
    setSelectedInvariants(
      selectedInvariants.includes(invariant)
        ? selectedInvariants.filter((inv: Invariant) => inv !== invariant)
        : [...selectedInvariants, invariant],
    );
  };

  const availableInvariants = useMemo(() => {
    const filtered = invariants?.filter((inv) => selectedContracts.includes(inv.path)) ?? [];

    return filtered.reduce(
      (acc, inv) => {
        const existingGroup = acc.find((group) => group.path === inv.path);

        if (existingGroup) {
          existingGroup.invariants.push(inv);
        } else {
          acc.push({
            path: inv.path,
            invariants: [inv],
          });
        }

        return acc;
      },
      [] as { path: string; invariants: Invariant[] }[],
    );
  }, [invariants, selectedContracts]);

  return (
    <Card className="w-full md:w-3/4 shadow-md overflow-x-scroll border border-default-100">
      <CardHeader className="flex flex-col items-start gap-2 px-6 pt-6 pb-0">
        <div className="flex items-center gap-2">
          <h2 className="font-medium">Select Invariants (Optional)</h2>
          <Tooltip
            placement="top-end"
            content={
              <div className="text-center text-sm p-2">
                Selecting invariants is optional. <br />
                If you don&apos;t select any, we&apos;ll automatically generate invariants for the selected contracts.
              </div>
            }
          >
            <InfoIcon className="size-4" />
          </Tooltip>
        </div>
        <p className="text-default-500 text-sm">Choose the invariants you want to include in your scan</p>
        {invariants && invariants.length > 0 && (
          <div className="flex items-center gap-2 mt-2">
            <Chip color="primary" variant="flat">
              {invariants?.filter((inv) => selectedContracts.includes(inv.path))?.length} invariants available
            </Chip>
            <Chip color="secondary" variant="flat">
              {selectedInvariants.length} selected
            </Chip>
          </div>
        )}
      </CardHeader>
      <Divider className="my-4" />
      <CardBody>
        {!availableInvariants || availableInvariants.length === 0 ? (
          <div className="flex flex-col gap-4 justify-center items-center h-60 sm:p-6 bg-default-50 rounded-xl">
            <div className="text-center w-full">
              <Info size={24} className="mb-2 mx-auto" />
              <h3 className="text-xl font-semibold mb-2">No Invariants Available</h3>
              <p className="text-default-500 mb-4">
                Don&apos;t worry! We&apos;ll automatically generate invariants for the selected contracts.
              </p>
              <Chip color="secondary" variant="flat" className="mx-auto text-[10px] sm:text-sm">
                Invariants will be generated during scanning
              </Chip>
            </div>
          </div>
        ) : (
          <Accordion selectionMode="multiple" variant="light">
            {availableInvariants.map((invariant) => (
              <AccordionItem className="bg-transparent" key={invariant.path} title={invariant.path}>
                {invariant.invariants.map((inv) => (
                  <Card
                    key={inv.condition}
                    className={`w-full border my-4 ${
                      selectedInvariants.includes(inv) ? "border-secondary" : "border-default-100"
                    }`}
                    isPressable
                    onPress={() => handleInvariantToggle(inv)}
                  >
                    <CardBody className="p-4">
                      <div className="flex items-start gap-3">
                        <Checkbox
                          isSelected={selectedInvariants.includes(inv)}
                          onChange={() => handleInvariantToggle(inv)}
                          size="lg"
                          color="secondary"
                        />
                        <div className="flex-1">
                          <h3 className="text-md font-semibold mb-2">{inv.function}</h3>
                          <div className="bg-default-50 rounded-lg p-3">
                            <MarkdownWithCode content={inv.condition} />
                          </div>
                          {inv.description && <p className="mt-2 text-default-500 text-sm">{inv.description}</p>}
                        </div>
                      </div>
                    </CardBody>
                  </Card>
                ))}
              </AccordionItem>
            ))}
          </Accordion>
        )}
      </CardBody>
    </Card>
  );
};

export default InvariantsSelection;
