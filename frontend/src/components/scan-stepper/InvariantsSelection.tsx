import { useMemo } from "react";

import { Card, CardBody, CardHeader, Checkbox, Divider, ScrollShadow, Chip } from "@nextui-org/react";
import { Info } from "lucide-react";

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
    return invariants?.filter((inv) => selectedContracts.includes(inv.path));
  }, [invariants, selectedContracts]);

  return (
    <Card className="w-full shadow-md">
      <CardHeader className="flex flex-col items-start gap-2 px-6 pt-6 pb-0">
        <h2 className="text-xl font-bold">Select Invariants</h2>
        <p className="text-default-500">Choose the invariants you want to include in your scan</p>
        {invariants && invariants.length > 0 && (
          <div className="flex items-center gap-2 mt-2">
            <Chip color="primary" variant="flat">
              {availableInvariants?.length} invariants available
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
          <div className="flex flex-col gap-4 justify-center items-center h-60 p-6 bg-default-50 rounded-xl">
            <div className="text-center">
              <Info size={24} className="mb-2 mx-auto" />
              <h3 className="text-xl font-semibold mb-2">No Invariants Available</h3>
              <p className="text-default-500 mb-4">
                Don&apos;t worry! We&apos;ll automatically generate invariants for the selected contracts.
              </p>
              <Chip color="secondary" variant="flat" className="mx-auto">
                Invariants will be generated during scanning
              </Chip>
            </div>
          </div>
        ) : (
          <ScrollShadow>
            <div className="flex flex-col gap-4">
              {availableInvariants.map((invariant) => (
                <Card
                  key={invariant.condition}
                  className={`w-full border-2 ${
                    selectedInvariants.includes(invariant) ? "border-secondary" : "border-default-100"
                  }`}
                  isPressable
                  onPress={() => handleInvariantToggle(invariant)}
                >
                  <CardBody className="p-4">
                    <div className="flex items-start gap-3">
                      <Checkbox
                        isSelected={selectedInvariants.includes(invariant)}
                        onChange={() => handleInvariantToggle(invariant)}
                        size="lg"
                        color="secondary"
                      />
                      <div className="flex-1">
                        <h3 className="text-md font-semibold mb-2">
                          {invariant.function} <span className="text-sm font-light">({invariant.path})</span>
                        </h3>
                        <div className="bg-default-50 rounded-lg p-3">
                          <MarkdownWithCode content={invariant.condition} />
                        </div>
                        {invariant.description && (
                          <p className="mt-2 text-default-500 text-sm">{invariant.description}</p>
                        )}
                      </div>
                    </div>
                  </CardBody>
                </Card>
              ))}
            </div>
          </ScrollShadow>
        )}
      </CardBody>
    </Card>
  );
};

export default InvariantsSelection;
